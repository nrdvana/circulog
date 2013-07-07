#include "config.h"
#include "circulog_internal.h"

static inline bool SET_ERR(ccl_log_t *log, int code, const char* msg) {
	log->last_err= code;
	log->last_errno= errno;
	log->last_errmsg= msg;
	return false;
}

ccl_log_t *ccl_new() {
	ccl_log_t *log= (ccl_log_t*) malloc(sizeof(*log));
	if (!log) return NULL;
	ccl_init(log, sizeof(*log));
	return log;
}

bool ccl_delete(ccl_log_t *log) {
	bool succ= ccl_destroy(log);
	free(log);
	return succ;
}

bool ccl_init(ccl_log_t *log, int struct_size) {
	if (struct_size < sizeof(*log))
		return false;
	memset(log, 0, struct_size);
	log->timestamp_precision= CCL_DEFAULT_TIMESTAMP_PRECISION;
	log->max_message_size=    CCL_DEFAULT_MAX_MESSAGE_SIZE;
	log->index_size=          1;
	log->spool_size=          CCL_DEFAULT_SPOOL_SIZE;
	log->fd= -1;
	return true;
}

bool ccl_destroy(ccl_log_t *log) {
	bool err= false;
	if (log->memmap) {
		err= err || munmap(log->memmap, (size_t) log->memmap_size);
		log->memmap= NULL;
		log->memmap_size= 0;
	}
	if (log->fd >= 0) {
		err= err || close(log->fd);
		log->fd= -1;
	}
	return !err;
}

bool ccl_init_timestamp_params(ccl_log_t *log, int64_t epoch, int precision_bits) {
	if (log->fd >= 0)
		return SET_ERR(log, CCL_ELOGSTATE, "Can't call ccl_init_* after log is open");
	
	log->timestamp_epoch= epoch;
	log->timestamp_precision= precision_bits;
	return true;
}

bool ccl_init_geometry_params(ccl_log_t *log, int64_t spool_size, bool with_index, int max_message_size) {
	if (log->fd >= 0)
		return SET_ERR(log, CCL_ELOGSTATE, "Can't call ccl_init_* after log is open");
	
	log->spool_size= spool_size;
	log->index_size= with_index? 1 : 0;
	log->max_message_size= max_message_size;
	return true;
}

uint64_t ccl_timestamp_from_timespec(ccl_log_t *log, struct timespec *t) {
	#ifdef _POSIX_TIMERS
	struct timespec t2;
	if (!t) {
		t= &t2;
		if (clock_gettime(CLOCK_REALTIME, &t2) < 0)
			return 0LL;
	}
	#else
	if (!t) return ((uint64_t) time(NULL) - log->timestamp_epoch) << log->timestamp_precision;
	#endif
	return (((uint64_t) t->tv_sec - log->timestamp_epoch) << log->timestamp_precision) | (CCL_NSEC_TO_FRAC32(t->tv_nsec) >> (32-log->timestamp_precision));
}

void ccl_timestamp_to_timespec(ccl_log_t *log, uint64_t ts, struct timespec *t_out) {
	t_out->tv_sec=  (time_t) ((ts >> log->timestamp_precision) + log->timestamp_epoch);
	t_out->tv_nsec= CCL_FRAC32_TO_NSEC((ts >> (log->timestamp_precision-32)) & 0xFFFFFFFFLL);
	if (t_out->tv_nsec == 1000000000) {
		t_out->tv_sec= 1000000000;
		t_out->tv_sec++;
	}
}

static bool log_read(ccl_log_t *log, void* record, int record_size) {
	int count= 0;
	int got;
	while (count < record_size) {
		got= read(log->fd, ((char*)record)+count, record_size-count);
		if (got > 0)
			count+= got;
		else if (got < 0 && errno != EINTR)
			return SET_ERR(log, CCL_EREAD, "read failed: $syserr");
		else if (got == 0)
			return SET_ERR(log, CCL_EEOF, "unexpected EOF");
	}
	return true;
}

static bool log_write(ccl_log_t *log, void* record, int record_size) {
	int count= 0;
	int wrote;
	while (count < record_size) {
		wrote= write(log->fd, ((char*)record)+count, record_size-count);
		if (wrote > 0)
			count+= wrote;
		else if (wrote < 0 && errno != EINTR)
			return SET_ERR(log, CCL_EWRITE, "write failed: $syserr");
	}
	return true;
}

static bool log_lock(ccl_log_t *log) {
	struct flock lock;
	int ret;
	
	memset(&lock, 0, sizeof(lock));
	lock.l_type= F_WRLCK;
	lock.l_whence= SEEK_SET;
	lock.l_start= 0;
	lock.l_len= sizeof(ccl_log_header_t);
	
	if (log->shared_write) {
		// TODO: this is cheesy, but works for now.  Think up a better interface for write timeouts.
		alarm(3);
		ret= fcntl(log->fd, F_SETLKW, &lock);
		alarm(0);
	} else {
		ret= fcntl(log->fd, F_SETLK, &lock);
	}
	if (ret < 0)
		return SET_ERR(log, CCL_ELOCK, "Failed to lock logfile for writing: $syserr");
	return true;
}

static bool log_unlock(ccl_log_t *log) {
	struct flock lock;
	int ret;
	
	memset(&lock, 0, sizeof(lock));
	lock.l_type= F_UNLCK;
	lock.l_whence= SEEK_SET;
	lock.l_start= 0;
	lock.l_len= sizeof(ccl_log_header_t);
	
	ret= fcntl(log->fd, F_SETLK, &lock);
	if (ret < 0)
		return SET_ERR(log, CCL_ELOCK, "Failed to lock logfile for writing: $syserr");
	return true;
}

static bool log_create_file(ccl_log_t *log) {
	ccl_log_header_t header;
	long pagesize;
	int64_t
		spool_size= log->spool_size,
		spool_start,
		index_size= log->index_size,
		index_start,
		mask;
	off_t file_size;
	
	// first, make spool_size both a multiple of the page size (if available)
	// and a multiple of 8 otherwise.
	pagesize= sysconf(_SC_PAGESIZE);
	if (pagesize < 8)
		pagesize= 8;
	mask= pagesize-1;
	spool_size= (spool_size + mask) & ~mask;
	
	// *if* the user wants an index...
	if (log->index_size > 0) {
		// determine the index size from spool_size
		// (one index entry for each CCL_INDEX_GRANULARITY of spool)
		index_size= ((spool_size + CCL_INDEX_GRANULARITY - 1) >> CCL_INDEX_GRANULARITY_BITS)
			* sizeof(ccl_log_index_entry_t);
		// and align the index start to the size of the entries
		mask= sizeof(ccl_log_index_entry_t) - 1;
		index_start= (sizeof(header) + mask) & ~mask;
	}
	// else index is disabled.
	else {
		index_size= 0;
		index_start= sizeof(header);
	}
	
	// finally align the start of the spool
	mask= pagesize-1;
	spool_start= (index_start + index_size + mask) & ~mask;
	
	memset(&header, 0, sizeof(header));
	header.magic=                 htole64(CCL_HEADER_MAGIC);
	header.version=               htole32(CCL_CURRENT_VERSION);
	header.oldest_compat_version= htole32(CCL_CURRENT_VERSION);
	header.header_size=           htole32(sizeof(header));
	header.timestamp_precision=   htole32(log->timestamp_precision);
	header.timestamp_epoch=       htole64(log->timestamp_epoch);
	header.index_start=           htole64(index_start);
	header.index_size=            htole64(index_size);
	header.spool_start=           htole64(spool_start);
	header.spool_size=            htole64(spool_size);
	header.max_message_size=      htole32(log->max_message_size);
	
	file_size= spool_start+spool_size;
	
	// overflow check
	if (file_size < spool_start+spool_size)
		return SET_ERR(log, CCL_ESIZELIMIT, "Spool size exceeds implementation limits");
	
	// now write the file
	
	if (ftruncate(log->fd, file_size) < 0
		|| !log_write(log, &header, sizeof(header))
		)
		return SET_ERR(log, CCL_EWRITE, "Failed to write new log: $syserr");
	
	return true;
}

static bool log_load_file(ccl_log_t *log) {
	ccl_log_header_t header;
	off_t file_size;
	int extra, index_entries;
	
	file_size= lseek(log->fd, 0, SEEK_END);
	if (file_size == (off_t)-1)
		return SET_ERR(log, CCL_ESEEK, "Can't seek to end of $logfile: $syserr");
	
	if (lseek(log->fd, 0, SEEK_SET) == (off_t)-1)
		return SET_ERR(log, CCL_ESEEK, "Can't seek to start of $logfile: $syserr");
	
	// read basic fields
	if (!log_read(log, &header, CCL_MIN_HEADER_SIZE))
		return false;
	
	// check magic number, and determine endianness
	if (le64toh(header.magic) != CCL_HEADER_MAGIC)
		return SET_ERR(log, CCL_ELOGINVAL, "Bad magic number in $logfile");
	
	//if (be64toh(header.magic) == CCL_HEADER_MAGIC) {
	//log->wrong_endian= true;
	
	// version check
	if (le32toh(header.oldest_compat_version) > CCL_CURRENT_VERSION)
		return SET_ERR(log, CCL_ELOGVERSION, "$logfile version too new");
	
	log->header_size= le32toh(header.header_size);
	
	// recorded header_size must be at least as big as the minimum
	if (log->header_size < CCL_MIN_HEADER_SIZE)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile specifies an invalid header size");
	
	// read the rest of the header, up to the size of our header struct
	if (log->header_size > CCL_MIN_HEADER_SIZE && sizeof(header) > CCL_MIN_HEADER_SIZE) {
		extra= (log->header_size < sizeof(header)? log->header_size : sizeof(header)) - CCL_MIN_HEADER_SIZE;
		if (!log_read(log, ((char*)&header)+CCL_MIN_HEADER_SIZE, extra))
			return false;
	}
	
	log->version=             le32toh(header.version);
	log->timestamp_precision= le32toh(header.timestamp_precision);
	log->timestamp_epoch=     le64toh(header.timestamp_epoch);
	log->index_start=         le64toh(header.index_start);
	log->index_size=          le64toh(header.index_size);
	log->spool_start=         le64toh(header.spool_start);
	log->spool_size=          le64toh(header.spool_size);
	log->max_message_size=    le32toh(header.max_message_size);
	
	// Now it is safe to use the rest of the header fields we know about
	
	if ((uint64_t)file_size < log->spool_start + log->spool_size)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile is truncated (file size less than end of message spool)");
	if (log->index_start < log->header_size)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile index overlaps with header");
	if (log->index_size) {
		index_entries= log->index_size / sizeof(ccl_log_index_entry_t);
		if (index_entries * sizeof(ccl_log_index_entry_t) != log->index_size)
			return SET_ERR(log, CCL_ELOGINVAL, "$logfile index size is not a multiple of log_index_entry_t");
		if (index_entries != (log->spool_size + CCL_INDEX_GRANULARITY-1) >> CCL_INDEX_GRANULARITY_BITS)
			return SET_ERR(log, CCL_ELOGINVAL, "$logfile index size does not match spool size");
	}
	if (log->spool_start < log->index_start + log->index_size)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile message spool overlaps with index");
	if (log->spool_size & 7)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile message spool size is not a multiple of 8");
	if (log->timestamp_precision < 0 || log->timestamp_precision > 64)
		return SET_ERR(log, CCL_ELOGINVAL, "$logfile timestamp precision outside valid range");
	
	// Lock it for writing, if write-exclusive mode.
	// In shared-write mode, we lock on each write operation.
	// In read-only mode we make no locks at all.
	if (log->writeable && !log->shared_write) {
		if (!log_lock(log))
			return false;
	}
	
	return true;
}

/** ccl_open - open (and optionally create) a log
 * 
 * Opens the specified path and verifies that it is a valid log file.
 *
 * Access modes are CCL_READ, CCL_WRITE, CCL_SHARE.
 *
 * If create is true, and the file does not exist (or is empty) it will be
 * created according to the fields of the log struct, which can be initialized
 * to the desired values with
 *   * ccl_init_timestamp_params
 *   * ccl_init_geometry_params
 *
 * Returns true if successful, or false with a code in log->last_err on
 * failure.
 */
bool ccl_open(ccl_log_t *log, const char *path, int access) {
	bool create;
	off_t file_size;
	
	if (!log) return false;
	
	if (log->fd >= 0)
		return SET_ERR(log, CCL_ELOGSTATE, "Log object was already opened");
	
	create= (access & CCL_CREATE);
	log->writeable= (access & CCL_WRITE);
	log->shared_write= log->writeable && (access & CCL_SHARE);

	// open the file
	log->fd= open(path, (create? O_CREAT:0) | (log->writeable? O_RDWR : O_RDONLY), 0666);
	if (log->fd < 0)
		return SET_ERR(log, CCL_EOPEN, "Unable to open $logfile: $syserr");
	
	// now find the length of the file
	file_size= lseek(log->fd, 0, SEEK_END);
	if (file_size == (off_t)-1)
		SET_ERR(log, CCL_ESEEK, "Can't seek to end of $logfile: $syserr");
	// If file size is zero, and create was specified, initialize the log
	// or, if file size > 0, just try loading it.
	else if (file_size > 0 || (create && log_create_file(log))) {
		if (log_load_file(log))
			return true;
	}
	// if we failed, put the log object back in a closed state
	close(log->fd);
	log->fd= -1;
	return false;
}

/*
bool ccl_resize(ccl_log_t *log, const char *path, int64_t newSize, bool create, bool force) {
	ccl_log_t newLog;
	ccl_log_header_t header;
	bool haveOld= false;
	char fname[255];
	
	// Step one, open the old log with an exclusive lock, if the old file exists
	// is the passed log already open?
	if (log->fd >= 0) {
		if (log->access == CCL_READ) {
			log->last_err= CCL_ERDONLY;
			log->last_errno= 0;
			return false;
		}
		else if (log->access == CCL_SHARE) {
			lock_log(log);
		}
		haveOld= true;
	}
	else {
		if (ccl_open(log, path)) {
			haveOld= true;
		} else if (create && log->last_err == CCL_ELOGOPEN && log->last_errno == ENOENT) {
		} else if (force) {
		} else {
			// if we can't open it, and it does exist, and we're not supposed to blow it away,
			//  we fail.
			return false;
		}
	}
	
	// Step two, create the new log with an alternate file name
	if (strlen(path)+2 > sizeof(fname)) {
		log->last_err= CCL_ESYSERR;
		log->last_errno= ENAMETOOLONG;
		return false;
	}
	strcpy(fname, path);
	if (haveOld) strcat(fname, "~");
	
	ccl_init(&newLog, sizeof(newLog));
	newLog.block_size= coerce_block_size(log->block_size);
	newLog.size= coerce_log_size(newSize, newLog.block_size);
	newLog.header_size= sizeof(header);
	newLog.timestamp_precision= log->timestamp_precision;
	newLog.version= CCL_CURRENT_VERSION;
	newLog.max_message_size= (haveOld? log->max_message_size : CCL_DEFAULT_MAX_MESSAGE_SIZE);
	newLog.access= CCL_WRITE;
	
	newLog.fd= open(fname, O_RDWR|O_CREAT|O_EXCL, 0700);
	if (newLog.fd < 0
		|| !lock_log(&newLog)
		|| ftruncate(newLog.fd, newLog.size) < 0
	) {
		log->last_err= CCL_ERESIZECREATE;
		log->last_errno= errno;
		
		// only unlink if we just now created it
		if (newLog.fd >= 0) unlink(fname);
		
		ccl_destroy(&newLog);
		return false;
	}
	
	memset(&header, 0, sizeof(header));
	header.magic= CCL_HEADER_MAGIC;
	header.version= CCL_CURRENT_VERSION;
	header.oldest_compat_version= 0;
	header.size= newLog.size;
	header.header_size= newLog.header_size;
	header.block_size= newLog.block_size;
	header.timestamp_precision= newLog.timestamp_precision;
	
	if (!write_rec(newLog.fd, &header, header.header_size)) {
		log->last_err= CCL_ERESIZECREATE;
		log->last_errno= errno;
		
		unlink(fname);
		ccl_destroy(&newLog);
		return false;
	}
	newLog.file_pos= header.header_size;
	
	// Now, we iterate over all the messages in the old log
	if (haveOld) {
		// TODO: implement
	}
	// We also destroy the old log.
	if (!ccl_destroy(log))
		return false;
	
	// Now, we close and delete the old log
	if (rename(fname, path) < 0) {
		log->last_err= CCL_ERESIZERENAME;
		log->last_errno= errno;
		return false;
	}
	
	// And now transfer the new log internals to the passed-in log struct.
	// The caller's log struct could possibly be an old version, so we need to take
	//  care to only copy fields that exist inside of log->struct_size
	
	// log->sizeof_struct remains the same
	log->size= newLog.size;
	log->header_size= newLog.header_size;
	log->block_size=  newLog.block_size;
	log->version= newLog.version;
	// log->max_message_size remains the same
	// log->wrong_endian= newLog.wrong_endian;
	// log->dirty= newLog.dirty;
	log->access= newLog.access;
	log->fd= newLog.fd;
	log->file_pos= newLog.file_pos;
	log->memmap= newLog.memmap;
	// don't touch error codes
	
	// We also don't ccl_destroy(newLog) because we just transferred or freed all its allocated parts.
	
	// All done!
	return true;
}
*

int64_t ccl_seek(ccl_log_t *log, int mode, int64_t value) {
	switch (mode) {
	case CCL_SEEK_OLDEST:
	case CCL_SEEK_RELATIVE:
	case CCL_SEEK_NEWEST:
	case CCL_SEEK_ADDR:
		return 0;
	case CCL_SEEK_LIMIT:
		
	case CCL_SEEK_TIME:
		return 0;
	default:
		log->last_err= CCL_EPARAM;
		log->last_errno= 0;
		return 0;
	}
}

inline int64_t nextBlock(ccl_log_t *log, int64_t addr) {
	int64_t mask= log->block_size-1;
	addr= ((addr+mask) & ~mask);
	return addr > log->size? log->header_size : addr;
}
inline int64_t firstMsgInBlock(int64_t blockAddr) {
	return addr+log->block_size-8
}

typedef int bsearch_callback_t(int64_t timestamp);
bool block_search(ccl_log_t *log, bsearch_callback_t *test) {
	int64_t addr= log->header_size;
	
}
*
inline int encode_size(uint64_t value, uint64_t *encoded_out) {
	if (value >> 14) {
		if (value >> 29) {
			if (value >> 60)
				return 0; // larger than 60 bit isn't supported (though could theoretically exist)
			*encoded_out= (value << 4)|7;
			return 8;
		}
		*encoded_out= (value << 3)|3;
		return 4;
	} else {
		if (value >> 7) {
			*encoded_out= (value << 2)|1;
			return 2;
		}
		*encoded_out= (value << 1);
		return 1;
	}
}

inline int decode_size(uint64_t encoded, uint64_t *value_out) {
	switch ((int) (encoded & 0xF)) {
	case 0b1111:
		return 0;
	case 0b0111:
		*value_out= encoded >> 4;
		return 8;
	case 0b0011:
	case 0b1011:
		*value_out= (encoded & 0xFFFFFFFF) >> 3; 
		return 4;
	case 0b0001:
	case 0b0101:
	case 0b1001:
	case 0b1101:
		*value_out= (encoded & 0xFFFF) >> 2;
		return 2;
	default:
		*value_out= (encoded & 0xFF) >> 1;
		return 1;
	}
}

bool ccl_write_message(ccl_log_t *log, const struct iovec *caller_iov, int iov_count, int64_t timestamp) {
	uint64_t i64_buf[4];
	int i, iov_count_tmp;
	struct iovec iov_tmp, *iov;
	int64_t freespace, msglen, msglen2, msg_filepos, bytes_needed;
	
	// access-mode check
	if (log->access == CCL_READ) {
		log->last_err= CCL_ERDONLY;
		log->last_errno= 0;
		return false;
	}
	// TODO: add support for shared write-access
	if (log->access == CCL_SHARE) {
		log->last_err= CCL_ESYSERR;
		log->last_errno= 0;
		return false;
	}
	
	// Fill in the timestamp with "now()" if not specified by the user
	if (timestamp == 0) {
		timestamp= ccl_encode_timestamp(log, NULL);
		if (timestamp == 0) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
	}
	
	// sum up the message size
	// start at 64 so we can check the whole record size for overflow
	msglen= 64;
	for (i= 0; i < iov_count; i++) {
		msglen2= msglen + iov[i].iov_len;
		if (msglen2 < msglen) {
			log->last_err= CCL_EMSGSIZE;
			log->last_errno= 0;
			return false;
		}
		msglen= msglen2;
	}
	msglen -= 64; // subtract it back off
	// check vs. max message size
	if (msglen > log->max_message_size) {
		log->last_err= CCL_EMSGSIZE;
		log->last_errno= 0;
		return false;
	}
	
	// encode the variable-length size, and determine its size
	sizeof_size= encode_size(msglen, &i64_buf[0]);
	if (!sizeof_size) {
		log->last_err= CCL_EMSGSIZE;
		log->last_errno= 0;
		return false;
	}
	
	msg_filepos= log->next_message_filepos;
	
	// first size gets encoded little-endian, and second size gets encoded big-endian
	i64_buf[1]= i64_buf[0];
	i64_buf[0]= htole64(i64_buf[0]);
	i64_buf[1]= htobe64(i64_buf[1]);
	// after reverse size is timestamp, and checksum, encoded as little-endian
	i64_buf[2]= htole64(timestamp);
	i64_buf[3]= CCL_MESSAGE_CHECKSUM(msglen, timestamp, msg_filepos);
	
	// ensure we have enough iov slots for this message
	// (we re-use an iovec which we keep in log->iovec_buf)
	if (log->iovec_count < iov_count+2) {
		newbuf= realloc(log->iovec_buf, sizeof(*iov) * (iov_count+2));
		if (!newbuf) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
		log->iovec_buf= newbuf;
		log->iovec_count= iov_count+2;
	}
	iov= (struct iovec *) log->iovec_buf;
	
	// now build the new iov
	iov[0].iov_base= (void*) i64_buf;
	iov[0].iov_len=  (size_t) sizeof_size;
	memcpy(iov+1, caller_iov, sizeof(*iov) * iov_count);
	iov_count++;
	iov[iov_count].iov_base= (void*)(((char*)(i64_buf+2)) - sizeof_size);
	iov[iov_count].iov_len=  8 + 8 + 8 - ((sizeof_size + msglen) & 0x7)
	iov_count++;
	
	// determine total message record size
	bytes_needed= msglen + iov[0].iov_len + iov[iov_count].iov_len;
	log->bytes_til_next_index-= bytes_needed;
	
	// compare with remaining space in data area
	// when we reach the end of the file, we have to split the message in 2 pieces.
	freespace= log->size - log->next_message_filepos;
	if (bytes_needed > freespace && freespace > 0) {
		bytes_needed -= freespace;
		iov_count_tmp= 0;
		while (freespace) {
			if (freespace >= iov[iov_count_tmp].iov_len) {
				iov_count_tmp++
				freespace -= iov[iov_count_tmp].iov_len;
			}
			else {
				iov_tmp= iov[iov_count_tmp];
				iov[iov_count_tmp].iov_len= (size_t) freespace;
				iov_count_tmp++;
				freespace= 0;
			}
		}
		
		writeev_all(log, iov, iov_count_tmp)
			or return false;
		// then seek to start of message area
		if (lseek(log->fd, (size_t) log->header_size + log->index_size, SEEK_SET) < 0) {
			log->last_err= CCL_ELOGWRITE;
			log->last_errno= errno;
			return false;
		}
		log->next_message_filepos= log->header_size + log->index_size;
		log->bytes_til_next
		
		// If the final iov was clipped,
		if (iov[iov_count_tmp-1].iov_len < iov_tmp.iov_len) {
			// shift the final iov to point to its other half
			iov+= iov_count_tmp - 1;
			iov_count -=  iov_count_tmp - 1;
			iov[0].iov_base= ((char*)(iov[0].iov_base)) + iov[0].iov_len;
			iov[0].iov_len = iov_tmp.iov_len - iov[0].iov_len;
		}
		else {
			iov += iov_count_tmp;
			iov_count -= iov_count_tmp;
		}
	}
	
	writeev_all(log, iov, iov_count)
		or return false;
	log->next_message_filepos+= bytes_needed;
	
	// update any index boundaries we've crossed
		printf("stub: update index\n");
		// FOR each ?KB boundary our message overlaps,
		//   update that index entry
		// if index changed, seek back to file position
	
	return false;
}

bool ccl_read_message(ccl_log_t *log, ccl_message_info_t *msg_out) {
	// read 3 x int64 before current file pos
	// parse size, and verify checksum
	// read the message into the log's buffer
	// verify size is also at start of message
	// present to user
	return false;
}


	uint64_t encoded_size= 0;
	int size_bytes, padding, count;
	// leave room for padding(max=7), reverse_count(max=8), timestamp(8), checksum(8)
	uint64_t suffix[4];
	
	if (!(msg
		&& msg->sizeof_struct == sizeof(*msg)
		&& msg->data_len > 0
		&& (msg->data_ofs == 0?
			// if starting a new message, make sure length and offset make sense
			// and make sure the log object doesn't think we're in the middle of a prev msg
			(log->msg_pos == 0
			&& log->msg_len == 0
			&& msg->msg_len > 0
			&& msg->msg_len <= log->max_message_size
			&& (int64_t)msg->data_len <= (int64_t) msg->msg_len
			)
			:
			// if continuing a message, make sure this picks up where prev call ended
			(msg->msg_len == log->msg_len
			&& msg->data_ofs == log->msg_pos
			)
		)
	)) {
		log->last_err= CCL_EPARAM;
		log->last_errno= 0;
		return false;
	}
	
	// If writing a new message, the file pointer should be on a multiple of 8
	if (!((log->size & 7) == 0
		&& log->file_pos >= log->header_size
		&& log->file_pos <= log->size
		&& (msg->data_ofs || (log->file_pos & 0x7) == 0)
	)) {
		log->last_err= CCL_ELOGSTRUCT;
		log->last_errno= 0;
		return false;
	}
	
	// access-mode check
	if (log->access == CCL_READ) {
		log->last_err= CCL_ERDONLY;
		log->last_errno= 0;
		return false;
	}
	// TODO: add support for shared write-access
	if (log->access == CCL_SHARE) {
		log->last_err= CCL_ESYSERR;
		log->last_errno= 0;
		return false;
	}
	
	// make sure we have a write-buffer
	if (!log->buffer) {
		if (!log->buffer_size)
			log->buffer_size= 8*1024; // TODO: make this reflect the max-message-size, a bit.
		if (log->buffer_size < 256)
			log->buffer_size= 256;
		if (!(log->buffer= malloc(log->buffer_size))) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
	}
	
	// Fill in the timestamp with "now()" if not specified by the user
	if (msg->timestamp == 0) {
		msg->timestamp= ccl_encode_timestamp(log, NULL);
		if (msg->timestamp == 0) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
	}
	
	*
	 * We now have asserted the following conditions:
	 * If we are writing a new message:
	 *   - 0 == msg->data_ofs == log->msg_ofs == log->msg_len < msg->msg_len
	 *   - 0 < msg->data_len <= msg->msglen <= max_message_size
	 *   - log->file_pos is a multiple of 8, and is in a valid position (where we assume the end of the previous message is)
	 * If we are continuing a message:
	 *   - 0 < msg->data_ofs == log->msg_ofs < log->msg_len == msg->msg_len
	 *   - log->file_pos is in a valid position (which we assume is the middle of the previous message's data)
	 *
	
	size_bytes= encode_size(&encoded_size, msg->msg_len);
	
	// starting a new message?
	if (log->msg_pos == 0) {
		log->msg_start_addr= log->file_pos;
		log->msg_len= msg->msg_len;
		
		// The buffer is empty, and size is greater than 8, so just write it directly
		assert(log->buffer_pos == 0);
		assert(log->buffer_size >= 8);
		assert(log->file_pos <= (((log->file_pos + log->block_size - 1) & ~(log->block_size-1)) - 16));
		assert(log->file_pos < log->size);
		*((int64_t*) log->buffer)= htole64(encoded_size);
		log->buffer_pos= size_bytes;
	}

	// write the data
	if (!buffered_write(log, msg->data, msg->data_len, false))
		return false;
	
	// ending the message?
	if (msg->data_ofs + msg->data_len == msg->msg_len) {
		suffix[0]= 0; // possible padding for data
		suffix[1]= htobe64(encoded_size);
		suffix[2]= htole64(msg->timestamp);
		suffix[3]= CCL_MESSAGE_CHECKSUM(msg->data_len, msg->timestamp, log->msg_start_addr);
		
		// The beginning of log->buffer is always 8-aligned, so we can calculate alignment
		//  with buffer_pos instead of calculating the actual file address
		padding= ((log->buffer_pos + 7) & ~7) - log->buffer_pos;
		count= (padding >= size_bytes? padding + 16 : padding + 24);
		if (!buffered_write(log, ((char*)(suffix+4)) - count, count, true))
			return false;
		
		assert((log->buffer_pos & 7) == 0);
		log->msg_pos= 0;
		log->msg_len= 0;
	}
	else {
		// to be continued by another call
		log->msg_pos+= msg->data_len;
	}
	return true;
}*

ccl_message_info_t *ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen) {
	return NULL;
}
*/

int ccl_err_code(ccl_log_t *log, int *syserr_out) {
	if (syserr_out)
		*syserr_out= log->last_errno;
	return log->last_err;
}

int ccl_err_text(ccl_log_t *log, char* buf, int buflen) {
	const char *msg, *next_var, *err_str;
	char *pos;
	int count, bufpos, n;
	
	if (!(msg= log->last_errmsg))
		msg= "no error";
	
	// perform substitutions on "$var"
	bufpos= 0;
	while (*msg) {
		next_var= strchr(msg, '$');
		// copy literal portion of message
		count= next_var? next_var-msg : strlen(msg);
		if (bufpos < buflen)
			memcpy(buf+bufpos, msg, count < (buflen-bufpos)? count : (buflen-bufpos));
		msg+= count;
		bufpos+= count;
		// If ended on a variable,
		if (next_var) {
			next_var++; // skip '$' to reach start of the name
			msg= next_var;
			// iterate to end of the name
			while (*msg >= 'a' && *msg <= 'z') msg++;
			// identify it
			count= msg - next_var; // length of name
			n= buflen > bufpos? buflen-bufpos : 0; 
			pos= buflen > bufpos? buf+bufpos : NULL; // place in buffer to write (or null, to only calc length)
			if (strncmp(next_var, "syserr", count) == 0) {
				char errbuf[128];
				// Here, we deal with stupidity regarding strerror.
				// If only sprintf(%m) were portable...
				#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
				err_str= errbuf;
				if (strerror_r(log->last_errno, errbuf, sizeof(errbuf)) < 0)
					snprintf(errbuf, sizeof(errbuf), "errno %d", (int) log->last_errno);
				#else
				err_str= strerror_r(log->last_errno, errbuf, sizeof(errbuf));
				#endif
				bufpos+= snprintf(pos, n, "%s", err_str);
			}
			else if (strncmp(next_var, "logfile", count) == 0) {
				bufpos+= snprintf(pos, n, "%s", "log file"); // TODO: sub file name, if known
			}
			else {
				bufpos+= snprintf(pos, n, "$%.*s", count, next_var);
			}
		}
	}
	if (buflen)
		buf[bufpos < buflen? bufpos : buflen-1]= '\0';
	return bufpos;
}
