#include "config.h"
#include "libcirculog.h"

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
	log->fd= -1;
	return true;
}

bool ccl_destroy(ccl_log_t *log) {
	bool err= false;
	if (log->memmap) {
		err= err || munmap((void*)log->memmap, (size_t) log->memmap_size);
		log->memmap= NULL;
		log->memmap_spool= NULL;
		log->memmap_size= 0;
	}
	if (log->fd >= 0) {
		err= err || close(log->fd);
		log->fd= -1;
	}
	if (log->iovec_buf) {
		free(log->iovec_buf);
		log->iovec_buf= NULL;
		log->iovec_buf_count= 0;
	}
	return !err;
}

bool log_resize_iovec(ccl_log_t *log, int new_count) {
	void *newbuf;
	newbuf= realloc(log->iovec_buf, sizeof(struct iovec) * new_count);
	if (!newbuf)
		return SET_ERR(log, CCL_ESYSERR, "malloc: $syserr");
	log->iovec_buf= newbuf;
	log->iovec_buf_count= new_count;
	return true;
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

static inline bool log_seek(ccl_log_t *log, off_t offset) {
	if (lseek(log->fd, offset, SEEK_SET) == (off_t)-1)
		return SET_ERR(log, CCL_ESEEK, "seek failed: $syserr");
	return true;
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

static inline int64_t log_wrap_addr(ccl_log_t *log, int64_t addr) {
	addr= addr >> 3 << 3;
	return addr < 0? addr+log->spool_size
		: addr >= log->spool_size? addr - log->spool_size
		: addr;
}

static inline bool log_readspool(ccl_log_t *log, int64_t start_addr, void *record, size_t record_size) {
	if (!log_seek(log, log->spool_start + start_addr))
		return false;
	if (start_addr+record_size > log->spool_size) {
		int n= (int) (log->spool_size - start_addr);
		if (!log_read(log, record, n))
			return false;
		if (!log_seek(log, log->spool_start))
			return false;
		record= (void*) ((char*) record + n);
		record_size -= n;
	}
	return log_read(log, record, record_size);
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

static bool log_writev(ccl_log_t *log, struct iovec *iov, int iov_count) {
	int wrote;
	while (iov_count) {
		wrote= writev(log->fd, iov, iov_count);
		if (wrote < 0) {
			if (errno == EINTR) continue;
			return SET_ERR(log, CCL_EWRITE, "write failed: $syserr");
		}
		while (wrote && iov_count) {
			if (wrote >= iov[0].iov_len) {
				wrote -= iov[0].iov_len;
				iov++;
				iov_count--;
			} else {
				iov[0].iov_len-= wrote;
				iov[0].iov_base= ((char*)iov[0].iov_base) + wrote;
				wrote= 0;
			}
		}
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
		return SET_ERR(log, CCL_ELOCK, "Failed to lock $logfile for writing: $syserr");
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
		return SET_ERR(log, CCL_ELOCK, "Failed to unlock $logfile: $syserr");
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
	header.version=               htole32((int32_t)CCL_CURRENT_VERSION);
	header.oldest_compat_version= htole32((int32_t)CCL_CURRENT_VERSION);
	header.header_size=           htole32((int32_t)sizeof(header));
	header.timestamp_precision=   htole32((int32_t)log->timestamp_precision);
	header.timestamp_epoch=       htole64(log->timestamp_epoch);
	header.index_start=           htole64(index_start);
	header.index_size=            htole64(index_size);
	header.spool_start=           htole64(spool_start);
	header.spool_size=            htole64(spool_size);
	header.max_message_size=      htole32((int32_t)log->max_message_size);
	
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
	
	if (!log_seek(log, 0))
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
*/

/** Encode a number as a variable number of bytes, within an int64.
 *
 * 0..0x7F use one byte, and are shifted left (given a low 0 bit)
 * 0x80..0x3FFF use 2 bytes, and are shifted left 2 (given low bits 01)
 * 0x4000..0x1FFFFFFF use 4 bytes, and are shifted left 3 (given low bits 011)
 * 0x20000000..0x0FFFFFFFFFFFFFFF use 8 bytes and are shifted left 4 (given low bits 0111)
 * Numbers greater than this are not currently supported (or needed), though they would
 * continue the pattern of doubling the width and adding a low-order 1-bit.
 *
 * Returns the number of *bytes* used.  Returns the encoded number in encoded_out,
 * in the low-order bits.
 */
inline int encode_size(uint32_t value, uint32_t *encoded_out) {
	if (value >> 14) {
		if (value >> 29) {
			return 0; // larger than 29 bit isn't supported by this implementation
			//if (value >> 60) {
			// ...
			//}
			//*encoded_out= (value << 4)|7;
			//return 8;
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

/** Decode a number previously encoded by encode_size.
 * See encode_size() for encoding details.
 *
 * The original size is stored in value_out, as a plain 64-bit int.
 *
 * Returns the number of *bytes* the size occupied within 'encoded', or 0 if
 * the size was larger than 64-bit (not supported by this implementation,
 * and likely invalid)
 */
inline int decode_size(uint32_t encoded, uint32_t *value_out) {
	switch ((int) (uint8_t) encoded) {
	case 0b0111:
//		*value_out= encoded >> 4;
//		return 8;
	case 0b1111:
		return 0;
	case 0b0011:
	case 0b1011:
		*value_out= ((uint32_t) encoded) >> 3; 
		return 4;
	case 0b0001:
	case 0b0101:
	case 0b1001:
	case 0b1101:
		*value_out= ((uint16_t) encoded) >> 2;
		return 2;
	default:
		*value_out= ((uint8_t) encoded) >> 1;
		return 1;
	}
}

/** ccl_read_msg - try to read a message (usually combined with a seek flag)
 *
 * Reading a CircuLog is a best-effort sort of algorithm, which runs
 * unsynchronized with the writing process, and may or may not succeed.
 * This function attempts to find the log message you were interested in,
 * and read it into a buffer where you can safely work with it.  It verifies
 * a weak checksum of the protocol prefix/suffix bytes to ensure (with only
 * moderate certainty) that the message you read was a complete record.
 * If your messages are flagged as having data-checksums, then the data is
 * checked and you get much higher certainty that you have a complete record.
 *
 * If no seek flag is specified, this method tries to read a message at
 * msg->address, and fails if that is not the start of a valid message.
 * 
 * Upon success, ccl_read_msg will return true, and set all fields of msg
 * other than buffer and buffer_len, unless CCL_BUFFER_AUTO flag is given
 * in which case the buffer will be resized as needed.
 *
 * The msg->data pointer will be set to "" if the flag CCL_NODATA is requested,
 * and msg->data_len to 0.
 *
 * Else, if msg->buffer is non-null (possibly as the result of CCL_BUFFER_AUTO)
 * msg->data will be a pointer into msg->buffer.  msg->data_len might be less
 * than the full message length if the buffer wasn't large enough, but the return
 * code will be false to make you aware of this.  Try again with a buffer at least
 * msg->frame_len or larger.
 *
 * Note that the writer is allowed to write raw binary data (including NUL
 * charachers) into a message.  Use data_len instead of strlen(data) if you
 * want to correctly handle these messages. But for convenience, the protocol
 * places a NUL byte at the end of every message, so you can safely operate
 * on the data as a string if you expect your messages to be text.  Messages
 * truncated by insufficient buffer space will also always be NUL-terminated.
 * 
 * Seek Flags:
 *
 * CCL_SEEK_ADDR searches for the nearest message to msg->address.  This can
 * be time consuming if msg->address is not near a message boundary and the
 * messages are large, but for "normal" sized messages, it won't be noticable.
 *
 * CCL_SEEK_TIME searches the log for the first message with a timestamp
 * greater or equal to the value of msg->timestamp
 *
 * CCL_SEEK_OLDEST searches the log for the message with the oldest timestamp.
 *
 * CCL_SEEK_NEWEST searches the log for the message with the newest timestamp.
 *
 * CCL_SEEK_PREV tries to read a log message occuring immediately before the
 * message at msg->address.
 *
 * CCL_SEEK_NEXT tries to read a log message immediately following the message
 * at msg->address based on msg->frame_len.
 *
 * CCL_SEEK_RELATIVE looks at msg->offset to perform some number of CCL_SEEK_PREV
 * (negative) or CCL_SEEK_NEXT (positive).  In other words, setting msg->offset
 * to -1 and using the flag CCL_SEEK_RELATIVE is the same as using the flag
 * CCL_SEEK_PREV. -5 means perform CCL_SEEK_PREV 5 times.
 *
 */
bool ccl_read_msg(ccl_log_t *log, ccl_msg_t *msg, int flags) {
	ccl_msg_header_t header;
	ccl_msg_footer_t footer;
	
	if (flags & CCL_SEEK_ADDR) {
		// Scan 1024 bytes at a time, in each direction, and pick the nearest message.
		return SET_ERR(log, CCL_EUNSUPPORTED, "unimplemented"); // TODO: implement.
	}
	else if (flags & CCL_SEEK_TIME) {
		// seek toward the given timestamp
		return SET_ERR(log, CCL_EUNSUPPORTED, "unimplemented"); // TODO: implement
	}
	else if (flags & CCL_SEEK_OLDEST) {
		return SET_ERR(log, CCL_EUNSUPPORTED, "unimplemented"); // TODO: implement
	}
	else if (flags & CCL_SEEK_NEWEST) {
		return SET_ERR(log, CCL_EUNSUPPORTED, "unimplemented"); // TODO: implement
	}
	else if (flags & CCL_SEEK_PREV) {
		// see if another message ends at this address
		if (!log_load_msg_footer(log, log_wrap_addr(log, msg->address), &footer)
			|| !log_load_msg_header(log, footer.start_addr, &header))
			return SET_ERR(log, CCL_ENOTFOUND, log->last_errmsg);
	}
	else if (flags & CCL_SEEK_NEXT) {
		// see if there is a message following this one.  This uses the length
		// of the cuurent message, rather than reading it again
		if (!log_load_msg_header(log, log_wrap_addr(log, msg->address + msg->frame_len), &header)
			|| !log_load_msg_footer(log, header.end_addr, &footer))
			return SET_ERR(log, CCL_ENOTFOUND, log->last_errmsg);
	}
	else
		return SET_ERR(log, CCL_EBADPARAM, "missing seek flag");
	
	if (flags & CCL_NODATA)
		return log_load_msg_nodata(log, &header, &footer, msg);
	else
		return log_load_msg(log, header.start_addr, header.end_addr, msg, flags & CCL_BUFFER_AUTO);
}

bool log_find_msg_header(ccl_log_t *log, int64_t addr, int64_t limit, ccl_msg_header_t *header) {
	size_t buf_len, buf_pos;
	char *buf;
	
	assert((addr & 7) == 0);
	assert(addr >= 0);
	assert(addr < log->spool_start);
	
	// allocate buffer if non-memmap
	if (!log->memmap) {
		buf_len= log->spool_size > 4096? 4096 : log->spool_size;
		buf= malloc(buf_len);
		if (!buf)
			return SET_ERR(log, CCL_ESYSERR, "malloc failed");
	}
	
	// positive limit means scan forward
	while (limit > 0) {
		if (log->memmap_spool) {
			// handle spool-wrap
			buf= (char*)(log->memmap_spool+addr);
			buf_len= (size_t) (addr+limit > log->spool_size)? log->spool_size - addr : limit;
		}
		else {
			if (buf_len > limit) buf_len= limit;
			if (!log_readspool(log, addr, buf, buf_len)) {
				free(buf);
				return false;
			}
		}
		// find next signature
		for (buf_pos=0; buf_pos < buf_len; buf_pos+= 8) {
			if (buf[buf_pos] == '\x1E' && buf[buf_pos+1] == '\x01')
				if (log_load_msg_header(log, log_wrap_addr(log, addr+buf_pos-8), header)) {
					if (!log->memmap_spool)
						free(buf);
					return true;
				}
		}
		addr+= buf_len;
		if (addr >= log->spool_size) addr-= log->spool_size;
		limit-= buf_len;
	}
	// negative means scan backward
	while (limit < 0) {
		if (log->memmap_spool) {
			// handle spool_wrap
			if (addr+limit >= 0) { // can scan in one shot
				addr+= limit;
				buf_len= -limit;
				limit= 0;
			} else if (addr > 0) { // scan back to start of spool
				limit+= addr;
				buf_len= addr;
				addr= 0;
			} else { // scan from end of spool back -limit bytes
				addr= log->spool_size+limit;
				buf_len= -limit;
				limit= 0;
			}
			buf= (char*)(log->memmap_spool+addr);
		}
		else {
			if (buf_len > -limit) buf_len= -limit;
			addr-= buf_len;
			if (addr < 0) addr+= log->spool_size;
			if (!log_readspool(log, addr, buf, buf_len)) {
				free(buf);
				return false;
			}
		}
		// find next signature
		for (buf_pos=buf_len-8; buf_pos >= 0; buf_pos-= 8) {
			if (buf[buf_pos] == '\x1E' && buf[buf_pos+1] == '\x01')
				if (log_load_msg_header(log, log_wrap_addr(log, addr+buf_pos-8), header)) {
					if (!log->memmap_spool)
						free(buf);
					return true;
				}
		}
	}
	return SET_ERR(log, CCL_ENOTFOUND, "");
}

/** Load the header of the message frame into the ccl_msg_t object.
 *
 * Returns true if it succeeds and the data looks valid.
 * Returns false (with an error in the log object) if anything went wrong.
 */
bool log_load_msg_header(ccl_log_t *log, int64_t start_addr, ccl_msg_header_t *header) {
	char buffer[16];

	assert((start_addr & 7) == 0);
	assert(start_addr >= 0);
	assert(start_addr < log->spool_start);

	// read the header (for timestamp, signature and size)
	// handle case where it could wrap the end of the spool (which is always a multiple of 8 bytes)
	if (log->memmap_spool) {
		if (start_addr+8 < log->spool_size)
			memcpy(buffer, (void*)(log->memmap_spool+start_addr), 16);
		else {
			memcpy(buffer, (void*)(log->memmap_spool+start_addr), 8);
			memcpy(buffer+8, (void*)(log->memmap_spool), 8);
		}
	}
	else if (!log_readspool(log, start_addr, buffer, 16))
		return false;
	
	header->start_addr= start_addr;
	return log_parse_msg_header(log, buffer, header);
}

inline bool log_parse_msg_header(ccl_log_t *log, const char *buffer, ccl_msg_header_t *header) {
	int size_size;
	uint32_t msglen;

	// check signature
	if (le16toh(* (uint16_t*) (buffer+8)) != CCL_MSG_SIGNATURE)
		return SET_ERR(log, CCL_ENOTFOUND, "Bad signature");
	
	// decode the size
	size_size= decode_size( le32toh(* (uint32_t*) (buffer+12)), &msglen );
	if (!(size_size > 0 && msglen > 0 && msglen+24 < log->spool_size && msglen <= log->max_message_size))
		return SET_ERR(log, CCL_ENOTFOUND, "Bad msglen");
	
	// record results
	header->end_addr= header->start_addr + CCL_MESSAGE_FRAME_SIZE(msglen, size_size);
	if (header->end_addr >= log->spool_size)
		header->end_addr -= log->spool_size;
	header->msg_len=       msglen;
	header->data_ofs=      12 + size_size;
	header->timestamp=     le64toh(* (int64_t *) buffer);
	header->msg_type=      (uint8_t) buffer[10];
	header->msg_chk_algo=  (0xF & buffer[11]) + 1;
	header->msg_level=     (0xF & (buffer[11] >> 4)) - 3;
	return true;
}

/** Load the footer of the message frame into the ccl_msg_t object.
 *
 * Returns true if it succeeds and the data looks valid.
 * Returns false (with an error in the log object) if anything went wrong.
 */
bool log_load_msg_footer(ccl_log_t *log, int64_t end_addr, ccl_msg_footer_t *footer) {
	char buffer[8];
	int64_t addr;
	
	assert((end_addr & 7) == 0);
	assert(end_addr >= 0);
	assert(end_addr < log->spool_start);
	
	// read the end of the message (containing size)
	addr= end_addr - 16;
	if (addr < 0)
		addr+= log->spool_size;
	if (log->memmap) {
		memcpy(buffer, (void*)(log->memmap_spool + addr), 8);
	} else {
		if (!log_readspool(log, addr, buffer, 8))
			return false;
	}

	footer->end_addr= end_addr;
	return log_parse_msg_footer(log, buffer, footer);
}

inline bool log_parse_msg_footer(ccl_log_t *log, const char* buffer, ccl_msg_footer_t *footer) {
	int size_size;
	uint32_t msglen;

	// parse size
	size_size= decode_size( be32toh(* (uint32_t*) buffer), &msglen );
	if (size_size <= 0 || msglen <= 0 || msglen > log->spool_size || msglen > log->max_message_size)
		return SET_ERR(log, CCL_ENOTFOUND, "Bad msglen");
	
	// Success.  Set fields of footer struct
	footer->start_addr= footer->end_addr - CCL_MESSAGE_FRAME_SIZE(msglen, size_size);
	if (footer->start_addr < 0)
		footer->start_addr+= log->spool_size;
	footer->msg_len= msglen;
	footer->frame_cksum= le32toh(* (uint32_t*) (buffer+4));
	return true;
}

/** Identify whether a message might exist at an address.
 *
 * Returns a boolean of whether it succeeded.
 *
 * log - a log object, in an open state
 * msg - a ccl_msg object, possibly partially populated
 * got_header - whether the header was loaded already
 * got_footer - whether the footer was loaded already
 * 
 */
bool log_load_msg_nodata(ccl_log_t *log, ccl_msg_header_t *header, ccl_msg_footer_t *footer, ccl_msg_t *msg) {
	ccl_msg_header_t _header;
	ccl_msg_footer_t _footer;
	
	// load what we don't have already
	if (!header) {
		if (!footer)
			return SET_ERR(log, CCL_EBADPARAM, "Need header or footer");
		header= &_header;
		if (!log_load_msg_header(log, footer->start_addr, header))
			return false;
	}
	if (!footer) {
		footer= &_footer;
		if (!log_load_msg_footer(log, header->end_addr, footer))
			return false;
	}

	// verify sizes and addresses match
	if (header->start_addr != footer->start_addr
		|| header->end_addr != footer->end_addr
		|| header->msg_len != footer->msg_len)
		return SET_ERR(log, CCL_ENOTFOUND, "invalid message; header/footer mismatch");
	
	// check frame_checksum
	if (footer->frame_cksum != CCL_MESSAGE_FRAME_CHECKSUM(header->start_addr, header->msg_len, header->timestamp))
		return SET_ERR(log, CCL_ENOTFOUND, "Wrong frame checksum");
	
	// found a possible message.  give caller what they asked for.
	msg->address=   header->start_addr;
	msg->timestamp= header->timestamp;
	msg->frame_len= (header->end_addr > header->start_addr)?
		header->end_addr - header->start_addr
		: header->end_addr - header->start_addr + log->spool_size;
	msg->data=      "";
	msg->data_len=  0;
	msg->type=      header->msg_type;
	msg->chk_algo=  header->msg_chk_algo;
	msg->level=     header->msg_level;
	return true;
}

/** Loads a message from the specified address range, and stores it in msg.
 *
 * A message must be copied out of the memmap in order to protect from
 * concurrent writes.  This function copies the range of the log's spool,
 * and then tries to validate that the message is not corrupted, using
 * whatever checksum algorithm the log is using.
 *
 * If the buffer in msg is not large enough, it copies what it can, and
 * returns false with an error code of CCL_ESIZELIMIT, which also means that
 * the message has not been validated!
 */
bool log_load_msg(ccl_log_t *log, int64_t start_addr, int64_t end_addr, ccl_msg_t *msg, bool grow_buffer) {
	int64_t frame_len;
	size_t n, n2;
	ccl_msg_header_t header;
	ccl_msg_footer_t footer;
	char _buf[16];
	char *buf;
	
	// sanity checks
	assert((start_addr & 7) == 0);
	assert(start_addr >= 0);
	assert(start_addr < log->spool_size);
	assert((end_addr & 7) == 0);
	assert(end_addr >= 0);
	assert(end_addr < log->spool_size);
	
	// figure size of message + timestamp & checksum
	frame_len= end_addr - start_addr;
	if (frame_len < 0)
		frame_len+= log->spool_size;
	// Sanity check on frame size
	if (frame_len < 24 || frame_len > log->max_message_size + 24)
		return SET_ERR(log, CCL_EBADPARAM, "invalid message length");
	// Must fit in size_t for this implementation
	if (sizeof(size_t) < 8 && frame_len > (int64_t)(size_t)-1)
		return SET_ERR(log, CCL_EUNSUPPORTED, "message size exceeds size_t");

	n= (size_t) frame_len;
	// Grow the buffer if needed and allowed
	if (grow_buffer && n > msg->buffer_len) {
		buf= (char*) realloc(msg->buffer, n);
		if (!buf)
			return SET_ERR(log, CCL_ESYSERR, "Can't allocate read buffer");
		msg->buffer= buf;
		msg->buffer_len= n;
	}
	// else if the buffer is fine, use it
	else if (n <= msg->buffer_len) {
		buf= msg->buffer;
	}
	// else if we can't fit it all in the buffer, return part of it
	else if (msg->buffer_len > 16) {
		buf= msg->buffer;
		n= msg->buffer_len;
	}
	// or if the buffer is smaller than the header, use our own buffer
	else {
		buf= _buf;
		n= 16;
	}
	
	// Copy the message (or just part of it if buffer was too small)
	if (log->memmap_spool) {
		// if we wrap, split the operation
		if (log->spool_size - start_addr < frame_len) {
			n2= (int) (log->spool_size - start_addr);
			memcpy(buf,    (void*)(log->memmap_spool + start_addr), n2);
			memcpy(buf+n2, (void*)(log->memmap_spool), n - n2); 
		} else {
			memcpy(buf,    (void*)(log->memmap_spool + start_addr), n);
		}
	} else {
		// if we wrap, split the operation
		if (start_addr + frame_len > log->spool_size) {
			n2= (int) (log->spool_size - start_addr);
			if (!log_readspool(log, start_addr, buf, n2)
				|| !log_readspool(log, 0, buf+n2, n - n2))
				return false;
		} else {
			if (!log_readspool(log, start_addr, buf, n))
				return false;
		}
	}
	
	// parse header
	if (!log_parse_msg_header(log, buf, &header))
		return false;
	
	// check footer, and initialize msg data/data_len fields.
	if (n == frame_len) {
		if (!log_parse_msg_footer(log, buf+n-8, &footer))
			return false;
		if (!log_load_msg_nodata(log, &header, &footer, msg))
			return false;
		
		// verify message checksum
		switch (header.msg_chk_algo) {
		  case 0:  break; // 0 is "no checksum"
		// TODO: run CRC32 or CRC64 or SHA-1 checks.
		  default: return SET_ERR(log, CCL_EUNSUPPORTED, "Message uses unknown checksum algorithm");
		}
		
		msg->data= msg->buffer + header.data_ofs;
		msg->data_len= (size_t) header.msg_len;
	}
	// else if partial message...
	else {
		// null footer causes footer to be read from log.
		if (!log_load_msg_nodata(log, &header, NULL, msg))
			return false;
		// Only set up ->data if we actually have some of it
		if (buf == msg->buffer && msg->buffer_len > header.data_ofs+1) {
			msg->buffer[msg->buffer_len-1]= '\0';
			msg->data= msg->buffer + header.data_ofs;
			n2= msg->buffer_len - header.data_ofs;
			msg->data_len= (header.msg_len > n2)? (size_t) header.msg_len : n2;
		}
		return SET_ERR(log, CCL_EBUFFERSIZE, "Message buffer smaller than frame_len");
	}
	return true;
}

bool log_write_msg(ccl_log_t *log, ccl_msg_t *msg, struct iovec *iov, int iov_count) {
	// Header is 12 bytes + size_size, which is 4 bytes max in the current implementation.
	// Footer is big enough for padding (max 8), checksum (max 20), size (max 4), frame_cksum (4)
	char buffer[16 + 8+24+4+4]; // header, footer
	char *header_buf= buffer;
	char *footer_buf= buffer+sizeof(buffer); // grows backward
	char *chk_buf, *buf_tmp;
	size_t header_buf_len, footer_buf_len;
	
	size_t msg_len, msg_len2, cksum_len, padding_len, n, tmp;
	int64_t addr= msg->address, frame_len;
	uint32_t encoded_size;
	int i, size_size;
	bool success;
	
	// sanity checks
	assert(iov_count >= 2);
	assert(iov[0].iov_len == 0);
	assert(iov[iov_count-1].iov_len == 0);
	assert((addr & 7) == 0);
	assert(addr >= 0);
	assert(addr < log->spool_size);
	assert((msg->type >> 8) == 0);
	assert(((msg->chk_algo-1) >> 4) == 0);
	assert(((msg->level+3) >> 4) == 0);
	
	switch (msg->chk_algo) {
	case CCL_MSG_CHK_NONE: cksum_len= 0; break;
	case CCL_MSG_CHK_CRC32:
	case CCL_MSG_CHK_CRC64:
	case CCL_MSG_CHK_SHA1:
		return SET_ERR(log, CCL_EUNSUPPORTED, "Unimplemented checksum algorithm");
	default:
		return SET_ERR(log, CCL_EBADPARAM, "Undefined checksum algorithm");
	}
	
	// sum up the message size
	// start at 32 so we can check the whole record size for int overflow
	//  on 32-bit (or less likely, overflow on 64-bit, if bad values in iov_len)
	msg_len= 32+cksum_len;
	for (i= iov_count-2; i; i--) {
		msg_len2= msg_len + iov[i].iov_len;
		if (msg_len2 < msg_len)
			return SET_ERR(log, CCL_EUNSUPPORTED, "Message size exceeds implementation limits");
		msg_len= msg_len2;
	}
	msg_len -= 32; // subtract it back off
	
	// encode the message size, and determine length of encoding
	if ((msg_len >> 32) || !(size_size= encode_size((uint32_t) msg_len, &encoded_size)))
		return SET_ERR(log, CCL_EUNSUPPORTED, "Message size exceeds implementation limits");

	// check vs. max message size of this logfile
	if (msg_len > log->max_message_size)
		return SET_ERR(log, CCL_EMSGSIZE, "Message size exceeds max_message_size of log");

	frame_len= CCL_MESSAGE_FRAME_SIZE(msg_len, size_size);
	msg->frame_len= frame_len;
	if (frame_len > log->spool_size)
		return SET_ERR(log, CCL_EMSGSIZE, "Message size exceeds log spool size");
	
	padding_len= frame_len - 12 - size_size - msg_len - size_size - 4;
	assert(padding_len > 0);
	assert(padding_len <= 8);

	// format header
	* (int64_t*) header_buf = msg->timestamp;
	header_buf[8]= '\x1E';
	header_buf[9]= '\x01';
	header_buf[10]= msg->type;
	header_buf[11]= ((msg->level+3) << 4) | ((msg->chk_algo-1) & 0xF);
	* (int32_t*) (header_buf+12) = htole32(encoded_size);
	header_buf_len= 12 + size_size;
	
	// format footer
	footer_buf_len= 4 + size_size + cksum_len + padding_len;
	* (uint32_t*) (footer_buf - 4) = htole32( CCL_MESSAGE_FRAME_CHECKSUM(addr, msg_len, msg->timestamp) );
	* (uint32_t*) (footer_buf - 8) = htobe32(encoded_size);
	footer_buf -= footer_buf_len;
	// fill padding with NUL bytes
	for (i= 0; i < padding_len; i++)
		footer_buf[i]= '\0';
	// set up buffer pos for writing checksum
	chk_buf= footer_buf + padding_len;
	// checksum of all message data bytes, not including pading
	switch (msg->chk_algo) {
	case CCL_MSG_CHK_NONE: break;
	default:
		return SET_ERR(log, CCL_EUNSUPPORTED, "BUG: unhandled cksum_algo");
	}

	// set up iovecs for header & footer
	iov[0].iov_base= header_buf;
	iov[0].iov_len=  header_buf_len;
	iov[iov_count-1].iov_base= footer_buf;
	iov[iov_count-1].iov_len=  footer_buf_len;
	
	// write it, either via mmap or writev
	if (log->memmap_spool) {
		for (i= 0; i<iov_count; i++) {
			if (addr + iov[i].iov_len <= log->spool_size) {
				memcpy((void*) (log->memmap_spool+addr), iov[i].iov_base, iov[i].iov_len);
				addr+= iov[i].iov_len;
			}
			else {
				n= (size_t) (log->spool_size - addr);
				memcpy((void*) (log->memmap_spool+addr), iov[i].iov_base, n);
				memcpy((void*) log->memmap_spool, ((char*)iov[i].iov_base) + n, iov[i].iov_len - n);
				addr= iov[i].iov_len - n;
			}
		}
	}
	else {
		if (!log_seek(log, log->spool_start + addr))
			return false;
		// If we don't wrap the spool, we can use a single writev().
		if (addr + frame_len <= log->spool_size) {
			if (!log_writev(log, iov, iov_count))
				return false;
		}
		// Else, we have to split the iovec[] into 2 segments.
		else {
			// figure out which iovec we need to split
			n= log->spool_size - addr;
			for (i= 0; i < iov_count; i++) {
				if (n < iov[i].iov_len)
					// split this one.
					break;
				n -= iov[i].iov_len;
			}

			// first half
			tmp= iov[i].iov_len;
			iov[i].iov_len= n;
			success= log_writev(log, iov, i+1);
			iov[i].iov_len= tmp;
			if (!success) return false;

			// second half
			if (!log_seek(log, log->spool_start))
				return false;
			buf_tmp= (char*) iov[i].iov_base;
			iov[i].iov_base= buf_tmp+n;
			iov[i].iov_len -= n;
			success= log_writev(log, iov+i, iov_count-i);
			iov[i].iov_base= buf_tmp;
			iov[i].iov_len= tmp;
			if (!success) return false;
		}
	}
	return true;
}

bool ccl_write_msg(ccl_log_t *log, ccl_msg_t *msg, struct iovec *iov, int iov_count) {
	// access-mode check
	if (!log->writeable)
		return SET_ERR(log, CCL_EREADONLY, "Log is read-only");
	// Type is required
	if (!msg->type)
		return SET_ERR(log, CCL_EBADPARAM, "msg->type must be non-zero");
	
	// Cksum algorithm defaults to setting in log.
	if (!msg->chk_algo)
		msg->chk_algo= log->default_chk_algo;
	
	// Fill in the timestamp with "now()" if not specified by the user
	if (msg->timestamp == 0) {
		msg->timestamp= ccl_timestamp_from_timespec(log, NULL);
		if (msg->timestamp == 0)
			return SET_ERR(log, CCL_ESYSERR, "Can't generate timestamp: $syserr");
	}
	
	// we build a new io vector with room for the prefix, user's vectors, and suffix.
	// (we re-use an iovec which we keep in log->iovec_buf)
	if (log->iovec_buf_count < iov_count+2)
		if (!log_resize_iovec(log, iov_count+2))
			return false;
	memcpy(log->iovec_buf+1, iov, sizeof(*iov) * iov_count);
	log->iovec_buf[0].iov_len= 0;
	log->iovec_buf[iov_count+1].iov_len= 0;

	// Determine next spool address to write.  If log is shared, need to lock, then
	// seek newest, then write, then unock.  If we are sole writer, then just continue
	// where we left off.
	// TODO: add support for shared write-access
	if (log->shared_write)
		return SET_ERR(log, CCL_EUNSUPPORTED, "Shared write is not implemented");
	msg->address= ;
	
	return log_write_msg(log, msg, log->iovec_buf, iov_count+2);
}


/*
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
		suffix[3]= CCL_MESSAGE_META_CHECKSUM(msg->data_len, msg->timestamp, log->msg_start_addr);
		
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
