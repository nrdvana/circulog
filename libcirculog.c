#include "config.h"
#include "circulog_internal.h"

static const char* errorTable[]= {
	/* CCL_ESYSERR       */ "%m",
	/* CCL_ELOGSTRUCT    */ "Log object is invalid",
	/* CCL_ELOGOPEN      */ "Failed to open log file: %m",
	/* CCL_ELOGVERSION   */ "Unsupported log file version",
	/* CCL_ELOGINVAL     */ "Invalid log format",
	/* CCL_ELOGREAD      */ "Failed to read log: %m",
	/* CCL_ERDONLY       */ "Log was opened read-only",
	/* CCL_ERESIZECREATE */ "Log resize failed: Unable to create temp log file: %m",
	/* CCL_ERESIZENAME   */ "Log resize failed: Temp log file name too long",
	/* CCL_EGETLOCK      */ "Failed to lock log file.  fcntl: %m",
	/* CCL_EDROPLOCK     */ "Failed to unlock log file. fcntl: %m",
	/* CCL_ERESIZERENAME */ "Failed to rename resized file to log file: %m",
	/* CCL_EMSGPARAM     */ "Invalid message_info parameters",
	/* CCL_ELOGWRITE     */ "Failed to write log: %m"
};

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

void ccl_init(ccl_log_t *log, int struct_size) {
	memset(log, 0, struct_size);
	log->sizeof_struct= struct_size;
	log->fd= -1;
	log->size=                CCL_DEFAULT_LOG_SIZE;
	log->block_size=          CCL_DEFAULT_BLOCK_SIZE;
	log->max_message_size=    CCL_DEFAULT_MAX_MESSAGE_SIZE;
	log->timestamp_precision= CCL_DEFAULT_TIMESTAMP_PRECISION;
}

bool ccl_destroy(ccl_log_t *log) {
	bool err= false;
	if (log->memmap) {
		err= err || munmap(log->memmap, (size_t) log->size);
		log->memmap= NULL;
	}
	if (log->fd >= 0) {
		err= err || close(log->fd);
		log->fd= -1;
	}
	return !err;
}

const char* ccl_err_text(ccl_log_t *log, char* buf, int bufLen) {
	const char* errFmt, *pct_m;
	int cnt;
	
	if (bufLen < 2) return "";
	if (log->last_err < 0 || log->last_err >= sizeof(errorTable)/sizeof(*errorTable))
		return "[invalid error number]";
	errFmt= errorTable[log->last_err];
	
	// Here, we manually perform one substitution of "%m", and deal with all the
	//   shitty APIs of strerror, strerror_r, and glibc strerror_r.
	if ((pct_m= strstr(errFmt, "%m"))) {
		cnt= snprintf(buf, bufLen, "%.*s", pct_m - errFmt, errFmt);
		if (cnt < bufLen-1) {
			// append the system error string
			#ifdef POSIX_STRERROR
			strerror_r(log->last_errno, buf, bufLen-cnt);
			if (buf[cnt] == '\0')
				cnt+= snprintf(buf+cnt, bufLen-cnt, "[strerror failed]");
			#else
			const char *sysErrMsg= strerror_r(log->last_errno, buf+cnt, bufLen-cnt);
			if (buf[cnt] == '\0')
				cnt+= snprintf(buf+cnt, bufLen-cnt, "%s", sysErrMsg);
			#endif
			
			// then append the rest of the format-string
			if (cnt < bufLen-1)
				snprintf(buf+cnt, bufLen-cnt, "%s", pct_m+2);
		}
	}
	else {
		snprintf(buf, bufLen, "%s", errFmt);
	}
	return buf;
}

static bool read_rec(int fd, void* record, int recordSize) {
	int count= 0;
	int got;
	while (count < recordSize) {
		got= read(fd, ((char*)record)+count, recordSize-count);
		if (got > 0)
			count+= got;
		else if (got < 0 && errno != EINTR) {
			return false;
		} else {
			errno= EPROTO;
			return false;
		}
	}
	return true;
}

static bool write_rec(int fd, const void *record, int32_t recordSize) {
	int count= 0;
	int wrote;
	while (count < recordSize) {
		wrote= write(fd, ((char*)record)+count, recordSize-count);
		if (wrote > 0)
			count+= wrote;
		else if (wrote < 0 && errno != EINTR) {
			return false;
		} else {
			errno= EPROTO; // not quite sensible, but this should never happen anyway
			return false;
		}
	}
	return true;
}

static bool lock_log(ccl_log_t *log) {
	struct flock lock;
	int ret;
	
	memset(&lock, 0, sizeof(lock));
	lock.l_type= F_WRLCK;
	lock.l_whence= SEEK_SET;
	lock.l_start= 0;
	lock.l_len= sizeof(ccl_log_header_t);
	
	if (log->access == CCL_SHARE) {
		// TODO: this is cheesy, but works for now.  Think up a better interface for write timeouts.
		alarm(3);
		ret= fcntl(log->fd, F_SETLKW, &lock);
		alarm(0);
	} else {
		ret= fcntl(log->fd, F_SETLK, &lock);
	}
	if (ret < 0) {
		log->last_err= CCL_EGETLOCK;
		log->last_errno= errno;
		return false;
	}
	return true;
}

static bool unlock_log(ccl_log_t *log) {
	struct flock lock;
	int ret;
	
	memset(&lock, 0, sizeof(lock));
	lock.l_type= F_UNLCK;
	lock.l_whence= SEEK_SET;
	lock.l_start= 0;
	lock.l_len= sizeof(ccl_log_header_t);
	
	ret= fcntl(log->fd, F_SETLK, &lock);
	if (ret < 0) {
		log->last_err= CCL_EDROPLOCK;
		log->last_errno= errno;
		return false;
	}
	return true;
}

inline int coerce_block_size(int64_t sz) {
	// 16 is the smallest possible block size, since every block contains a int64
	// Block size of 16 is ridiculous, but useful for library validation
	if (sz < 16) return CCL_DEFAULT_BLOCK_SIZE;
	
	// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
	sz--;
	sz |= sz >> 1;
	sz |= sz >> 2;
	sz |= sz >> 4;
	sz |= sz >> 8;
	sz |= sz >> 16;
	sz++;
	return sz;
}

inline int coerce_log_size(int64_t sz, int64_t block_size) {
	// round up to the next multiple of block_size
	return (sz + block_size - 1) & ~(block_size-1);
}

bool ccl_open(ccl_log_t *log, const char *path) {
	off_t fileSize;
	ccl_log_header_t header;
	
	if (!log || log->fd != -1 || (
		log->sizeof_struct != sizeof(ccl_log_t)
		/* extend this with other valid sizes on new versions of the struct */
		))
	{
		log->last_err= CCL_ELOGSTRUCT;
		log->last_errno= 0;
		return false;
	}
	
	// open the file
	log->fd= open(path, log->access > CCL_READ? O_RDWR : O_RDONLY);
	if (log->fd < 0) {
		log->last_err= CCL_ELOGOPEN;
		log->last_errno= errno;
		return false;
	}
	
	// now find the length of the file
	fileSize= lseek(log->fd, 0, SEEK_END);
	if (fileSize == (off_t)-1 || lseek(log->fd, 0, SEEK_SET) == (off_t)-1 ) {
		log->last_err= CCL_ELOGOPEN;
		log->last_errno= errno;
		return false;
	}
	log->file_pos= 0;
	
	// we need at least sizeof(header)
	if (fileSize < sizeof(ccl_log_header_t)) {
		log->last_err= CCL_ELOGINVAL;
		log->last_errno= 0;
		return false;
	}
	
	// read it
	if (!read_rec(log->fd, &header, sizeof(header))) {
		log->last_err= CCL_ELOGREAD;
		log->last_errno= errno;
		return false;
	}
	log->file_pos+= sizeof(header);
	
	// check magic number, and determine endianness
	if (header.magic != le64toh(CCL_HEADER_MAGIC)) {
		//if (header.magic != endian_swap_64(CCL_HEADER_MAGIC)) {
			log->last_err= CCL_ELOGINVAL;
			log->last_errno= 0;
			return false;
		//}
		//log->wrong_endian= true;
	}
	
	log->version=     le32toh(header.version);
	log->size=        le64toh(header.size);
	log->header_size= le64toh(header.header_size);
	log->block_size=  le32toh(header.block_size);
	log->timestamp_precision= le32toh(header.timestamp_precision);
	
	// version check
	if (le32toh(header.oldest_compat_version) > CCL_CURRENT_VERSION) {
		log->last_err= CCL_ELOGVERSION;
		log->last_errno= 0;
		return false;
	}
	
	// recorded size must match actual file size
	// recorded header_size must be at least as big as our struct
	// block_size must be a power of 2, and size must be a multiple of block_size
	if (!(
		log->size == fileSize
		&& coerce_block_size(log->block_size) == log->block_size
		&& coerce_log_size(log->size, log->block_size) == log->size
		&& log->header_size >= sizeof(header)
	)) {
		log->last_err= CCL_ELOGINVAL;
		log->last_errno= 0;
		return false;
	}
	
	// Lock it for writing, if write-exclusive mode.
	// In shared-write mode, we lock on each write operation.
	// In read-only mode we make no locks at all.
	if (log->access > CCL_WRITE) {
		if (!lock_log(log))
			return false;
		// check if the previous writer died unexpectedly
		//log->dirty= header.writer_pid != 0;
	}
	
	return true;
}

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
/*
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
*/
inline int encode_size(uint64_t *encoded, uint64_t value) {
	if (value >> 7) {
		if (value >> 14) {
			if (value >> 29) {
				if (value > 60)
					return 0; // larger than 60 bit isn't supported (though could theoretically exist)
				*encoded= (value << 4)+7;
				return 8;
			}
			*encoded= (value << 3)+3;
			return 4;
		}
		*encoded= (value << 2)+1;
		return 2;
	}
	*encoded= (value << 1);
	return 1;
}

inline int decode_size(uint64_t *value, uint64_t encoded) {
	if (encoded & 1) {
		if (encoded & 2) {
			if (encoded & 4) {
				if (encoded & 8)
					return 0; // larger than 61 bit isn't supported (though could theoretically exist)
				*value= encoded >> 4;
				return 8;
			}
			*value= (encoded & 0xFFFFFFFF) >> 3; 
			return 4;
		}
		*value= (encoded & 0xFFFF) >> 2;
		return 2;
	}
	*value= (encoded & 0xFF) >> 1;
	return 1;
}

bool buffered_write(ccl_log_t *log, char *data, int count, bool flush) {
	int n;
	int64_t block_avail= ((log->file_pos + log->buffer_pos) & (log->block_size - 1)) - 8;
	char* buf= log->buffer;
	int buf_avail= log->buffer_size - log->buffer_pos;
	bool commit= false, done= false;
	while (!done) {
		assert((log->file_pos & 7) == 0);
		assert(block_avail >= 0);
		assert(buf_avail >= 0);
		
		// buffer full, need to flush
		if (buf_avail == 0)
			commit= true;
		// time to write block-end-marker?
		else if (block_avail == 0) {
			// everything is 8-aligned, so if we have any buffer available, we have 8 bytes.
			assert(buf_avail >= 8);
			
			*(int64_t*)(log->buffer+log->buffer_pos)= log->msg_start_addr;
			log->buffer_pos+= 8;
			buf_avail-= 8;
			block_avail= log->block_size - 8;
			// if we're at EOF, we need to flush the buffer
			if (log->file_pos + log->buffer_pos == log->size)
				commit= true;
		}
		// more data to add?
		else if (count) {
			// n = min( count, buf_avail, block_avail )
			n= (buf_avail < block_avail)? buf_avail : (int)block_avail;
			if (count < n)
				n= count;
			
			assert(n > 0);
			// Optimization: if there's a bunch of data to write, and we have
			//  nothing buffered, just write directly from 'data'.
			if (log->buffer_pos == 0 && n > log->buffer_size) {
				buf= data;
				// but, must still be a multiple of 8.
				n= n & ~0x7;
				commit= true;
			}
			else {
				memcpy(log->buffer+log->buffer_pos, data, n);
			}
			log->buffer_pos+= n;
			buf_avail-= n;
			block_avail-= n;
			data+= n;
			count-= n;
		}
		// else we're done
		else {
			// is this the end of a mesage?
			if (flush && log->buffer_pos > 0)
				commit= true;
			done= true;
		}
		
		if (commit) {
			commit= false;
			// Write the buffer if it is full or we're at EOF or 'flush' was requested
			// Incedentally, all those cases require there to be a multiple of 8 bytes in the buffer.
			assert((log->buffer_pos & 7) == 0);
			if (!write_rec(log->fd, buf, log->buffer_pos)) {
				log->last_err= CCL_ELOGWRITE;
				log->last_errno= errno;
				// if we were trying our direct-from-data optimization, we need to clean up buffer_pos
				if (buf != log->buffer)
					log->buffer_pos= 0;
				return false;
			}
			buf= log->buffer; // restore buf pointer (might have been switched to 'data')
			log->file_pos += log->buffer_pos;
			log->buffer_pos= 0;
			buf_avail= log->buffer_size;
			// wrap at EOF
			if (log->file_pos >= log->size) {
				assert(log->file_pos == log->size);
				log->file_pos= log->header_size;
				block_avail= (log->file_pos & (log->block_size - 1)) - 8;
			}
		}
	}
	return true;
}

bool ccl_write_message(ccl_log_t *log, ccl_message_info_t *msg) {
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
	
	/*
	 * We now have asserted the following conditions:
	 * If we are writing a new message:
	 *   - 0 == msg->data_ofs == log->msg_ofs == log->msg_len < msg->msg_len
	 *   - 0 < msg->data_len <= msg->msglen <= max_message_size
	 *   - log->file_pos is a multiple of 8, and is in a valid position (where we assume the end of the previous message is)
	 * If we are continuing a message:
	 *   - 0 < msg->data_ofs == log->msg_ofs < log->msg_len == msg->msg_len
	 *   - log->file_pos is in a valid position (which we assume is the middle of the previous message's data)
	 */
	
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
}

ccl_message_info_t *ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen) {
	return NULL;
}
