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
	log->max_message_size= CCL_DEFAULT_MAX_MESSAGE_SIZE;
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

int coerce_block_size(int64_t sz) {
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

int coerce_log_size(int64_t sz, int64_t block_size) {
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
	
	log->size=        le64toh(header.size);
	log->header_size= le64toh(header.header_size);
	log->block_size=  le64toh(header.block_size);
	log->version=     le32toh(header.version);
	
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

bool ccl_resize(ccl_log_t *log, const char *path, int64_t logSize, bool create, bool force) {
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
	newLog.size= coerce_log_size(logSize, newLog.block_size);
	newLog.header_size= sizeof(header);
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
	log->wrong_endian= newLog.wrong_endian;
	log->dirty= newLog.dirty;
	log->access= newLog.access;
	log->fd= newLog.fd;
	log->file_pos= newLog.file_pos;
	log->memmap= newLog.memmap;
	// don't touch error codes
	
	// We also don't ccl_destroy(newLog) because we just transferred or freed all its allocated parts.
	
	// All done!
	return true;
}

int64_t ccl_get_timestamp(struct timespec *t) {
	#ifdef _POSIX_TIMERS
	struct timespec t2;
	if (!t) {
		t= &t2;
		if (clock_gettime(CLOCK_REALTIME, &t2) < 0)
			return 0LL;
	}
	#else
	if (!t) return ((int64_t) time(NULL)) << 16;
	#endif
	return (((int64_t) t->tv_sec) << 16) + CCL_NSEC_TO_16BIT_FRAC(t->tv_nsec);
}

void ccl_split_timestamp(int64_t ts, struct timespec *t_out) {
	t_out->tv_nsec= CCL_16BIT_FRAC_TO_NSEC(ts & 0xFFFFLL);
	t_out->tv_sec=  (time_t) (ts >> 16);
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

bool ccl_write_message(ccl_log_t *log, ccl_message_info_t *msg) {
	int64_t addr, msg_start_addr, next_block, msg_end;
	int msg_data_pos, size_bytes, avail, count;
	uint64_t encoded_size;
	bool wrote_ts, wrote_size, success, done;
	uint8_t* bufpos;
	
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
	if (!(log->file_pos >= log->header_size
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
	
	// make sure we have a write-buffer
	if (!log->buffer) {
		if (!log->buffer_size)
			log->buffer_size= 8*1024;
		if (!(log->buffer= malloc(log->buffer_size))) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
	}
	
	// Fill in the timestamp with "now()" if not specified by the user
	if (msg->timestamp == 0) {
		msg->timestamp= ccl_get_timestamp(NULL);
		if (msg->timestamp == 0) {
			log->last_err= CCL_ESYSERR;
			log->last_errno= errno;
			return false;
		}
	}
	
	if (log->access == CCL_SHARE) {
		// not supported yet
		log->last_err= CCL_ESYSERR;
		log->last_errno= 0;
		return false;
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
	addr= log->file_pos;
	msg_start_addr= msg->data_ofs == 0? addr : log->msg_start_addr;
	next_block= ((addr + log->block_size - 1) & ~((int64_t)log->block_size-1));
	msg_data_pos= 0;
	wrote_ts= msg->data_ofs != 0;
	wrote_size= msg->data_ofs != 0;
	size_bytes= encode_size(&encoded_size, msg->msg_len);
	assert((log->size & 7) == 0);
	success= true;
	done= false;
	while (!done) {
		bufpos= (uint8_t*) log->buffer;
		do { /* fill buffer as much as possible */
			// Step 1: loop at the end of the log
			assert(addr <= next_block-8);
			if (addr >= log->size) {
				assert(addr == log->size);
				if (lseek(log->fd, log->header_size, SEEK_SET) < 0) {
					success= false;
					break;
				}
				if (msg_start_addr == addr)
					msg_start_addr= log->header_size;
				addr= log->header_size;
				next_block= ((addr + log->block_size - 1) & ~((int64_t)log->block_size-1));
				if (bufpos != log->buffer)
					break; // done flling buffer, since we will have to do another 'write' anyway
			}
			
			avail= log->buffer_size - (bufpos - (uint8_t*) log->buffer);
			
			// Step 2: write the block's current-message-addr if we're at the end of the block
			assert(addr <= next_block-8);
			if (addr == next_block-8) {
				if (avail < 8)
					break; // no room for the block-address, so we'll do it next time around
				// append message_start_addr to buffer
				*((int64_t*)(bufpos))= htole64(msg_start_addr);
				bufpos+= 8;
				addr+= 8;
				avail-= 8;
				next_block+= log->block_size;
			}
			
			// Step 3: we're in a safe state to start writing bytes of the message
			// Figure how many continuous bytes we can write, and constrain 'avail'
			assert(addr <= next_block-8);
			if (next_block - 8 - addr < avail)
				avail= (int)(next_block - 8 - addr);
			if (log->size - addr < avail)
				avail= (int)(log->size - addr);
			
			// If we're out of space here, it's because of a full buffer or EOF.
			// Either requires us to flush the buffer.
			if (avail == 0)
				break;
			
			// Step 4: write the timestamp, if this is the start of a message and we haven't written it yet
			assert(addr <= next_block-8);
			if (!wrote_ts) {
				if (avail < 8)
					break; // we have to stop here, until we can get the whole timestamp written
				assert((addr & 7) == 0);
				*(int64_t*)(bufpos)= htole64(msg->timestamp);
				bufpos+= 8;
				addr+= 8;
				avail-= 8;
				wrote_ts= true;
				if (avail == 0) continue; // go back and check for EOF and end-of-block
			}
			
			// Step 5: write the message size as a byte-encoding similar to UTF-8
			//   We have some space available, but if the buffer is too full to do
			//   it in one shot, we break out of the loop to flush it and start over.
			assert(avail > 0);
			if (!wrote_size) {
				assert((addr & 7) == 0);
				// really, this should never happen, since we just started the message and the buffer should be mostly empty.
				// but, some day we might try to buffer multiple messages per write
				if (avail < 8)
					break;
				*((int64_t*)bufpos)= htole64(encoded_size);
				bufpos += size_bytes;
				addr += size_bytes;
				avail -= size_bytes;
				wrote_size= true;
				if (avail == 0) continue; // go back and check for EOF and end-of-block
			}
			
			// Step 6: write some or all of the actual data
			//   We keep track of how much we've written in the 'msg_data_pos' var.
			assert(avail > 0);
			if (msg_data_pos < msg->data_len) {
				count= msg->data_len - msg_data_pos;
				if (avail < count) count= avail;
				memcpy(bufpos, ((char*)msg->data)+msg_data_pos, count);
				bufpos += count;
				addr += count;
				avail -= count;
				msg_data_pos+= count;
				if (avail == 0) continue;
			}
			
			// Step 7: If we have the end of the data, we write some padding and the end-count
			//  If we've exhausted the supplied data but it isn't the msg_len, then the caller
			//    will call us again with more data so we're done for now.
			assert(avail > 0);
			if (msg->data_ofs + msg->data_len == msg->msg_len) {
				// round up to the next boundary
				msg_end= (addr+7LL) & ~7LL;
				count= msg_end - addr;
				if (avail < count)
					// go get a fresh buffer
					break;
				
				// Is the space between the end of the string large enough to accomodate the count?
				if (count >= size_bytes) {
					encoded_size= htobe64(encoded_size);
					memcpy(bufpos, ((char*)&encoded_size)+8-count, count);
					addr  += count;
					bufpos+= count;
					avail -= count;
					// done
				}
				else {
					// else we fill up to the boundary with 0 and the count goes in its own 8 bytes
					if (count > 0) {
						memset(bufpos, 0, count);
						addr  += count;
						bufpos+= count;
						avail -= count;
						if (avail == 0) continue;  // might be a block boundary or EOF
					}
					// count gets its own 8 bytes, if we have room.
					assert((addr & 7) == 0);
					if (avail < 8) break; // full buffer
					
					// the encoded_size is padded with 0, so it works out.
					*((int64_t*)bufpos)= htobe64(encoded_size);
					addr  += 8;
					bufpos+= 8;
					avail -= 8;
					// done
				}
			}
			
			done= true;
		} while (false); // all looping is performed with 'continue'
		
		// Now, we write the buffer to the file.
		if (success) {
			count= bufpos - (uint8_t*) log->buffer;
			assert(count > 0);
			success= write_rec(log->fd, log->buffer, count);
		}
		if (!success)
			done= true;
	}
	if (!success) {
		// write failed, (or seek failed)
		log->last_err= CCL_ELOGWRITE;
		log->last_errno= errno;
		// and we try to restore everything to the exact state it was before the call
		lseek(log->fd, log->file_pos, SEEK_SET);
	}
	else if (msg->data_ofs + msg->data_len == msg->msg_len) {
		// message is complete
		log->file_pos= addr;
		log->msg_start_addr= 0;
		log->msg_pos= 0;
		log->msg_len= 0;
	}
	else {
		// to be continued by another call
		if (log->msg_pos > 0)
			log->msg_start_addr= log->file_pos;
		log->file_pos= addr;
		log->msg_pos += msg->data_len;
		log->msg_len= msg->msg_len;
	}
	return success;
}

ccl_message_info_t *ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen) {
	return NULL;
}
