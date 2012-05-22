#include "config.h"
#include "circulog_internal.h"

static const char* errorTable[]= {
	/* CCL_ESYSERR       */ "%m",
	/* CCL_ELOGSTRUCT    */ "Log object is invalid",
	/* CCL_ELOGOPEN      */ "Failed to open log file: %m",
	/* CCL_ELOGVERSION   */ "Unsupported log file version",
	/* CCL_ELOGINVAL     */ "Invalid log format",
	/* CCL_ELOGREAD      */ "Failed to read log: %m",
	/* CCL_ERESIZERDONLY */ "Cannot resize log opened in read-mode",
	/* CCL_ERESIZECREATE */ "Log resize failed: Unable to create temp log file: %m",
	/* CCL_ERESIZENAME   */ "Log resize failed: Temp log file name too long",
	/* CCL_EGETLOCK      */ "Failed to lock log file.  fcntl: %m",
	/* CCL_EDROPLOCK     */ "Failed to unlock log file. fcntl: %m",
	/* CCL_ERESIZERENAME */ "Failed to rename resized file to log file: %m",
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

inline void endian_swap_32(void *data) {
	((char*)data)[0] ^= ((char*)data)[3];
	((char*)data)[3] ^= ((char*)data)[0];
	((char*)data)[0] ^= ((char*)data)[3];
	((char*)data)[1] ^= ((char*)data)[2];
	((char*)data)[2] ^= ((char*)data)[1];
	((char*)data)[1] ^= ((char*)data)[2];
	//return (uint32_t)(x<<24) | (uint32_t)((x&(uint32_t)0xFF00)<<8) | (uint32_t)((x>>8)&(uint32_t)0xFF00) | (uint32_t)(x>>24);
}
inline void endian_swap_64(void *data) {
	((char*)data)[0] ^= ((char*)data)[7];
	((char*)data)[7] ^= ((char*)data)[0];
	((char*)data)[0] ^= ((char*)data)[7];
	((char*)data)[1] ^= ((char*)data)[6];
	((char*)data)[6] ^= ((char*)data)[1];
	((char*)data)[1] ^= ((char*)data)[6];
	((char*)data)[2] ^= ((char*)data)[5];
	((char*)data)[5] ^= ((char*)data)[2];
	((char*)data)[2] ^= ((char*)data)[5];
	((char*)data)[3] ^= ((char*)data)[4];
	((char*)data)[4] ^= ((char*)data)[3];
	((char*)data)[3] ^= ((char*)data)[4];
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
	
	// check magic number, and determine endianness
	if (header.magic != CCL_HEADER_MAGIC) {
		endian_swap_64(&header.magic);
		if (header.magic == CCL_HEADER_MAGIC) {
			log->wrong_endian= true;
			endian_swap_32(&header.version);
			endian_swap_32(&header.oldest_compat_version);
			endian_swap_64(&header.size);
			endian_swap_64(&header.header_size);
			endian_swap_64(&header.oldest);
			endian_swap_64(&header.newest);
			endian_swap_64(&header.writer_pid);
		}
		else {
			log->last_err= CCL_ELOGINVAL;
			log->last_errno= 0;
			return false;
		}
	}
	
	// version check
	if (header.oldest_compat_version > CCL_CURRENT_VERSION) {
		log->last_err= CCL_ELOGVERSION;
		log->last_errno= 0;
		return false;
	}
	
	// message offsets must be greater than the header length
	if (header.size != fileSize
		|| header.header_size < sizeof(header)
		|| header.header_size > header.oldest
		|| header.header_size > header.newest
	) {
		log->last_err= CCL_ELOGINVAL;
		log->last_errno= 0;
		return false;
	}
	
	log->size= header.size;
	log->header_size= header.header_size;
	log->version= header.version;
	
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
			log->last_err= CCL_ERESIZERDONLY;
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
			log->last_err=   log->last_err;
			log->last_errno= log->last_errno;
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
	newLog.size= logSize;
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
	header.header_size= sizeof(header);
	header.oldest= header.header_size;
	header.newest= header.header_size;
	
	if (!write_rec(newLog.fd, &header, sizeof(header))) {
		log->last_err= CCL_ERESIZECREATE;
		log->last_errno= errno;
		
		unlink(fname);
		ccl_destroy(&newLog);
		return false;
	}
	
	// Now, we iterate over all the messages in the old log
	if (haveOld) {
		
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
	log->version= newLog.version;
	// log->max_message_size remains the same
	log->wrong_endian= newLog.wrong_endian;
	log->dirty= newLog.dirty;
	log->access= newLog.access;
	log->fd= newLog.fd;
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
	return (((int64_t) t->tv_sec) << 16) | CCL_NSEC_TO_16BIT_FRAC(t->tv_nsec);
}

void ccl_split_timestamp(int64_t ts, struct timespec *t_out) {
	t_out->tv_nsec= CCL_16BIT_FRAC_TO_NSEC(ts & 0xFFFFLL);
	t_out->tv_sec=  (time_t) (ts >> 16);
}

int64_t ccl_first_message(ccl_log_t *log) {
	return log->header_size;
}

int64_t ccl_last_message(ccl_log_t *log) {
	return log->header_size;
}

int64_t ccl_next_message(ccl_log_t *log, int64_t prevMsgAddress) {
	return log->header_size;
}

int64_t ccl_message_at_time(ccl_log_t *log, int64_t timestamp) {
	return log->header_size;
}

bool ccl_write_message(ccl_log_t *log, ccl_message_info_t *msg) {
	return false;
}

ccl_message_info_t *ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen) {
	return NULL;
}
