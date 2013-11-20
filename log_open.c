#include "config.h"
#include "libcirculog.h"

#define INIT_FIELD_FROM_HEADER(fieldname) \
		(((setting= ccl_config_get(log->config, #fieldname, strlen(#fieldname))) \
		&& ccl_log_set_field(log, CCL_LOG_FIELD_OFFSET(fieldname), setting+strlen(#fieldname)+1, NULL)) \
		|| SET_ERR(log, CCL_ELOGINVAL, "invalid " #fieldname))
#define INIT_OPT_FIELD_FROM_HEADER(fieldname) \
		(!(setting= ccl_config_get(log->config, #fieldname, strlen(#fieldname))) \
		|| ccl_log_set_field(log, CCL_LOG_FIELD_OFFSET(fieldname), setting+strlen(#fieldname)+1, NULL) \
		|| SET_ERR(log, CCL_ELOGINVAL, "invalid " #fieldname))

bool ccl_log_load_header(ccl_log_t *log) {
	ccl_log_header_t header;
	int64_t file_size;
	int settings_len;
	unsigned char sha1_chk[20];
	const char *setting;
	
	// Read static header fields
	if (!log->memmap) {
		file_size= lseek(log->fd, 0, SEEK_END);
		if (file_size == (off_t)-1 || lseek(log->fd, 0, SEEK_SET) == (off_t)-1)
			return SET_ERR(log, CCL_ESYSERR, "Can't seek to end of $logfile: $syserr");
		if (!ccl_log_read(log, &header, sizeof(header)))
			return SET_ERR(log, CCL_ESYSERR, "Can't read header: $syserr");
	} else {
		file_size= log->memmap_size;
		if (log->memmap_size < sizeof(header))
			return SET_ERR(log, CCL_ELOGINVAL, "Memory buffer is smaller than header");
		memcpy(&header, (char*) log->memmap, sizeof(header));
	}
	
	// Check magic and version
	if (le64toh(header.magic) != CCL_HEADER_MAGIC)
		return SET_ERR(log, CCL_ELOGINVAL, "Bad magic number");
	if (le16toh(header.oldest_compat_version) > CCL_CURRENT_VERSION)
		return SET_ERR(log, CCL_EUNSUPPORTED, "Log version is too new for this library");
	
	// Load name=value configuration block
	settings_len= le32toh(header.config_len);
	if (!ccl_config_resize(&log->config, sizeof(ccl_config_t) + settings_len))
		return SET_ERR(log, CCL_ESYSERR, "malloc failed");
	log->config->settings_len= settings_len;
	
	if (!log->memmap) {
		if (!ccl_log_read(log, log->config->settings, settings_len))
			return SET_ERR(log, CCL_ESYSERR, "Can't read header: $syserr");
	} else {
		if (log->memmap_size < sizeof(header) + settings_len)
			return SET_ERR(log, CCL_ELOGINVAL, "Memory buffer is smaller than header");
		memcpy(log->config->settings, (char*) log->memmap + sizeof(header), settings_len);
	}
	
	// validate SHA1 of header
	SHA1((unsigned char*) log->config->settings, settings_len, sha1_chk);
	if (memcmp(sha1_chk, header.config_sha1, sizeof(sha1_chk)))
		return SET_ERR(log, CCL_ELOGINVAL, "Header checksum mismatch");
	
	log->version= le16toh(header.version);
	log->config_time= le64toh(header.config_time);

	// Load all mandatory fields from config settings
	if (!INIT_FIELD_FROM_HEADER(spool_start)
		|| !INIT_FIELD_FROM_HEADER(spool_size)
		|| !INIT_FIELD_FROM_HEADER(timestamp_precision)
		|| !INIT_FIELD_FROM_HEADER(timestamp_epoch))
		return false;
	
	if (log->spool_start + log->spool_size > file_size)
		return SET_ERR(log, CCL_ELOGINVAL, "Message spool exceeds file_size (truncated file?)");
	
	// Load optional fields from config settings
	if (!INIT_OPT_FIELD_FROM_HEADER(max_message_size)
		|| !INIT_OPT_FIELD_FROM_HEADER(default_chk_algo)
		|| !INIT_OPT_FIELD_FROM_HEADER(name))
		return false;

	log->memmap_spool= log->memmap? log->memmap + log->spool_start : NULL;
	
	return true;
}

bool ccl_log_write_header(ccl_log_t *log) {
	char *dest;
	ccl_log_header_t header;
	struct iovec iov[2];
	
	assert(log->config != NULL);
	
	if (log->config->settings_len > log->spool_start
		|| sizeof(header) + log->config->settings_len > log->spool_start)
		return SET_ERR(log, CCL_ELOGINVAL, "log header overlaps message spool");
	
	// Build new header
	header.magic=       htole64(CCL_HEADER_MAGIC);
	header.version=     htole16(CCL_CURRENT_VERSION);
	header.oldest_compat_version= htole16(0);
	header.config_len=  htole32(log->config->settings_len);
	header.config_time= htole64(log->config_time);
	
	// run sha1 on config
	SHA1((unsigned char*) log->config->settings, log->config->settings_len, (unsigned char*) header.config_sha1);
	
	if (log->memmap) {
		dest= (char*) log->memmap;
		memcpy(dest, &header, sizeof(header));
		dest += sizeof(header);
		memcpy(dest, log->config->settings, log->config->settings_len);
		dest += log->config->settings_len;
		memset(dest, 0, log->spool_start - (dest - log->memmap));
		return true;
	}
	else {
		iov[0].iov_base= &header;
		iov[0].iov_len=  sizeof(header);
		iov[1].iov_base= log->config->settings;
		iov[1].iov_len=  log->config->settings_len;
		return ccl_log_seek(log, 0) && ccl_log_writev(log, iov, 2);
	}
}

#define ROUND_MULTIPLE(x, multiple_of) ( (((x)-1) | ((multiple_of)-1)) + 1 )

bool ccl_log_create_log(ccl_log_t *log) {
	long pagesize;
	off_t file_size= 0, total_size;
	char buffer[20];
	size_t n;
	bool use_file_size= false;
	
	pagesize= sysconf(_SC_PAGESIZE);
	if (pagesize < 4096) pagesize= 4096;

	// requesting default size?
	if (log->spool_size == 0) {
		// determine size of file
		if (log->fd >= 0) {
			file_size= lseek(log->fd, 0, SEEK_END);
			if (file_size == (off_t)-1)
				return SET_ERR(log, CCL_ESYSERR, "Can't seek to end of $logfile: $syserr");
			if (file_size >= pagesize*2) {
				use_file_size= true;
				log->spool_size= file_size;
			} else {
				log->spool_size= CCL_DEFAULT_SPOOL_SIZE;
			}
		} else {
			file_size= log->memmap_size;
			log->spool_size= file_size;
			use_file_size= true;
		}
	}
	
	// Add log fields to the config variables
	if (!ccl_log_store_fields_in_config(log))
		return false;

	// Spool starts after header and dynamic fields (config)
	// Then we leave some room for the value we're about to insert, plus some room for later.
	// and then, round up to next multiple of page size
	log->spool_start= ROUND_MULTIPLE(
		sizeof(ccl_log_header_t) + log->config->settings_len + 256,
		pagesize
	);
	n= sprintf(buffer, "%lld", (long long) log->spool_start);
	if (!ccl_config_set(&log->config, "spool_start", 11, buffer, n))
		return false;
	
	// If we're fitting within the existing file_size constraint, adjust spool_size
	if (use_file_size) {
		// round down to multiple of 8
		if ((int64_t) file_size - (int64_t) log->spool_start < pagesize)
			return SET_ERR(log, CCL_EBADPARAM, "spool_size too small when using default file length");
		log->spool_size= (file_size - log->spool_start) >> 3 << 3;
		// update config
		n= sprintf(buffer, "%lld", (long long) log->spool_size);
		if (!ccl_config_set(&log->config, "spool_size", 10, buffer, n))
			return false; // this should never fail, since it can only shrink...
		
		// Now zero the spool
		if (log->memmap) {
			memset((char*) log->memmap + log->spool_start, 0, log->memmap_size - log->spool_start);
		} else {
			// zero the file by truncating it, then set the file length back to original size
			if (ftruncate(log->fd, 0) < 0
				|| ftruncate(log->fd, file_size) < 0)
				return SET_ERR(log, CCL_ESYSERR, "Failed to resize logfile");
		}
	}
	else {
		total_size= log->spool_start + log->spool_size;
		// overflow/wrap check
		if (total_size < log->spool_start || total_size < log->spool_size)
			return SET_ERR(log, CCL_ESIZELIMIT, "Spool size exceeds implementation limits");
		
		// if using a file, truncate file to correct length
		if (log->fd >= 0) {
			// if its memmapped, unmap it (else our mmap might give us SIGBUS)
			if (log->memmap) {
				if (munmap((void*)log->memmap, log->memmap_size) != 0)
					return SET_ERR(log, CCL_ESYSERR, "Can't unmap previous file");
				log->memmap= NULL;
				log->memmap_spool= NULL;
				log->memmap_size= 0;
			}
			// zero the file by truncating it, then set the file length
			if (ftruncate(log->fd, 0) < 0
				|| ftruncate(log->fd, total_size) < 0)
				return SET_ERR(log, CCL_ESYSERR, "Failed to resize logfile");
		}
		// else if using shared-mem, make sure total size fits within memmap
		else {
			if (log->spool_start >= log->memmap_size)
				return SET_ERR(log, CCL_ESIZELIMIT, "header config exceeds memory buffer size");
			if (total_size > log->memmap_size)
				return SET_ERR(log, CCL_ESIZELIMIT, "message spool exceeds memory buffer size");
			// and zero the spool
			memset((char*) log->memmap + log->spool_start, 0, log->memmap_size - log->spool_start);
		}
	}
	
	// Now write header
	if (!ccl_log_write_header(log))
		return false;
	return true;
}

/** ccl_open_file - open (and optionally create) a log
 * 
 * Opens the specified path and verifies that it is a valid log file.
 *
 * Access modes are CCL_READ, CCL_WRITE, CCL_SHARE (not supported yet).
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
bool ccl_open_file(ccl_log_t *log, const char *path, int access) {
	bool create;
	off_t file_size;
	ccl_log_t tmp;
	int fd;
	int64_t magic;
	bool success= false;
	
	if (!log) return false;
	
	if (ccl_log_is_open(log))
		return SET_ERR(log, CCL_ELOGSTATE, "Log object is already open");
	
	create= (access & CCL_CREATE);
	
	fd= open(path, (create? O_CREAT:0) | (log->writeable? O_RDWR : O_RDONLY), 0666);
	if (fd < 0)
		return SET_ERR(log, CCL_EOPEN, "Unable to open $logfile: $syserr");
	
	// find the length of the file
	file_size= lseek(fd, 0, SEEK_END);
	if (file_size == (off_t)-1) {
		close(fd);
		return SET_ERR(log, CCL_ESEEK, "Can't seek to end of $logfile: $syserr");
	}
	
	// perform open on tmp log object, to prevent log config from being lost
	// if there is a partial load.  Also makes easier cleanup, by using ccl_destroy
	ccl_init(&tmp, sizeof(tmp));
	tmp.fd= fd;
	tmp.writeable= (access & CCL_WRITE);

	if (!ccl_log_clone_config(log, &tmp)) {
		ccl_destroy(&tmp); // also closes fd
		return false;
	}
	
	// Lock it for writing, if write-exclusive mode.
	// In shared-write mode, we lock on each write operation.
	// In read-only mode we make no locks at all.
	if (tmp.writeable)
		if (!ccl_log_lock(&tmp)) {
			ccl_destroy(&tmp);
			return false;
		}
	
	// If file size is zero, and create was specified, initialize the log
	if (file_size == 0 && create) {
		if (ccl_log_create_log(&tmp))
			success= true;
	}
	// or, if file size > 0, just try loading it.
	else if (file_size > 0) {
		if (ccl_log_load_header(&tmp))
			success= true;
		else {
			// Failed to load.  If the first 8 bytes of the file are 0,
			// and create is true, then assume we should overwrite the file.
			success= create
				&& ccl_log_seek(&tmp, 0)
				&& ccl_log_read(&tmp, &magic, sizeof(magic))
				&& magic == 0
				&& ccl_log_clone_config(log, &tmp)  // re-init settings that load_header might have overwritten
				&& ccl_log_create_log(&tmp);
		}
	}
	
	if (success) {
		// Destroy log, and replace with tmp.  tmp does not get destroyed
		//   because it's been moved.
		ccl_destroy(log);
		*log= tmp;
		
		// mmap, if requested
		if (access & CCL_MMAP) {
			log->memmap_size= log->spool_start + log->spool_size;
			log->memmap= (volatile char*) mmap(NULL, log->memmap_size,
				(log->writeable? PROT_READ|PROT_WRITE : PROT_READ),
				MAP_SHARED, log->fd, 0);
			if (log->memmap == NULL) { // stupid, but I've seen this happen before...
				log->memmap= (volatile char*) mmap(NULL, log->memmap_size,
					(tmp.writeable? PROT_READ|PROT_WRITE : PROT_READ),
					MAP_SHARED, log->fd, 0);
				munmap(NULL, log->memmap_size);
			}
			// revert to non-memmap if it didn't work
			// TODO: generate warning, but need to define API for warnings
			if (log->memmap == MAP_FAILED) {
				log->memmap= NULL;
				log->memmap_size= 0;
			}
		}
		return true;
	} else {
		// Destroy tmp, but copy error msg first
		ccl_log_clone_err(&tmp, log);
		ccl_destroy(&tmp);
		return false;
	}
}

bool ccl_open_shm(ccl_log_t *log, volatile void *shm, size_t shm_size, int access) {
	ccl_log_t tmp;
	bool create, success= false;
	
	if (!log) return false;
	
	if (ccl_log_is_open(log))
		return SET_ERR(log, CCL_ELOGSTATE, "Log object is already open");
	
	create= (access & CCL_CREATE);
	
	// perform open on tmp log object, to prevent log config from being lost
	// if there is a partial load.  Also makes easier cleanup, by using ccl_destroy
	ccl_init(&tmp, sizeof(tmp));
	tmp.writeable= (access & CCL_WRITE);

	if (!ccl_log_clone_config(log, &tmp)) {
		ccl_destroy(&tmp);
		return false;
	}

	tmp.memmap= (volatile char*) shm;
	tmp.memmap_size= shm_size;
	
	if (ccl_log_load_header(&tmp))
		success= true;
	else {
		// Failed to load.  If the first 8 bytes of the memory are 0,
		// and create is true, then assume we should overwrite the file.
		success= create
			&& shm_size > 8
			&& * (int64_t*) shm == 0
			&& ccl_log_clone_config(log, &tmp)  // re-init settings that load_header might have overwritten
			&& ccl_log_create_log(&tmp);
	}
	
	if (success) {
		// Destroy log, and replace with tmp.  tmp does not get destroyed
		//   because it's been moved.
		ccl_destroy(log);
		*log= tmp;
		return true;
	} else {
		// Destroy tmp, but copy error msg first
		ccl_log_clone_err(&tmp, log);
		ccl_destroy(&tmp);
		return false;
	}
}

