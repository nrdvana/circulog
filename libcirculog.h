#ifndef CCL_LIBCIRCULOG_H
#define CCL_LIBCIRCULOG_H

#include <stdbool.h>
#include <stdint.h>

/** ccl_log_header_t : the actual header of a circulog log file
 *
 * The fields of this struct are carefully sized and arranged
 * so that the compiler packing setting should not matter.
 *
 * The following must be true for the header to be valid:
 *  - magic == CCL_HEADER_MAGIC
 *  - version >= oldest_compat_version
 *  - header_size >= CCL_MIN_HEADER_SIZE
 *  - timestamp_precision < 64
 *  - spool_start >= header_size
 *  - spool_size is a multiple of 8 bytes
 *
 * The spool must start on a page boundary and be a multiple of the
 * page size in order for the mmap optimizations to be used.
 * However, files are not required to do this; they just become
 * inelegible for the optimization.
 */
typedef struct ccl_log_header_s {
	uint64_t magic;
	uint16_t version;
	uint16_t oldest_compat_version;
	uint32_t config_len;
	uint64_t config_time;
	char     config_sha1[20];
} ccl_log_header_t;

#define CCL_HEADER_MAGIC 0x676f4c7563726943LL
#define CCL_MIN_HEADER_SIZE (sizeof(ccl_log_header_v0))
#define CCL_CURRENT_VERSION 0x00000000
#define CCL_DEFAULT_MAX_MESSAGE_SIZE 4096
#define CCL_DEFAULT_SPOOL_SIZE (10*1024*1024)
#define CCL_DEFAULT_TIMESTAMP_PRECISION 20
#define CCL_DEFAULT_CHK_ALGO CCL_MSG_CHK_NONE
#define CCL_INDEX_GRANULARITY_BITS 16
#define CCL_INDEX_GRANULARITY (1<<CCL_INDEX_GRANULARITY_BITS)
#define CCL_INDEX_ENTRY_SIZE (sizeof(ccl_log_index_entry_t))

/* Format of a log message
 * (can't be represented as a plain C struct)
 * 
 * [8] timestamp
 * [2] 0x1E 0x01  (signature)
 * [1] msg_type
 * [1] msg_chk_algo (bits 0..3), msg_level (bits 4..7)
 * [1..8] size
 *        message
 *        padding
 *        msg_cksum (if any)
 * [1..8] reverse_size
 * [4] frame_checksum
 *
 * where
 *   - Messages are marked by the signature bytes 0x1E 0x01
 *   - 'msg_type' is a byte identifying the type of data in the message.
 *   - 'msg_chk_algo' identifies which checksum was used for the message data.
 *       See CCL_MSG_CK_* constants.
 *   - 'msg_level' describes the priority of a message, as 0 (low) to 15 (high)
 *   - 'timestamp' is uint64_t fixed-precision number, and is relative to log.timestamp_epoch
 *   - 'size' is the length of the data in parenthesees, in bytes, written as a
 *      variable-length integer.
 *   - 'message' is a string of text (or raw binary data) possibly *including* a checksum
 *   - 'padding' is 1 to 8 NUL bytes, aligning the message payload to multiple of 8
 *      bytes, and also NUL terminating the message.
 *   - 'msg_cksum' is a number of bytes (possibly 0) determined by cksumtype field.
 *   - 'reverse_size' is the same as 'size', but with the bytes swapped
 *   - 'frame_cksum' is uint32_t calculated by some simple math on the metadata bytes.
 *      (the address of the message, timestamp, size, msg_type, msg_chk_algo, msg_level)
 *      It is used as a rough first guess of whether the message is valid, or if the
 *      user wants to navigate messages without fully reading each one.
 */

// (when read little endian)
#define CCL_MSG_SIGNATURE 0x011E

// This is not the header itself, just a handy struct for log_load_msg_header
typedef struct ccl_msg_header_s {
	int64_t start_addr;
	int64_t end_addr;
	int64_t msg_len;
	int64_t timestamp;
	int msg_type;
	int msg_chk_algo;
	int msg_level;
	int data_ofs;
} ccl_msg_header_t;

// This is not the footer itself, just a handy struct for log_load_msg_footer
typedef struct ccl_msg_footer_s {
	int64_t start_addr;
	int64_t end_addr;
	int64_t msg_len;
	uint32_t frame_cksum;
} ccl_msg_footer_t;

// Weak checksum... but saves us from processing the whole message,
// and should be good enough to prevent accidentally accepting a half-written message
#define CCL_MESSAGE_FRAME_CHECKSUM(start_address, datalen, timestamp) \
	( (uint32_t) ( \
		(uint32_t)((start_address)>>3) * (uint32_t)3 \
		+ (uint32_t)((timestamp)) * (uint32_t)5 \
		+ (uint32_t)((timestamp)>>32) * (uint32_t)7 \
		+ (uint32_t)((datalen)) * (uint32_t)11 \
	) )

#define CCL_NSEC_TO_FRAC32(nsec) ((((uint64_t)(nsec)) * ((1ULL<<62)/1000000000)) >> 30)
#define CCL_FRAC32_TO_NSEC(frac) ((long) (((frac) * 1000000000ULL + 0x80000000ULL) >> 32))

// 12 + sizeof_size + size + sizeof_size + 4 + NUL padding (+1, then round up to 8)
#define CCL_MESSAGE_FRAME_SIZE(size, sizeof_size) ( \
	( ( (((sizeof_size)<<1)+(size)) >> 3) + 3) << 3 \
)

/** ccl_config_t: circulog configuration struct
 *
 * Struct which manages settings of a circulog.  Circulog supports arbitrary
 * settings, in addition to the core settings.  The settings are stored in a
 * buffer much like environment variables.
 */
typedef struct ccl_config_s {
	size_t allocated;
	size_t settings_len;
	char settings[];
} ccl_config_t;

bool  ccl_config_resize(ccl_config_t **cfg, int new_len);
char* ccl_config_get(ccl_config_t *cfg, const char* name, int name_len);
bool  ccl_config_set(ccl_config_t **cfg, const char* name, int name_len, const char* value, int value_len);

/** ccl_log_t: circulog object representing an open log.
 *
 * This struct is permitted to exist in varying states of validity.
 * Always initialize with ccl_init, and call ccl_destroy when done, even if
 * ccl_open failed **unless** you use ccl_new and ccl_delete, which call
 * init and destroy for you.
 */
typedef struct ccl_log_s {
	// Log open/access parameters
	int fd;
	volatile char *memmap, *memmap_spool;
	size_t memmap_size;
	bool writeable: 1;

	ccl_config_t *config;
	int64_t config_time;
	
	// Parsed versions of important config settings
	char *name;
	int version;
	int timestamp_precision;
	uint64_t timestamp_epoch;
	int max_message_size;
	int default_chk_algo;
	off_t spool_start, spool_size;
	
	// temp buffer used by write, but allocate here so we can re-use
	int iovec_buf_count;
	struct iovec *iovec_buf;
	int64_t spool_write_pos;
	
	// Storage for info about the last error
	int last_err;
	int last_errno;
	const char* last_errmsg;
} ccl_log_t;

#include "circulog.h"

// Quick accessor to return whether log is open (either file or shared mem)
inline bool ccl_log_is_open(ccl_log_t *log) {
	return log->memmap || (log->fd >= 0);
}

bool ccl_log_write_header(ccl_log_t *log);
bool ccl_log_load_header(ccl_log_t *log);
bool ccl_log_create_log(ccl_log_t *log);
bool ccl_log_resize_iovec(ccl_log_t *log, int new_count);

bool ccl_log_clone_err(ccl_log_t *src, ccl_log_t *dest);

#define CCL_LOG_FIELD_OFFSET(fieldname) ( ( (char*) &((ccl_log_t*)4096)->fieldname ) - (char*) 4096 ) 
int  ccl_log_field_by_name(const char* name);
bool ccl_log_get_field(ccl_log_t *log, int field_id, char *str_out, int *str_len, int64_t *int_out);
bool ccl_log_set_field(ccl_log_t *log, int field_id, const char *svalue, int64_t *ivalue);
bool ccl_log_clone_config(ccl_log_t *src, ccl_log_t *dest);
bool ccl_log_store_fields_in_config(ccl_log_t *log);

#define CCL_MSG_HEADER_BUFFER_BYTES 20
bool log_load_msg_header(ccl_log_t *log, int64_t start_addr, ccl_msg_header_t *header);
bool log_load_msg_footer(ccl_log_t *log, int64_t end_addr, ccl_msg_footer_t *footer);
bool log_parse_msg_header(ccl_log_t *log, const char* bufffer, ccl_msg_header_t *header);
bool log_parse_msg_footer(ccl_log_t *log, const char* bufffer, ccl_msg_footer_t *footer);
bool log_load_msg_nodata(ccl_log_t *log, ccl_msg_header_t *header, ccl_msg_footer_t *footer, ccl_msg_t *msg);
bool log_load_msg(ccl_log_t *log, int64_t start_addr, int64_t end_addr, ccl_msg_t *msg, bool grow_buffer);
bool log_find_msg_header(ccl_log_t *log, int64_t addr, int64_t limit, ccl_msg_header_t *header);

typedef int ccl_binary_search_callback_t(void* callback_data, ccl_msg_header_t *header);
bool log_find_msg_header_binsearch(ccl_log_t *log, ccl_binary_search_callback_t *decision, void *decision_data, ccl_msg_header_t *header);

bool log_write_msg(ccl_log_t *log, ccl_msg_t *msg, struct iovec *iov, int iov_count);

// utility method for setting error code/errno/message and returning false
static inline bool SET_ERR(ccl_log_t *log, int code, const char* msg) {
	log->last_err= code;
	log->last_errno= errno;
	log->last_errmsg= msg;
	return false;
}

// utility method for seeking to offset from start of logfile
static inline bool ccl_log_seek(ccl_log_t *log, off_t offset) {
	if (lseek(log->fd, offset, SEEK_SET) == (off_t)-1)
		return SET_ERR(log, CCL_ESEEK, "seek failed: $syserr");
	return true;
}

bool ccl_log_read(ccl_log_t *log, void* record, int record_size);
bool ccl_log_writev(ccl_log_t *log, struct iovec *iov, int iov_count);
bool ccl_log_lock(ccl_log_t *log);
bool ccl_log_unlock(ccl_log_t *log);

#endif
