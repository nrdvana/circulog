#ifndef CIRCULOG_INTERNAL_H
#define CIRCULOG_INTERNAL_H

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
 *  - index_start >= header_size
 *  - index_size is a multiple of sizeof(ccl_log_index_entry_t)
 *  - index_size / sizeof(ccl_log_index_entry_t) == ceil(spool_size / INDEX_GRANULARITY)
 *  - spool_start >= index_start+index_size
 *  - spool_size is a multiple of 8 bytes
 *  - file size >= spool_start+spool_size
 *
 * The spool must start on a page boundary and be a multiple of the
 * page size in order for the mmap optimizations to be used.
 * However, files are not required to do this; they just become
 * inelegible for the optimization.
 */
typedef struct ccl_log_header_s {
	uint64_t
		magic;
	uint32_t
		version,
		oldest_compat_version,
		header_size,
		timestamp_precision;
	int64_t
		timestamp_epoch;
	uint64_t
		index_start,
		index_size,
		spool_start,
		spool_size;
	uint32_t
		max_message_size,
		reserved_1;
} ccl_log_header_t;

typedef struct ccl_log_header_s ccl_log_header_v0;

#define CCL_HEADER_MAGIC 0x676f4c7563726943LL
#define CCL_MIN_HEADER_SIZE (sizeof(ccl_log_header_v0))
#define CCL_CURRENT_VERSION 0x00000000
#define CCL_DEFAULT_MAX_MESSAGE_SIZE 4096
#define CCL_DEFAULT_SPOOL_SIZE (10*1024*1024)
#define CCL_DEFAULT_TIMESTAMP_PRECISION 32
#define CCL_INDEX_GRANULARITY_BITS 16
#define CCL_INDEX_GRANULARITY (1<<CCL_INDEX_GRANULARITY_BITS)
#define CCL_INDEX_ENTRY_SIZE (sizeof(ccl_log_index_entry_t))

/** ccl_log_index_entry_t : format of each element in the index
 *
 * The index is simply a circular log of index entries, where each entry
 * is a timestamped pointer to a message in the main log data.
 * The index is just a suggestion of where to find valid log entries.
 * Valid log entries can always be found at the first byte of the file,
 * though it might be inefficient to scan the whole log file for the
 * desired timestamp.  The index speeds this up.
 */
typedef struct ccl_log_index_entry_s {
	int64_t timestamp;  // relative to timestamp_epoch
	int64_t msg_offset; // offset from start of message area
} ccl_log_index_entry_t;

/* Format of a log message
 * (can't be represented as a plain C struct)
 * 
 * [8] timestamp
 * [1..8] size
 *        message
 *        padding
 *        data_cksum
 * [1..8] reverse_size
 * [1] msg_type
 * [1] cksumtype (bits 0..3), msglevel (bits 4..7)
 * [2] flags (reserved)
 * [4] meta_checksum
 *
 * where
 *   - 'timestamp' is uint64_t and is relative to log.timestamp_epoch
 *   - 'message' is a string of text (or raw binary data) possibly *including* a checksum
 *   - 'size' is the length of the data in parenthesees, in bytes, written as a
 *     variable-length integer.
 *   - 'reverse_size' is the same as 'size', but with the bytes swapped
 *   - 'padding' is 1 to 8 NUL bytes, aligning the message payload to multiple of 8
 *       bytes, and also NUL terminating the message.
 *   - 'data_cksum' is a number of bytes (possibly 0) determined by cksumtype field.
 *   - 'msgtype' is a byte identifying the type of data in the message.
 *       0  - user-defined opaque bytes, user-defined flags.  utilities should display as hexdump.
 *       1  - UTF-8 text
 *       2  - UTF-8 JSON data
 *   - 'cksumtype' identifies which checksum was used for the message data
 *       0  - no checksum
 *       1  - CRC32 (4 byte checksum)
 *       2  - CRC64 (8 byte checksum)
 *       3  - SHA-1 (20 byte checksum)
 *   - 'msglevel' describes the priority of a message, as 0 (low) to 15 (high)
 *     A suggested mapping from msglevel to syslog constants is:
 *         >= 0xF : EMERG
 *         >= 0xE : ALERT
 *         >= 0xC : CRIT
 *         >= 0xA : ERR
 *         >= 0x8 : WARNING
 *         >= 0x6 : NOTICE
 *         >= 0x4 : INFO
 *         <= 0x3 : DEBUG
 *   - 'flags' are reserved for now, and should be 0 for msgtype other than 0.
 *   - 'meta_cksum' is uint32_t calculated by some simple math on the metadata bytes.
 *      (the address of the message, timestamp, size, and the 4 preceeding metadata bytes)
 *     It is used as a rough first guess of whether the message is valid, or if the
 *     user wants to navigate messages without fully reading each one.
 */

// Weak checksum... but saves us from processing the whole message,
// and should be good enough to prevent accidentally accepting a half-written message
#define CCL_MESSAGE_META_CHECKSUM(start_address, datalen, timestamp, info) \
	( (uint32_t) ( \
		(uint32_t)((start_address)>>3) * (uint32_t)3 \
		+ (uint32_t)((timestamp)) * (uint32_t)5 \
		+ (uint32_t)((timestamp)>>32) * (uint32_t)7 \
		+ (uint32_t)((datalen)) * (uint32_t)11 \
		+ (uint32_t)((info)) * (uint32_t)13 \
	) )

#define CCL_NSEC_TO_FRAC32(nsec) ((((uint64_t)(nsec)) * ((1ULL<<62)/1000000000)) >> 30)
#define CCL_FRAC32_TO_NSEC(frac) ((long) (((frac) * 1000000000ULL + 0x80000000ULL) >> 32))

// sizeof_size * 2 + size + 8 /*timestamp*/ + 4 /*meta*/ + 4 /*checksum*/ + padding of 1 to 8 bytes
#define CCL_BYTES_NEEDED_FOR_MESSAGE(size, sizeof_size) ( ( ( (((sizeof_size)<<1)+(size)) >> 3) + 3) << 3)

/** ccl_log_t: circulog object representing an open log.
 *
 * This struct is permitted to exist in varying states of validity.
 * Always initialize with ccl_init, and call ccl_destroy when done, even if
 * ccl_open failed ** unless ** you use ccl_new and ccl_delete, which call
 * init and destroy for you.
 */
typedef struct ccl_log_s {
	// Log-specific parameters
	int header_size;
	int version;
	int timestamp_precision;
	int64_t timestamp_epoch;
	int max_message_size;
	int checksum_algo;
	off_t index_start,
		index_size,
		spool_start,
		spool_size;
	//bool wrong_endian;
	//bool dirty;
	
	bool writeable: 1,
		shared_write: 1;
	int fd;
	volatile char *memmap;
	size_t memmap_size;
	int iovec_count;
	struct iovec *iovec_buf;
	int64_t spool_pos;
	
	// Storage for info about the last error
	int last_err;
	int last_errno;
	const char* last_errmsg;
} ccl_log_t;

#include "circulog.h"

bool log_probe_msgstart(ccl_log_t *log, int64_t start_addr, int64_t *end_addr_out, int64_t *timestamp_out);
bool log_probe_msgend(ccl_log_t *log, int64_t end_addr, int64_t *start_addr_out, int64_t *timestamp_out);
bool log_load_message(ccl_log_t *log, int64_t start_addr, int64_t end_addr, ccl_msg_t *msg);
bool log_load_message_nodata(ccl_log_t *log, int64_t start_addr, int64_t end_addr, ccl_msg_t *msg);

#endif
