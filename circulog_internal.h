#ifndef CIRCULOG_INTERNAL_H
#define CIRCULOG_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include "circulog.h"

/** ccl_log_header_t : the actual header of a circulog log file
 *
 * The fields of this struct are carefully sized and arranged
 * so that the compiler packing setting should not matter.
 *
 * The following must be true for the header to be valid:
 *  - magic == CCL_HEADER_MAGIC
 *  - version >= oldest_compat_version
 *  - size > header_size+index_size
 *  - header_size >= CCL_MIN_HEADER_SIZE
 *
 * The size field might not agree with the size of the log file.  In order to
 * mmap the file, its size might need to be rounded to the nearest multiple of
 * the page size (such as 4KiB).  This physical resize of the file does not
 * affect the logical boundary which causes the log to wrap.  The size field
 * is the authority.
 */
typedef struct ccl_log_header_s {
	uint64_t
		magic;
	uint32_t
		version,
		oldest_compat_version;
	uint64_t
		size;
	uint32_t
		header_size,
		index_size,
		timestamp_precision,
		reserved_0;
	int64_t
		timestamp_epoch;
} ccl_log_header_t;

#define CCL_HEADER_MAGIC 0x676f4c7563726943LL
#define CCL_MIN_HEADER_SIZE 48
#define CCL_CURRENT_VERSION 0x00000000

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
 * ( size message padding reverse_size ) timestamp checksum
 *
 * where
 *   - 'size' is the length of 'message' in bytes, written as a
 *     variable-length integer.
 *   - 'reverse_size' is the same as 'size', but with the bytes swapped
 *   - 'message' is a string of text (or raw binary data)
 *   - 'padding' is 1 to 8 NUL bytes, aligning the timestamp to multiple of 8
 *     bytes, and also NUL terminating the message.
 *   - 'timestamp' is uint64_t and is relative to log.timestamp_epoch
 *   - 'checksum' is uint64_t, and calculated by CCL_MESSAGE_CHECKSUM, which
 *     actually doesn't checksum the message at all, only the metadata
 *
 */

// Weak checksum... but saves us from processing the whole message,
// and should be good enough to prevent accidentally accepting a half-written message
#define CCL_MESSAGE_CHECKSUM(datalen, timestamp, start_address) \
	((((start_address)>>3)*0x0505050505050505LL) ^ ((timestamp)*0x1000010000100001LL) ^ ((datalen)*0x9009009009009LL))

#define CCL_NSEC_TO_FRAC32(nsec) ((((uint64_t)(nsec)) * ((1ULL<<62)/1000000000)) >> 30)
#define CCL_FRAC32_TO_NSEC(frac) ((long) (((frac) * 1000000000ULL + 0x80000000ULL) >> 32))

// sizeof_size * 2 + size + sizeof(timestamp) + sizeof(checksum) + padding of 1 to 8 bytes
#define CCL_BYTES_NEEDED_FOR_MESSAGE(size, sizeof_size) ( ( ( (((sizeof_size)<<1)+(size)) >> 3) + 3) << 3)

#endif
