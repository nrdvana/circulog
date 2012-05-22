#ifndef CIRCULOG_INTERNAL_H
#define CIRCULOG_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include "circulog.h"

typedef struct {
	uint64_t
		magic;
	int32_t
		version,
		oldest_compat_version;
	int64_t
		size,
		header_size,
		oldest,
		newest,
		writer_pid;
} ccl_log_header_t;

#define CCL_HEADER_MAGIC 0x43697263754c6f67LL
#define CCL_CURRENT_VERSION 0x00000000

typedef struct {
	int64_t timestamp;
	uint32_t prevOfs;
	uint32_t dataLen;
	char data[0];
} ccl_log_entry_t;

#define CCL_LOG_ENTRY_LENGTH(entry) ( sizeof(LogEntry_t) + (entry)->dataLen + 1 )
#define CCL_NEXT_LOG_ENTRY_OFS(entry) ( sizeof(LogEntry_t) + (((entry)->dataLen + (uint32_t)8) & (uint32_t)~0x7) )

#endif
