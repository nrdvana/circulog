#ifndef CIRCULOG_H
#define CIRCULOG_H

#include <stdint.h>

typedef struct {
	uint64_t
		magic;
	int32_t version;
	int32_t oldest_compat_version;
	uint64_t
		size,
		oldest,
		newest,
		writer_pid,
		reserved[10];
} ccl_log_header_t;

#define CIRCULOG_MAGIC 0x43697263754c6f67LL

typedef struct {
	int64_t timestamp;
	uint32_t prevOfs;
	uint32_t dataLen;
	char data[0];
} LogEntry_t;

#define LOG_ENTRY_LENGTH(entry) ( sizeof(LogEntry_t) + (entry)->dataLen + 1 )
#define NEXT_LOG_ENTRY_OFS(entry) ( sizeof(LogEntry_t) + (((entry)->dataLen + (uint32_t)8) & (uint32_t)~0x7) )

#define DEFAULT_MAX_MESSAGE_SIZE (4096-1)
#define DEFAULT_LOG_SIZE (10*1024*1024)

#endif
