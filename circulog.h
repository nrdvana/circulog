#ifndef CCL_CIRCULOG_H
#define CCL_CIRCULOG_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sys/uio.h>

#ifndef CCL_LIBCIRCULOG_H
typedef struct ccl_log_s { int opaque[30]; } ccl_log_t;
#endif

extern ccl_log_t *ccl_new();
extern bool ccl_init(ccl_log_t *log, int struct_size);
extern bool ccl_destroy(ccl_log_t *log);
extern bool ccl_delete(ccl_log_t *log);

extern bool ccl_get_option(ccl_log_t *log, const char *name, char *str_out, int *str_len, int64_t *int_out);
extern bool ccl_set_option(ccl_log_t *log, const char *name, const char *svalue, int64_t *ivalue);

inline bool ccl_get_option_str(ccl_log_t *log, const char *name, char *str_out, int *str_len) {
	return ccl_get_option(log, name, str_out, str_len, NULL);
}
inline bool ccl_get_option_int(ccl_log_t *log, const char *name, int64_t *int_out) {
	return ccl_get_option(log, name, NULL, NULL, int_out);
}

inline bool ccl_set_option_str(ccl_log_t *log, const char *name, const char *str) {
	return ccl_set_option(log, name, str, NULL);
}
inline bool ccl_set_option_int(ccl_log_t *log, const char *name, int64_t val) {
	return ccl_set_option(log, name, NULL, &val);
}

// Users should ignore messages of type OOB
#define CCL_MSG_TYPE_UNDEF   0
// User-defined opaque bytes
#define CCL_MSG_TYPE_DATA    2
// UTF8 Text
#define CCL_MSG_TYPE_UTF8    3
// JSON (encoded with UTF-8)
#define CCL_MSG_TYPE_JSON    4

// Available checksum algorithms
#define CCL_MSG_CHK_UNDEF   0
#define CCL_MSG_CHK_NONE    1
#define CCL_MSG_CHK_CRC32   2
#define CCL_MSG_CHK_CRC64   3
#define CCL_MSG_CHK_SHA1    4

// Message levels are from -3 (lowest) to 12 (highest)
#define CCL_MSG_LEVEL_DEBUG3  -3
#define CCL_MSG_LEVEL_DEBUG2  -2
#define CCL_MSG_LEVEL_DEBUG1  -1
#define CCL_MSG_LEVEL_TRACE   CCL_MSG_LEVEL_DEBUG3
#define CCL_MSG_LEVEL_DEBUG   CCL_MSG_LEVEL_DEBUG1
#define CCL_MSG_LEVEL_INFO    0
#define CCL_MSG_LEVEL_NOTICE  1
#define CCL_MSG_LEVEL_WARN    2
#define CCL_MSG_LEVEL_WARNING CCL_MSG_LEVEL_WARN
#define CCL_MSG_LEVEL_ERROR   4
#define CCL_MSG_LEVEL_ERR     CCL_MSG_LEVEL_ERROR
#define CCL_MSG_LEVEL_FATAL   6
#define CCL_MSG_LEVEL_CRIT    8
#define CCL_MSG_LEVEL_ALERT   10
#define CCL_MSG_LEVEL_EMERG   12

#define CCL_READ   0
#define CCL_WRITE  1
#define CCL_SHARE  2
#define CCL_CREATE 4
extern bool ccl_open(ccl_log_t *log, const char *path, int access);


typedef struct ccl_msg_s {
	int64_t address;
	uint64_t timestamp;
	int64_t frame_len;
	const char *data;
	size_t data_len;
	char *buffer;
	size_t buffer_len;
	int type;
	int level;
	int chk_algo;
} ccl_msg_t;

extern bool ccl_msg_init(ccl_msg_t *msg);
extern bool ccl_msg_destroy(ccl_msg_t *msg);

extern bool ccl_write_msg(ccl_log_t *log, ccl_msg_t *msg, struct iovec *iov, int iov_count);
inline bool ccl_write_msg_str(ccl_log_t *log, ccl_msg_t msg) {
	return ccl_write_msg(log, &msg, NULL, 0);
}

#define CCL_WRITE_DATA(log, data, length, ...) ccl_write_msg_(log, (ccl_msg_t){ \
	.type= CCL_MSG_TYPE_DATA, .timestamp= 0, .chk_algo= 0, .level= 0, \
	.data= (data), .data_len= (length), ##__VA_ARGS__ })

#define CCL_WRITE_UTF8(log, str, ...) ccl_write_msg_(log, (ccl_msg_t){ \
	.type= CCL_MSG_TYPE_UTF8, .timetsamp= 0, .chk_algo= 0, .level= 0, \
	.data= (str), .data_len= strlen(str), ##__VA_ARGS__ })

#define CCL_WRITE_JSON(log, str, ...) ccl_write_msg_(log, (ccl_msg_t){ \
	.type= CCL_MSG_TYPE_JSON, .timetsamp= 0, .chk_algo= 0, .level= 0, \
	.data= (str), .data_len= strlen(str), ##__VA_ARGS__ })

#define CCL_SEEK_ADDR     0x0000
#define CCL_SEEK_TIME     0x0001
#define CCL_SEEK_OLDEST   0x0002
#define CCL_SEEK_NEWEST   0x0003
#define CCL_SEEK_PREV     0x0004
#define CCL_SEEK_NEXT     0x0005
#define CCL_SEEK_MASK     0x000F
#define CCL_BUFFER_AUTO   0x0100
#define CCL_NODATA        0x0200
extern bool ccl_read_msg(ccl_log_t *log, ccl_msg_t *msg, int flags);

extern uint64_t ccl_encode_timestamp(ccl_log_t *log, struct timespec *t);
extern void ccl_decode_timestamp(ccl_log_t *log, uint64_t ts, struct timespec *t_out);

// API-level errors
#define CCL_ELOGSTRUCT     0x10
#define CCL_ELOGSTATE      0x11
#define CCL_EREADONLY      0x12
#define CCL_EMSGSIZE       0x13
#define CCL_ESIZELIMIT     0x14
#define CCL_EBADPARAM      0x15
#define CCL_ENOTFOUND      0x16
#define CCL_EBUFFERSIZE    0x17
#define CCL_EUNSUPPORTED   0x18

// Errors about file incompatibility or corruption
#define CCL_ELOGVERSION    0x30
#define CCL_ELOGINVAL      0x31
#define CCL_EEOF           0x32

// Errors about syscall failure
#define CCL_ESYSERR        0x50
#define CCL_EREAD          0x51
#define CCL_EWRITE         0x52
#define CCL_ESEEK          0x53
#define CCL_ELOCK          0x54
#define CCL_EOPEN          0x55
#define CCL_ERENAME        0x56

extern int ccl_err_code(ccl_log_t *log, int *syserr_out);
extern int ccl_err_text(ccl_log_t *log, char* buf, int bufLen);

#endif // CIRCULOG_H
