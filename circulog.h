#ifndef CIRCULOG_H
#define CIRCULOG_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sys/uio.h>

#ifndef CIRCULOG_INTERNAL_H
typedef struct ccl_log_s { int opaque[30]; } ccl_log_t;
#endif

extern ccl_log_t *ccl_new();
extern bool ccl_init(ccl_log_t *log, int struct_size);
extern bool ccl_destroy(ccl_log_t *log);
extern bool ccl_delete(ccl_log_t *log);

extern bool ccl_init_timestamp_params(ccl_log_t *log, int64_t epoch, int precision_bits);
extern bool ccl_init_geometry_params(ccl_log_t *log, int64_t spool_size, bool with_index, int max_message_size);

#define CCL_READ   0
#define CCL_WRITE  1
#define CCL_SHARE  2
#define CCL_CREATE 4

#define CCL_CK_METAONLY  0x4154454d

extern bool ccl_open(ccl_log_t *log, const char *path, int access);

extern bool ccl_write_vec(ccl_log_t *log, const struct iovec *caller_iov, int iov_count, int64_t timestamp);

inline bool ccl_write_str(ccl_log_t *log, const char *str, int64_t timestamp) {
	struct iovec tmp;
	tmp.iov_base= (void*) str;
	tmp.iov_len= strlen(str);
	return ccl_write_vec(log, &tmp, 1, timestamp);
}

inline bool ccl_write_data(ccl_log_t *log, const void *data, int length, int64_t timestamp) {
	struct iovec tmp;
	tmp.iov_base= (void*) data;
	tmp.iov_len= length;
	return ccl_write_vec(log, &tmp, 1, timestamp);
}

typedef struct ccl_msg_s {
	int64_t address;
	int64_t timestamp;
	int64_t frame_len;
	const char *data;
	size_t data_len;
	char *buffer;
	size_t buffer_len;
	int msg_type;
	int msg_cksum_type;
	int msg_level;
} ccl_msg_t;

extern bool ccl_msg_init(ccl_msg_t *msg);
extern bool ccl_msg_destroy(ccl_msg_t *msg);

#define CCL_SEEK_ADDR     0x0000
#define CCL_SEEK_TIME     0x0001
#define CCL_SEEK_OLDEST   0x0002
#define CCL_SEEK_NEWEST   0x0003
#define CCL_SEEK_PREV     0x0004
#define CCL_SEEK_NEXT     0x0005
#define CCL_SEEK_MASK     0x000F
#define CCL_BUFFER_AUTO   0x0100
#define CCL_NODATA        0x0200
extern bool ccl_read_message(ccl_log_t *log, ccl_msg_t *msg, int flags);

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
#define CCL_BUFFERSIZE     0x17

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
