#ifndef CIRCULOG_H
#define CIRCULOG_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
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

extern bool ccl_open(ccl_log_t *log, const char *path, int access);

#define CCL_SEEK_OLDEST    0
#define CCL_SEEK_RELATIVE  1
#define CCL_SEEK_NEWEST    2
#define CCL_SEEK_ADDR      3
#define CCL_SEEK_LIMIT     4
#define CCL_SEEK_TIME      5

extern int64_t ccl_seek(ccl_log_t *log, int mode, int64_t value);

extern bool ccl_write_message(ccl_log_t *log, const struct iovec *caller_iov, int iov_count, int64_t timestamp);
extern bool ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen);

extern uint64_t ccl_encode_timestamp(ccl_log_t *log, struct timespec *t);
extern void ccl_decode_timestamp(ccl_log_t *log, uint64_t ts, struct timespec *t_out);

// Errors about misuse of API
#define CCL_ELOGSTRUCT     0x10
#define CCL_ELOGSTATE      0x11
#define CCL_EREADONLY      0x12
#define CCL_EMSGSIZE       0x13
#define CCL_ESIZELIMIT     0x14
#define CCL_EBADPARAM      0x15

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
