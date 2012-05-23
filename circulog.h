#ifndef CIRCULOG_H
#define CIRCULOG_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

// This struct is permitted to exist in varying states of validity.
// Always initialize with ccl_init, and call ccl_destroy when done, even if ccl_open failed.
// ** unless ** you use ccl_new and ccl_delete, which perform init and destroy.
typedef struct {
	int sizeof_struct;
	int64_t size;
	int32_t header_size, block_size;
	int32_t version;
	int32_t max_message_size;
	bool wrong_endian;
	bool dirty;
	int access; // CCL_READ, CCL_WRITE, CCL_SHARE
	int fd;
	void *memmap;
	void *buffer;
	int buffer_size;
	int64_t msg_start_addr;
	int msg_pos, msg_len;
	int64_t file_pos;
	int last_err;
	int last_errno;
} ccl_log_t;

typedef struct {
	int sizeof_struct;
	int64_t timestamp;
	int32_t
		msg_len,
		data_ofs,
		data_len;
	void *data;
} ccl_message_info_t;

#define CCL_DEFAULT_MAX_MESSAGE_SIZE 4096
#define CCL_DEFAULT_LOG_SIZE (10*1024*1024)
#define CCL_DEFAULT_BLOCK_SIZE (1<<18)

#define CCL_READ 0
#define CCL_WRITE 1
#define CCL_SHARE 3

#define CCL_SEEK_OLDEST    0
#define CCL_SEEK_RELATIVE  1
#define CCL_SEEK_NEWEST    2
#define CCL_SEEK_ADDR      3
#define CCL_SEEK_LIMIT     4
#define CCL_SEEK_TIME      5

#define CCL_ESYSERR        0
#define CCL_ELOGSTRUCT     1
#define CCL_ELOGOPEN       2 
#define CCL_ELOGVERSION    3 
#define CCL_ELOGINVAL      4
#define CCL_ELOGREAD       5
#define CCL_ERDONLY        6
#define CCL_ERESIZECREATE  7
#define CCL_ERESIZENAME    8
#define CCL_EGETLOCK       9
#define CCL_EDROPLOCK     10
#define CCL_ERESIZERENAME 11
#define CCL_EPARAM        12
#define CCL_ELOGWRITE     13

// These constants were experimentally found to produce a round-up/round-down ratio
//   of exactly 1 for the set [0 .. 999999999]
#define CCL_TS_NSEC_MULTIPLIER 2305843009LL
#define CCL_TS_NSEC_ADDER 17592283732194LL
#define CCL_TS_NSEC_SHIFT (61-16)

#define CCL_NSEC_TO_16BIT_FRAC(nsec) (((nsec) * CCL_TS_NSEC_MULTIPLIER + CCL_TS_NSEC_ADDER) >> CCL_TS_NSEC_SHIFT)
#define CCL_16BIT_FRAC_TO_NSEC(frac) ((long) (((frac) * 1000000LL + 0x8000) >> 16))

extern const char* ccl_err_text(ccl_log_t* log, char* buf, int bufLen);

extern ccl_log_t *ccl_new();
extern void ccl_init(ccl_log_t *log, int struct_size);
extern bool ccl_destroy(ccl_log_t *log);
extern bool ccl_delete(ccl_log_t *log);

extern bool ccl_open(ccl_log_t *log, const char *path);
extern bool ccl_resize(ccl_log_t *log, const char *path, int64_t logSize, bool create, bool force);

extern int64_t ccl_get_timestamp(struct timespec *t);
extern void ccl_split_timestamp(int64_t ts, struct timespec *t_out);

extern int64_t ccl_seek(ccl_log_t *log, int mode, int64_t value);

extern bool ccl_write_message(ccl_log_t *log, ccl_message_info_t *msg);
extern ccl_message_info_t *ccl_read_message(ccl_log_t *log, int dataOfs, void *buf, int bufLen);

#endif
