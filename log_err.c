#include "config.h"
#include "libcirculog.h"

void ccl_log_clone_err(ccl_log_t *src, ccl_log_t *dest) {
	log->last_err= tmp.last_err;
	log->last_errno= tmp.last_errno;
	log->last_errmsg= tmp.last_errmsg;
	return true;
}

int ccl_err_code(ccl_log_t *log, int *syserr_out) {
	if (syserr_out)
		*syserr_out= log->last_errno;
	return log->last_err;
}

inline int strerror_less_stupid(int err_no, char *buffer, int bufsize) {
	// Here, we deal with stupidity regarding strerror.
	// If only sprintf's %m were portable...
	#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
	if (strerror_r(err_no, buffer, bufsize) == 0)
		return strlen(buffer);
	else
		return snprintf(buffer, bufsize, "errno %d", (int) err_no);
	#else
	const char* err_str= strerror_r(err_no, buffer, bufsize);
	size_t n= strlen(err_str);
	if (err_str != buffer) {
		if (n > bufsize) n= bufsize-1;
		memcpy(buffer, err_str, n);
		buffer[n]= '\0';
	}
	return n;
	#endif
}

int ccl_err_text(ccl_log_t *log, char* buf, int buflen) {
	const char *msg, *next_var, *err_str;
	char *pos;
	int count, bufpos, n;
	
	if (!(msg= log->last_errmsg))
		msg= "no error";
	
	// perform substitutions on "$var"
	bufpos= 0;
	while (*msg) {
		next_var= strchr(msg, '$');
		// copy literal portion of message
		count= next_var? next_var-msg : strlen(msg);
		if (bufpos < buflen)
			memcpy(buf+bufpos, msg, count < (buflen-bufpos)? count : (buflen-bufpos));
		msg+= count;
		bufpos+= count;
		// If ended on a variable,
		if (next_var) {
			next_var++; // skip '$' to reach start of the name
			msg= next_var;
			// iterate to end of the name
			while (*msg >= 'a' && *msg <= 'z') msg++;
			// identify it
			count= msg - next_var; // length of name
			n= buflen > bufpos? buflen-bufpos : 0; 
			pos= buflen > bufpos? buf+bufpos : NULL; // place in buffer to write (or null, to only calc length)
			if (strncmp(next_var, "syserr", count) == 0) {
				bufpos+= strerror_less_stupid(log->last_errno, pos, n);
			}
			else if (strncmp(next_var, "logfile", count) == 0) {
				bufpos+= snprintf(pos, n, "%s", log->name? log->name : "log file");
			}
			else {
				bufpos+= snprintf(pos, n, "$%.*s", count, next_var);
			}
		}
	}
	if (buflen)
		buf[bufpos < buflen? bufpos : buflen-1]= '\0';
	return bufpos;
}
