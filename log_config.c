#include "config.h"
#include "libcirculog.h"

#define ROUND_MULTIPLE(x, multiple_of) ( (((x)-1) | ((multiple_of)-1)) + 1 )

bool ccl_config_resize(ccl_config_t **cfg, int new_len) {
	int pagesize;
	size_t new_alloc;
	ccl_config_t *new_cfg;
	
	// We always allocate in multiples of pagesize (or 256)
	pagesize= sysconf(_SC_PAGESIZE);
	if (pagesize < 256) pagesize= 256;
	
	new_alloc= ROUND_MULTIPLE(new_len, pagesize);
	if (!*cfg || new_alloc > (*cfg)->allocated) {
		new_cfg= (ccl_config_t*) realloc(*cfg, new_alloc);
		if (!new_cfg)
			return false;
		new_cfg->allocated= new_alloc;
		*cfg= new_cfg;
	}
	return true;
}

/** Get a configuration setting
 *
 * This performs a linear scan of the config buffer (copied form the log header)
 * looking for name.  If found, returns a pointer to the "name=value\0" string.
 * Else returns NULL.  Does not update log->error* fields.
 *
 * TODO: do something smarter than a linear scan.
 */
char* ccl_config_get(ccl_config_t *cfg, const char* name, int name_len) {
	char *p, *endp;
	if (!cfg) return NULL;
	for (p= cfg->settings, endp= p + cfg->settings_len; p; p= (char*) memchr(p, 0, endp - p)) {
		if (endp - p > name_len + 1
			&& memcmp(name, p, name_len) == 0
			&& p[name_len] == '=')
			return p;
	}
	return NULL;
}

/** Apply a configuration setting
 *
 * This updates the configuration data with a new name=value pair, possibly
 * growing the config to hold it.  The config buffer is rounded up to pagesize
 * of the system, so reallocations are infrequent with typical small
 * names/values.
 *
 * This method does not write out the new log header. The caller is responsible for that.
 *
 * Returns false if malloc fails
 */
bool ccl_config_set(ccl_config_t **cfg, const char* name, int name_len, const char* value, int value_len) {
	char *prev;
	int prev_ofs, prev_len, prev_settings_len, new_len, new_settings_len;

	prev_settings_len= (*cfg)? (*cfg)->settings_len : 0;
	
	// find existing setting
	if ((prev= ccl_config_get(*cfg, name, name_len))) {
		prev_len= name_len + 1 + strlen(prev) + 1;
		prev_ofs= prev - (*cfg)->settings;
	} else {
		// if it didn't exist, set up vars so we append
		prev_ofs= prev_settings_len;
		prev_len= 0;
	}
	
	new_len= value? name_len + 1 + value_len + 1 : 0;
	new_settings_len= prev_settings_len - prev_len + new_len;
	
	// If new size is zero, no settings left, and might as well free the buffer
	if (new_settings_len == 0) {
		if (*cfg) free(*cfg);
		*cfg= NULL;
		return true;
	}
	// else see if we need to grow the buffer
	if (!*cfg || sizeof(ccl_config_t) + new_settings_len > (*cfg)->allocated) {
		if (!ccl_config_resize(cfg, sizeof(ccl_config_t) + new_settings_len + 256))
			return false;
	}
	
	prev= (*cfg)->settings + prev_ofs;

	// Buffer is large enough, now.
	// Leave prefix as-is.
	// Move suffix (if length of setting changed)
	if (prev_len != new_len && prev_len > 0)
		memmove(prev + new_len, prev + prev_len, (*cfg)->settings_len - (prev_ofs + prev_len));
	// overwrite setting
	if (new_len > 0) {
		memcpy(prev, name, name_len);
		prev[name_len]= '=';
		memcpy(prev + name_len + 1, value, value_len);
		prev[name_len + 1 + value_len]= '\0';
	}
	(*cfg)->settings_len= new_settings_len;
	return true;
}

#define CHAR_PREFIX(c1,c2) (( ((c2) & 0xFF) << 8) | ((c1) & 0xFF))
#define CHECK_FIELD(fieldname) if (0 == strcmp(name, #fieldname)) return CCL_LOG_FIELD_OFFSET(fieldname);

// Returns a field offset (within ccl_log_t) by name,
// or -1 if no field matches.
int ccl_log_field_by_name(const char* name) {
	if (!name[0] || !name[1]) return -1;
	switch (CHAR_PREFIX(name[0], name[1])) {
	case CHAR_PREFIX('d','e'):
		CHECK_FIELD(default_chk_algo)
		break;
	case CHAR_PREFIX('m','a'):
		CHECK_FIELD(max_message_size)
		break;
	case CHAR_PREFIX('s','p'):
		CHECK_FIELD(spool_start)
		CHECK_FIELD(spool_size)
		break;
	case CHAR_PREFIX('t','i'):
		CHECK_FIELD(timestamp_precision)
		CHECK_FIELD(timestamp_epoch)
		break;
	case CHAR_PREFIX('v','e'):
		CHECK_FIELD(version)
		break;
	}
	return -1;
}

bool ccl_log_get_field(ccl_log_t *log, int field_id, char *str_out, int *str_len, int64_t *int_out) {
	int64_t int_tmp= 0;
	char *str_tmp= NULL, *endptr;
	size_t n;
	
	assert((str_out && str_len && !int_out) || (!str_out && !str_len && int_out));
	
	switch (field_id) {
	case CCL_LOG_FIELD_OFFSET(default_chk_algo):
		int_tmp= log->default_chk_algo;
		break;
	case CCL_LOG_FIELD_OFFSET(max_message_size):
		int_tmp= log->max_message_size;
		break;
	case CCL_LOG_FIELD_OFFSET(name):
		str_tmp= log->name;
		break;
	case CCL_LOG_FIELD_OFFSET(spool_size):
		int_tmp= log->spool_size;
		break;
	case CCL_LOG_FIELD_OFFSET(timestamp_precision):
		int_tmp= log->timestamp_precision;
		break;
	case CCL_LOG_FIELD_OFFSET(timestamp_epoch):
		int_tmp= log->timestamp_epoch;
		break;
	default:
		return SET_ERR(log, CCL_EBADPARAM, "invalid field_id");
	}
	
	if (int_out) {
		if (str_tmp) {
			int_tmp= strtoll(str_tmp, &endptr, 0);
			if (*endptr != '\0')
				return SET_ERR(log, CCL_EBADPARAM, "setting is not an integer");
		}
		*int_out= int_tmp;
	}
	else {
		if (str_tmp) {
			n= *str_len;
			*str_len= strlen(str_tmp);
			if (*str_len >= n)
				return SET_ERR(log, CCL_EBUFFERSIZE, "provided buffer too small");
			memcpy(str_out, str_tmp, *str_len+1);
		} else {
			n= *str_len;
			*str_len= snprintf(str_out, n, "%lld", (long long) int_tmp);
			if (*str_len >= n)
				return SET_ERR(log, CCL_EBUFFERSIZE, "provided buffer too small");
		}
	}
	return true;
}

/** ccl_log_set_field assigns a string or integer value to a field.
 *
 * field_id is the offset of the field within ccl_log_t, returned by log_get_field_by_name
 *
 * If svalue and ivalue are NULL, the value will be unset.
 * If only svalue is given, ivalue will be parsed form it as needed.
 * If only ivalue is given, svalue will be formatted as needed.
 * If both are given, they will be considered equivalent representations.
 *
 * Returns true if the value was set.
 * Returns false if anything went wrong, with a code and message in log.
 */
bool ccl_log_set_field(ccl_log_t *log, int field_id, const char *svalue, int64_t *ivalue) {
	int64_t i;
	char buffer[20], *endptr;
	size_t n;
	
	if (svalue && !ivalue) {
		i= strtoll(svalue, &endptr, 0);
		if (!*endptr)
			ivalue= &i;
	}
	if (ivalue && !svalue) {
		snprintf(buffer, sizeof(buffer), "%lld", (long long ) *ivalue);
		svalue= buffer;
	}
	
	switch (field_id) {
	case CCL_LOG_FIELD_OFFSET(default_chk_algo):
		if (!ivalue || *ivalue < CCL_MSG_CHK_NONE || *ivalue > CCL_MSG_CHK_SHA1)
			return SET_ERR(log, CCL_EBADPARAM, "invalid default_chk_algo");
		log->default_chk_algo= (int) *ivalue;
		return true;
	case CCL_LOG_FIELD_OFFSET(max_message_size):
		if ((svalue && !ivalue) || *ivalue < 0)
			return SET_ERR(log, CCL_EBADPARAM, "invalid max_message_size");
		log->max_message_size= ivalue? *ivalue : (-1<<(sizeof(log->max_message_size)*8-1));
		return true;
	case CCL_LOG_FIELD_OFFSET(name):
		if (!svalue && log->name) {
			free(log->name);
			log->name= NULL;
		} else if (svalue) {
			n= strlen(svalue)+1;
			char *buf= malloc(n);
			if (!buf)
				return SET_ERR(log, CCL_ESYSERR, "malloc failed");
			memcpy(log->name, svalue, n);
			if (log->name)
				free(log->name);
			log->name= buf;
		}
		return true;
	case CCL_LOG_FIELD_OFFSET(spool_size):
		if (!ivalue || *ivalue < 0)
			return SET_ERR(log, CCL_EBADPARAM, "invalid spool_size");
		log->spool_size= *ivalue;
		return true;
	case CCL_LOG_FIELD_OFFSET(timestamp_precision):
		if (!ivalue || *ivalue < 0 || *ivalue >= 64)
			return SET_ERR(log, CCL_EBADPARAM, "invalid timestamp_precision");
		log->timestamp_precision= *ivalue;
		return true;
	case CCL_LOG_FIELD_OFFSET(timestamp_epoch):
		if (!ivalue)
			return SET_ERR(log, CCL_EBADPARAM, "invalid timestamp_epoch");
		log->timestamp_epoch= *ivalue;
		return true;
	}
	return SET_ERR(log, CCL_EBADPARAM, "");
}

#define STORE_INT_FIELD(fieldname) \
	ccl_config_set(&log->config, #fieldname, strlen(#fieldname), \
		buffer, sprintf(buffer, "%lld", (long long) log->fieldname))
bool ccl_log_store_fields_in_config(ccl_log_t *log) {
	char buffer[20];
	return (STORE_INT_FIELD(default_chk_algo)
		&& STORE_INT_FIELD(max_message_size)
		&& STORE_INT_FIELD(spool_size)
		&& STORE_INT_FIELD(timestamp_precision)
		&& STORE_INT_FIELD(timestamp_epoch)
		&& ccl_config_set(&log->config, "name", 4, log->name, strlen(log->name))
		) || SET_ERR(log, CCL_ESYSERR, "malloc failed");
}

bool ccl_log_clone_config(ccl_log_t *src, ccl_log_t *dest) {
	size_t n;
	
	if (src->config) {
		if (!ccl_config_resize(&dest->config, src->config->allocated))
			return false;
		dest->config->settings_len= src->config->settings_len;
		memcpy(dest->config->settings, src->config->settings, src->config->settings_len);
	} else if (dest->config) {
		free(dest->config);
		dest->config= NULL;
	}
	
	if (dest->name) {
		free(dest->name);
		dest->name= NULL;
	}
	if (src->name) {
		n= strlen(src->name)+1;
		dest->name= (char*) malloc(n);
		if (!dest->name)
			return SET_ERR(src, CCL_ESYSERR, "malloc failed");
		memcpy(dest->name, src->name, n);
	}
	dest->version=             src->version;
	dest->timestamp_precision= src->timestamp_precision;
	dest->timestamp_epoch=     src->timestamp_epoch;
	dest->max_message_size=    src->max_message_size;
	dest->default_chk_algo=    src->default_chk_algo;
	dest->spool_start=         src->spool_start;
	dest->spool_size=          src->spool_size;
	return true;
}

/** Gets the value of the named option as either string or integer
 *
 * If str_out is given, then str_len must also be given and specifies the size of the buffer.
 * str_len will be updated to the length of the string.  Note that the input is a **buffer size**
 * and the output is a **string length** (not including NUL).
 *
 * If int_out is given, the function attempts to parse the value as a number, and if fails,
 * returns false with an error in log.
 */
bool ccl_get_option(ccl_log_t *log, const char* name, char *str_out, int *str_len, int64_t *int_out) {
	int tmp_i, name_len, field_id;
	char *endptr;
	const char *setting;
	int64_t tmp;
	
	if (!((int_out && !str_out && !str_len) || (!int_out && str_out && str_len)))
		return SET_ERR(log, CCL_EBADPARAM, "must request int_out, or {str_out,str_len}");
	
	name_len= strlen(name);
	field_id= ccl_log_field_by_name(name);
	// If its a known field, serve it from the field instead of the config strings
	if (field_id >= 0) {
		return ccl_log_get_field(log, field_id, str_out, str_len, int_out);
	}
	// else serve it from config strings
	else {
		setting= ccl_config_get(log->config, name, name_len);
		if (!setting)
			return SET_ERR(log, CCL_ENOTFOUND, "");
		
		// If they want it in a buffer, ensure size, and copy it.
		if (str_out) {
			// buffer size check
			tmp_i= *str_len;
			*str_len= strlen(setting + name_len + 1);
			if (*str_len >= tmp_i)
				return SET_ERR(log, CCL_EBUFFERSIZE, "provided buffer too small");
			memcpy(str_out, setting + name_len + 1, *str_len+1);
		}
		else {
			// If they want it as an int, parse it.
			tmp= strtoll(setting + name_len + 1, &endptr, 0);
			if (*endptr)
				return SET_ERR(log, CCL_EBADPARAM, "setting is not an integer");
			*int_out= tmp;
		}
	}
	return true;
}

/** Set the value of an option from either a string or an integer.
 *
 * This can be used to set all sorts of options, but most cannot be changed
 * once the log is opened.  As such, this function is mostly for setting defaults
 * for a new log.
 *
 * In the future, this will be able to dynamically update things like spool-size
 * or timestamp_precision by rewriting the entire log.
 */
bool ccl_set_option(ccl_log_t *log, const char* name, const char *svalue, int64_t *ivalue) {
	int field_id, name_len;
	char str[20];
	
	if (!(name_len= strlen(name)) || strchr(name, '='))
		return SET_ERR(log, CCL_EBADPARAM, "invalid name");
	field_id= ccl_log_field_by_name(name);
	
	// If the logfile is open, we need to do some analysis on whether we need to re-write
	// the whole thing, or if we can update just the header
	// TODO: do the hard logic.  Until then, disallow updates to an open log.
	if (ccl_log_is_open(log))
		return SET_ERR(log, CCL_ELOGSTATE, "Can't set fields on open log");

	// Is it a known field?
	if (field_id >= 0) {
		if (!ccl_log_set_field(log, field_id, svalue, ivalue))
			return false;
		// Un-set any matching value in config, to prevent discrepancy
		// We could just apply it there too, but would rather lazy-build the config
		if (!ccl_config_set(&log->config, name, name_len, NULL, 0))
			// should never happen! unset should always succeed
			return SET_ERR(log, CCL_ELOGSTRUCT, "BUG: un-setting field failed??");
		return true;
	}
	// else its a user-defined field, and needs stored as a string.
	else {
		// get string representation of value
		if (ivalue && !svalue) {
			sprintf(str, "%lld", (long long) *ivalue);
			svalue= str;
		}
		// store the name=value pair
		return ccl_config_set(&log->config, name, name_len, svalue, strlen(svalue));
	}
}

