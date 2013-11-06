#include "config.h"
#include "circulog.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

typedef struct {
	const char* fileName;
	long long logSize;
	int maxMsgSize;
	bool resizeLog;
	ccl_log_t *log;
	int patternCount;
} retention_category_t;

#ifdef CONFIG_PCRE
typedef struct {
	const char* spec;
	pcre* pattern;
	pcre_extra* studyData;
	const char* replace;
	int destLogIdx;
} retention_pattern_t;
#else
#error non-regex prefix matching not yet implemented
typedef struct prefix_trie_node_s {
	struct prefix_trie_node_s *nextChar[256];
	const char* remainder;
	int retention_category;
} prefix_trie_node_t;
#endif

typedef struct {
	int         verbose;
	int         defaultMaxMsgSize;
	long long   defaultLogSize;
	bool        defaultResizeLog;
	bool        createIfMissing;
	const char* logBaseName;
	int                   categoryCount;
	retention_category_t *category, *currentCategory;
	int                   patternCount;
	retention_pattern_t  *pattern;
} circulog_t;

bool ccl_addLogSpec(circulog_t* self, const char* spec);
bool ccl_addPatternSpec(circulog_t* self, const char* spec);
bool ccl_sanityCheck(circulog_t* self);
bool ccl_openLogFiles(circulog_t* self);
bool ccl_handleMessage(circulog_t* self, const char* msg, int msgLen);
bool ccl_parseOptions(circulog_t* self, char** argv);
bool ccl_processOption(circulog_t* self, char shortOpt, char* longOpt, char* optVal, char*** argvp);

extern unsigned int version_number;
extern const char
	*build_info_commit,
	*build_info_host,
	*build_info_date;
#include "circulog-util.version"

bool parseInt(long* dest, char* src);
bool parseSize(long long* dest, char* src);
void exit_usage(int stream, int exitcode);
void exit_version();
void exit_runtime_fail();

#define Error(fmt, args...)  do { if (self->verbose >= -1) fprintf(stderr, "ERROR: "   fmt "\n" , ## args); } while (0)
#define Warn(fmt, args...)   do { if (self->verbose >=  0) fprintf(stderr, "WARNING: " fmt "\n" , ## args); } while (0)
#define Notice(fmt, args...) do { if (self->verbose >=  1) fprintf(stderr, "NOTICE: "  fmt "\n" , ## args); } while (0)
#define Debug(fmt, args...)  do { if (self->verbose >=  2) fprintf(stderr, "DEBUG: "   fmt "\n" , ## args); } while (0)
#define Trace(fmt, args...)  do { if (self->verbose >=  3) fprintf(stderr, "DEBUG: "   fmt "\n" , ## args); } while (0)

int main(int argc, char** argv) {
	char *buffer, *start, *limit, *eol;
	int i, got, bufLen;
	bool eof, skipCurrent;
	circulog_t circulog, *self= &circulog;
	
	memset(self, 0, sizeof(*self));
	self->defaultMaxMsgSize= CCL_DEFAULT_MAX_MESSAGE_SIZE;
	self->defaultLogSize= CCL_DEFAULT_LOG_SIZE;
	self->createIfMissing= true;
	
	if (!ccl_parseOptions(self, argv+1)) {
		Debug("option-parsing failed");
		exit_usage(2, 2);
	}
	
	Debug("sanity check");
	if (!ccl_sanityCheck(self)) {
		Debug("sanity check failed");
		Error("Configuration is invalid (fatal)");
		return 2;
	}
	
	Debug("open logs");
	if (!ccl_openLogFiles(self)) {
		exit_runtime_fail();
	}
	
	bufLen= 0;
	for (i= 0; i < self->categoryCount; i++)
		if (self->category[i].maxMsgSize > bufLen)
			bufLen= self->category[i].maxMsgSize+1;
	buffer= malloc(bufLen);
	if (!buffer) {
		Error("malloc(msgbuf): %m");
		exit_runtime_fail();
	}
	
	start= limit= buffer;
	skipCurrent= false;
	eof= false;
	Debug("beginning main loop");
	while (!eof) {
		got= read(0, limit, bufLen-1 - (limit-buffer));
		if (got > 0) {
			eol= limit;   // start the search from here
			limit += got;
			*limit= '\0';
			// now see how many lines (messages) we can make from the buffer
			while ((eol= strchr(eol, '\n'))) {
				// handle message
				if (skipCurrent)
					skipCurrent= false;
				else {
					*eol= '\0';
					Debug("handle message");
					ccl_handleMessage(self, start, eol-start);
				}
				// reset pointers for next search
				start= eol+1;
				eol= start;
			}
			// shift remainder to front of buffer
			if (start > buffer) {
				memmove(buffer, start, limit-start);
				limit-= (start-buffer);
				*limit= '\0';
				start= buffer;
			}
			// check for full buffer
			if (limit - buffer >= bufLen) {
				Error("Message exceeds maximum length.  Processing first %d bytes...\n", limit-buffer);
				// already NUL terminated
				ccl_handleMessage(self, buffer, limit-buffer);
				skipCurrent= true;
				limit= start= buffer;
			}
		} else if (got == 0) {
			Debug("reached eof");
			if (limit > buffer) {
				Warn("Partial message (%d bytes) received before EOF.  Processing fragment as message...\n", limit-buffer);
				// already NUL terminated
				ccl_handleMessage(self, buffer, limit-buffer);
				limit= buffer;
			}
			eof= true;
		} else if (errno == EINTR) {
			// continue
		} else {
			Error("read(stdin): %m");
			exit_runtime_fail();
		}
	}
	Debug("exiting gracefully");
	return 0;
}

bool ccl_addLogSpec(circulog_t* self, const char* suffix) {
	char name[256];
	int i;
	retention_category_t *cat;
	
	int len= (self->logBaseName? strlen(self->logBaseName) : 0)+strlen(suffix);
	if (len+1 > sizeof(name)) {
		Error("Log filename too long (%d)", len);
		return false;
	}
	name[0]= '\0';
	if (self->logBaseName) strcat(name, self->logBaseName);
	strcat(name, suffix);
	
	// see if the name is already used.
	// (not an error, just re-selects that log)
	for (i=0; i<self->categoryCount; i++) {
		if (strcmp(name, self->category[i].fileName) == 0) {
			// re-select it
			self->currentCategory= self->category+i;
			// and we're done
			return true;
		}
	}
	
	// It doesn't exist, so we create it
	self->category= realloc(self->category, (self->categoryCount+1) * sizeof(self->category[0]));
	if (!self->category) {
		Error("realloc(logSpec): %m");
		exit_runtime_fail();
	}
	memset(self->category+self->categoryCount, 0, sizeof(self->category[0]));
	
	// initialize new category
	cat= self->category + self->categoryCount;
	cat->fileName= strdup(name);
	if (!cat->fileName) {
		Error("strdup: %m");
		exit_runtime_fail();
	}
	cat->logSize= self->defaultLogSize;
	cat->maxMsgSize= self->defaultMaxMsgSize;
	cat->resizeLog= self->defaultResizeLog;
	
	// select it
	self->currentCategory= cat;
	self->categoryCount++;
	return true;
}

bool ccl_addPatternSpec(circulog_t* self, const char* spec) {
	const char *errmsg, *dispStart, *dispEnd;
	int errofs;
	
	if (!self->currentCategory) {
		Error("Cannot specify patterns before first '--log'\n");
		return false;
	}

	self->pattern= realloc(self->pattern, (self->patternCount+1) * sizeof(self->pattern[0]));
	if (!self->pattern) {
		Error("realloc(logSpec): %m");
		exit_runtime_fail();
	}
	memset(self->pattern+self->patternCount, 0, sizeof(self->pattern[0]));
	
	retention_pattern_t *pat= self->pattern+self->patternCount;
	pat->spec= spec;
	pat->pattern= pcre_compile(spec, 0, &errmsg, &errofs, NULL);
	if (!pat->pattern) {
		// Failed to compile.  Display a helpful syntax error.
		dispStart= (errofs>20)? spec+errofs-20 : spec;
		dispEnd= dispStart+strlen(dispStart);
		if (dispEnd - dispStart > 60) dispEnd= dispStart+60;
		Error("Invalid Regular Expression Syntax: %s\n %s%.*s%s\n    %*s\n",
			errmsg,
			dispStart==spec? "  \"":"...", dispEnd-dispStart, dispStart, *dispEnd? "...":"\"",
			errofs+1-(dispStart-spec), "^");
		exit(2);
	}
	pat->studyData= pcre_study(pat->pattern, 0, &errmsg);
	if (errmsg) {
		Error("\"pcre_study\" failed for \"%s\"", errmsg);
		exit_runtime_fail();
	}
	pat->replace= NULL; // not supported yet
	pat->destLogIdx= self->currentCategory - self->category;
	self->currentCategory->patternCount++;
	self->patternCount++;
	return true;
}

bool ccl_sanityCheck(circulog_t* self) {
	// Maximum message size must be less than 1/4 of the total log size
	int i;
	if (self->categoryCount == 0) {
		if (self->verbose >= 0)
			Error("no log files specified");
		return false;
	}
	
	for (i=0; i<self->categoryCount; i++) {
		if (self->category[i].maxMsgSize > (self->category[i].logSize>>2)) {
			Error("Maximum message size (%d) exceeds 1/4 of log size (%lld) for \"%s\"",
				self->category[i].maxMsgSize, self->category[i].logSize, self->category[i].fileName);
			return false;
		}
		if (self->category[i].maxMsgSize > 1024*1024) {
			Warn("Max message size of %d will cause circulog to allocate an inconveniently large buffer."
				"  Carefully consider whether you really want to allow messages this large.", self->category[i].maxMsgSize);
		}
	}
	return true;
}

bool ccl_openLogFiles(circulog_t* self) {
	retention_category_t *c;
	
	for (c= self->category; c < self->category+self->categoryCount; c++) {
		c->log= ccl_new();
		if (!c->log) {
			Error("malloc: %m");
			return false;
		}
		c->log->access= CCL_WRITE;
		c->log->max_message_size= c->maxMsgSize;
		Debug("Opening %s", c->fileName);
		if (ccl_open(c->log, c->fileName)) {
			// successfully opened, but check if the size is ok
			if (c->log->size < c->logSize) {
				if (c->resizeLog) {
					Notice("Resizing %s to %lld", c->fileName, c->logSize);
					if (!ccl_resize(c->log, c->fileName, c->logSize, false, false)) {
						char buf[256];
						Error("Failed to resize \"%s\": %s", c->fileName, ccl_err_text(c->log, buf, sizeof(buf)));
						return false;
					}
				}
				else if (c->maxMsgSize > (c->log->size >> 2)) {
					Error("Actual log size of \"%s\" is %lld, which is less than 4x the max message size (%d)",
						c->fileName, c->log->size, c->maxMsgSize);
					return false;
				}
				else {
					Notice("Actual log size of \"%s\" is smaller than requested \"%lld\"", c->fileName, c->log->size);
				}
			}
		}
		else {
			// failed to open the file.  See if the reason was that it didn't exist...
			if (c->log->last_err == CCL_ELOGOPEN && c->log->last_errno == ENOENT && self->createIfMissing) {
				Notice("Creating missing %s", c->fileName);
				if (!ccl_resize(c->log, c->fileName, c->logSize, true, false)) {
					char buf[256];
					Error("Failed to create \"%s\": %s", c->fileName, ccl_err_text(c->log, buf, sizeof(buf)));
					return false;
				}
			}
			else {
				char buf[256];
				Error("open %s: %s", c->fileName, ccl_err_text(c->log, buf, sizeof(buf)));
				return false;
			}
		}
	}
	return true;
}

bool ccl_handleMessage(circulog_t* self, const char* msg, int msgLen) {
	int ret;
	ccl_message_info_t msgi;
	retention_pattern_t *p;
	retention_category_t *c= NULL, *catchall= &self->category[self->categoryCount-1];
	int ovector[20*3];
	
	// We discard messages unless there is a log specified with no pattern requirements
	if (catchall->patternCount) catchall= NULL;
	
	if (self->patternCount) {
		for (p= self->pattern; p < self->pattern+self->patternCount; p++) {
			Trace("Matching vs %s", p->spec);
			ret= pcre_exec(p->pattern, p->studyData, msg, msgLen, 0, 0, ovector, sizeof(ovector)/sizeof(*ovector));
			if (ret >= 0) {
				c= self->category + p->destLogIdx;
				break;
			} else if (ret < -1) {
				Warn("Failed matching \"%s\" to \"%.*s\": %d (see man pcreapi)", p->spec, msgLen, msg, ret);
			}
		}
		if (!c) c= catchall;
	}
	else
		c= catchall;
	
	// If we matched a category, we write it, else discard it.
	if (c) {
		msgi.sizeof_struct= sizeof(msgi);
		msgi.timestamp= 0; // ask lib to run clock_gettime
		msgi.msg_len= msgLen;
		msgi.data_ofs= 0;
		msgi.data_len= msgLen;
		msgi.data= (void*) msg;
		if (!ccl_write_message(c->log, &msgi)) {
			char buf[256];
			Error("Failed to write message \"%.*s\" to \"%s\": %s", msgLen, msg, c->fileName, ccl_err_text(c->log, buf, sizeof(buf)));
			return false;
		}
	} else {
		Debug("Discarding message \"%.*s\"", msgLen, msg);
	}
	return true;
}

bool ccl_parseOptions(circulog_t* self, char** argv) {
	bool endOptions= false;
	char *bundle, *opt, *optval;
	while (*argv) {
		if (!endOptions && argv[0][0] == '-') {
			optval= NULL;
			if (argv[0][1] == '-') {
				if (argv[0][2] == '\0') {
					argv++;
					endOptions= true;
				}
				else {
					// long opt
					opt= *argv++;
					opt+= 2;
					optval= strchr(opt, '=');
					if (optval) *optval++= '\0';
					if (!ccl_processOption(self, '\xFF', opt, optval, &argv))
						return false;
				}
			} else {
				// process bundled short opts
				bundle= *argv++;
				++bundle;
				while (*bundle)
					if (!ccl_processOption(self, *bundle++, NULL, NULL, &argv))
							return false;
			}
		} else {
			optval= *argv++;
			if (optval[0] == '+') {
				// implied '-p'
				if (!ccl_processOption(self, '\xFF', "pattern", optval+1, &argv))
					return false;
			} else {
				// implied '-l'
				if (!ccl_processOption(self, '\xFF', "log", optval, &argv))
					return false;
			}
		}
	}
	return true;
}

bool checkVal(const char* name, bool wantVal, char** optValp, char*** argvp) {
	if (*optValp) {
		if (!wantVal) {
			fprintf(stderr, "Unexpected value given for option \"%s\"\n", name);
			return false;
		}
	} else {
		if (wantVal) {
			if (**argvp)
				*optValp= *(*argvp)++;
			else {
				fprintf(stderr, "Missing required value for option \"%s\"\n", name);
				return false;
			}
		}
	}
	return true;
}

static bool reportInvalid(const char *name, const char* value) {
	fprintf(stderr, "Invalid value \"%s\" for option \"%s\"\n", value, name);
	return false;
}

bool ccl_processOption(circulog_t *self, char shortOpt, char* longOpt, char* optVal, char*** argvp) {
	char buf[2]= { shortOpt, '\0' };
	char *name= longOpt? longOpt : buf;
	long long size;
	
	#define BEGINMATCH if (0) {
	#define CASE(short,long,wantval) } else if (shortOpt == short || (longOpt && strcmp(longOpt, long)==0)) { if (!checkVal(name,wantval,&optVal,argvp)) return false;
	#define ENDMATCH } else { fprintf(stderr, "Unknown option \"%s\"\n", name); return false; }
	#define BADVAL reportInvalid(name, optVal)
	
	BEGINMATCH
	CASE('h', "help", 0)
		exit_usage(1,1);
	
	CASE('V', "version", 0)
		exit_version();
	
	CASE('v', "verbose", 0)
		self->verbose++;
	
	CASE('q', "quiet", 0)
		self->verbose--;
	
	CASE('B', "base-name", 1)
		self->logBaseName= optVal;
	
	CASE('l', "log", 1)
		if (!ccl_addLogSpec(self, optVal))
			return BADVAL;
	
	CASE('p', "pattern", 1)
		if (!ccl_addPatternSpec(self, optVal))
			return BADVAL;
	
	CASE('s', "size", 1)
		if (!parseSize(&size, optVal))
			return BADVAL;
	
		if (self->currentCategory) {
			self->currentCategory->logSize= size;
		} else {
			self->defaultLogSize= size;
		}
	
	CASE('m', "max-msg", 1)
		if (!parseSize(&size, optVal))
			return BADVAL;
		
		// The file format uses 32-bit msg lengths, so this is a hard-limit.
		// Anything over a few MB is probably too big for practical reasons,
		//  but we check that in ccl_sanityCheck()
		if (size > 0xFFFFFFFFLL) {
			fprintf(stderr, "Max message size too large: %s", optVal);
			return false;
		}
		if (self->currentCategory) {
			self->currentCategory->maxMsgSize= (unsigned int) size;
		} else {
			self->defaultMaxMsgSize= (unsigned int) size;
		}
	
	CASE('R', "resize", 0)
		if (self->currentCategory) {
			self->currentCategory->resizeLog= true;
		} else {
			self->defaultResizeLog= true;
		}
	
	ENDMATCH
	
	// ENDMATCH reports invalid option names, so if we get here, all was good.
	return true;
}

bool parseInt(long* dest, char* src) {
	char *endptr= src;
	*dest= strtol(src, &endptr, 10);
	return !endptr[0];
}

bool parseSize(long long* dest, char* src) {
	char *endptr= src;
	long long num= strtoll(src, &endptr, 10);
	if (endptr[0] != '\0' && endptr[1] != '\0')
		return false;
	switch ((char)(*endptr & 0xDF /*uppercase*/)) {
	case 'T':
		num <<= 40;
		break;
	case 'G':
		num <<= 30;
		break;
	case 'M':
		num <<= 20;
		break;
	case 'K':
		num <<= 10;
		break;
	case '\0':
		break;
	default:
		return false;
	}
	*dest= num;
	return true;
}

void exit_version() {
	fprintf(stdout,
		"circulog %d.%d.%d-%d\n%s\n",
		(version_number>>24)&0xFF,
		(version_number>>16)&0xFF,
		(version_number>>8)&0xFF,
		(version_number)&0xFF,
		build_info
	);
	exit(1);
}

void exit_usage(int stream, int exitcode) {
	fprintf(stream==1? stdout:stderr,
		"circulog version %d.%d.%d\n\n"
		"Usage: circulog [options] [LOG_NAME [options], ...]\n"
		"  option summary:\n"
		"    -h --help            This help text\n"
		"    -V --version         Print version and build info\n"
		"    -v --verbose         Display debugging info\n"
		"    -q --quiet           Suppress warnings and error messages\n"
		"    -B --base-name NAME  Prefix for all log file names\n"
		"    -l --log NAME        Specify log filename (or suffix of -B)\n"
		"    -s --size SIZE       (per-log) Specify the size of the log\n"
		"    -m --max-msg SIZE    (per-log) Specify the max message size\n"
		"    -R --resize          (per-log) Force the log file to be resized\n"
		"    -p --pattern PATTERN (per-log, multiple) Add a pattern to previous '--log'\n"
		"\n"
		"  Bare arguments are interpreted as '--log' unless they start with '+' in which\n"
		"    case they are interpreted as '--pattern'\n"
		"  Options marked as \"per-log\" will affect the preceeding '--log' file,\n"
		"    or they will affect the default if no '--log' options have been given yet.\n"
		"  Pattens are of the form /REGEX[/REPLACE]/FLAG\n"
		"    much like the syntax for sed or perl. ( '/foo/i', '/foo/bar/ig', etc )\n"
		"  Patterns are checked in sequential order. (but a log may be re-specified\n"
		"    in order to direct additional patterns to it)\n"
		"  Messages matching the pattern are immediately written to the previous\n"
		"    specified '--log' and execution resumes with the next message.\n"
		"  The final '--log' is the default for all messages which did not match a pattern.\n"
		"\n"
		"  Example: circulog -B /var/log/foo -m 1024 .err.cl -s 3M -p '/^ERROR:/i' .cl -s 1M\n"
		"\n",
		(version_number>>24)&0xFF,
		(version_number>>16)&0xFF,
		(version_number>>8)&0xFF
	);
	exit(exitcode);
}

void exit_runtime_fail() {
	fprintf(stderr, "ERROR: Unrecoverable, exiting.\n");
	abort();
}
