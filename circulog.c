#include "circulog.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// For now, we require PCRE.  I'd like to make it optional in the future.
#define CONFIG_PCRE

#ifdef CONFIG_PCRE
#include <pcre.h>
#endif

typedef struct {
	const char* fileName;
	int fd;
	long long logSize;
	int maxMsgSize;
	bool resizeLog;
} retention_category_t;

#ifdef CONFIG_PCRE
typedef struct {
	pcre* pattern;
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
extern const char* build_info;

bool parseInt(long* dest, char* src);
bool parseSize(long long* dest, char* src);
void exit_usage(int stream, int exitcode);
void exit_version();
void exit_runtime_fail();

int main(int argc, char** argv) {
	const char **item;
	char *buffer, *start, *limit, *eol;
	int i, got, bufLen;
	bool eof, skipCurrent;
	circulog_t self;
	
	memset(&self, 0, sizeof(self));
	self.defaultMaxMsgSize= DEFAULT_MAX_MESSAGE_SIZE;
	self.defaultLogSize= DEFAULT_LOG_SIZE;
	self.createIfMissing= true;
	
	if (!ccl_parseOptions(&self, argv+1))
		exit_usage(2, 2);
	
	if (!ccl_sanityCheck(&self)) {
		fprintf(stderr, "ERROR: Configuration is invalid, exiting\n");
		return 2;
	}
	
	if (!ccl_openLogFiles(&self)) {
		exit_runtime_fail();
	}
	
	bufLen= 0;
	for (i= 0; i < self.categoryCount; i++)
		if (self.category[i].maxMsgSize > bufLen)
			bufLen= self.category[i].maxMsgSize+1;
	buffer= malloc(bufLen);
	if (!buffer) {
		perror("malloc(msgbuf)");
		exit_runtime_fail();
	}
	
	start= limit= buffer;
	skipCurrent= false;
	while (!eof) {
		got= read(0, limit, bufLen-1 - (limit-buffer));
		if (got > 0) {
			eol= limit;   // start the search from here
			limit += got;
			*limit= '\0';
			// now see how many lines (messages) we can make from the buffer
			while (eol= strchr(eol, '\n')) {
				// handle message
				if (skipCurrent)
					skipCurrent= false;
				else {
					*eol= '\0';
					ccl_handleMessage(&self, start, eol-start);
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
				fprintf(stderr, "ERROR: Message exceeds maximum length.  Processing first %d bytes...\n", limit-buffer);
				// already NUL terminated
				ccl_handleMessage(&self, buffer, limit-buffer);
				skipCurrent= true;
				limit= start= buffer;
			}
		} else if (got == 0) {
			if (limit > buffer) {
				fprintf(stderr, "WARN: Partial message (%d bytes) received before EOF.  Processing fragment as message...\n", limit-buffer);
				// already NUL terminated
				ccl_handleMessage(&self, buffer, limit-buffer);
				limit= buffer;
			}
			eof= true;
		} else if (errno == EAGAIN || errno == EINTR) {
			// continue
		} else {
			perror("read(stdin)");
			exit_runtime_fail();
		}
	}
	
	return 0;
}

bool ccl_addLogSpec(circulog_t* self, const char* suffix) {
	char name[256];
	int i;
	retention_category_t *cat;
	
	int len= (self->logBaseName? strlen(self->logBaseName) : 0)+strlen(suffix);
	if (len+1 > sizeof(name)) {
		fprintf(stderr, "Log filename too long (%d)", len);
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
		perror("realloc(logSpec)");
		exit_runtime_fail();
	}
	
	// initialize new category
	cat= self->category + self->categoryCount;
	cat->fileName= strdup(name);
	if (!cat->fileName) {
		perror("strdup");
		exit_runtime_fail();
	}
	cat->fd= -1;
	cat->logSize= self->defaultLogSize;
	cat->maxMsgSize= self->defaultMaxMsgSize;
	cat->resizeLog= self->defaultResizeLog;
	
	// select it
	self->currentCategory= cat;
	self->categoryCount++;
	return true;
}

bool ccl_addPatternSpec(circulog_t* self, const char* spec) {
	// format is ident:/regex/[replacement/][flags]
	return false;
}

bool ccl_sanityCheck(circulog_t* self) {
	return false;
}

bool ccl_openLogFiles(circulog_t* self) {
	return false;
}

bool ccl_handleMessage(circulog_t* self, const char* msg, int msgLen) {
	return false;
}

bool ccl_parseOptions(circulog_t* self, char** argv) {
	bool endOptions= false;
	char *bundle, *opt, *optval, *endptr;
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
			// implied '-l'
			optval= *argv++;
			if (!ccl_processOption(self, '\xFF', "log", optval, &argv))
				return false;
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
	int i, count;
	char **array, **item;
	char buf[2]= { shortOpt, '\0' };
	char *name= longOpt? longOpt : buf;
	long long size;
	bool parsed;
	
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
	
	// If we didn't return true, it means optVal is invalid.
	// (ENDMATCH reports invalid option names)
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
	int i;
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
		"  Bare arguments are interpreted as '--log'.\n"
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
