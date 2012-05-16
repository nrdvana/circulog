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
	bool wantHelp;
	bool wantVersion;
	const char* targetFname;
	bool quickTS;
	long long logSize;
	int maxMsgSize;
	bool createIfMissing;
	bool forceCreate;
	const char** logSpec;
	const char** logPattern;
} options_t;

static options_t opts;

typedef struct {
	char shortName;
	char* longName;
	char type;
	void* dest;
} option_spec_t;

static const option_spec_t optionSpec[]= {
	{ 'h', "help",     'b', &opts.wantHelp },
	{ 'v', "version",  'b', &opts.wantVersion },
	{ 'l', "logfile",  '[', &opts.logSpec },
	{ 'p', "pattern",  '[', &opts.logPattern },
};

typedef struct {
	const char* fileSuffix;
	int fd;
	long long fileSize;
	int maxMsgSize;
} retention_category_t;

#ifdef CONFIG_PCRE
typedef struct {
	pcre* pattern;
	const char* replace;
	int retention_category;
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
	options_t *opts;
	int categoryCount;
	retention_category_t *category;
	int patternCount;
	retention_pattern_t *pattern;
	int maxMsgSize;
} circulog_t;

bool ccl_parseLogSpec(circulog_t* self, const char* spec);
bool ccl_parsePatternSpec(circulog_t* self, const char* spec);
bool ccl_sanityCheck(circulog_t* self);
bool ccl_openLogFiles(circulog_t* self);
bool ccl_handleMessage(circulog_t* self, const char* msg, int msgLen);

extern int version_number;
extern const char* build_info;

bool parseOptions(char** argv);
bool processOption(char shortOpt, char* longOpt, char* optVal, char*** argv);
bool parseInt(long* dest, char* src);
bool parseSize(long long* dest, char* src);
void exit_usage(int stream, int exitcode);
void exit_version();
void exit_runtime_fail();

int main(int argc, char** argv) {
	const char **item;
	char *start, *limit, *eol;
	int i, got;
	bool eof, skipCurrent;
	circulog_t self;
	
	memset(&opts, 0, sizeof(opts));
	opts.maxMsgSize= 4095; // 4kb, -1 for NUL terminator
	opts.logSize= -1;      // use default
	opts.createIfMissing= true;
	
	memset(&self, 0, sizeof(self));
	self.opts= &opts;
	
	if (!parseOptions(argv+1))
		exit_usage(2, 2);
	if (opts.wantHelp) exit_usage(1,1);
	if (opts.wantVersion) exit_version();
	
	for (item= opts.logSpec; item && *item; item++) {
		if (!ccl_parseLogSpec(&self, *item))
			exit_usage(2, 2);
	}
	for (item= opts.logPattern; item && *item; item++) {
		if (!ccl_parsePatternSpec(&self, *item))
			exit_usage(2, 2);
	}
	
	if (!ccl_sanityCheck(&self)) {
		fprintf(stderr, "ERROR: Configuration is invalid, exiting\n");
		return 2;
	}
	
	if (!ccl_openLogFiles(&self)) {
		exit_runtime_fail();
	}
	
	char* buffer= malloc(self.maxMsgSize+1);
	if (!buffer) {
		perror("malloc(msgbuf)");
		exit_runtime_fail();
	}
	
	start= limit= buffer;
	skipCurrent= false;
	while (!eof) {
		got= read(0, limit, self.maxMsgSize - (limit-buffer));
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
			if (limit - buffer >= self.maxMsgSize) {
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

bool ccl_parseLogSpec(circulog_t* self, const char* spec) {
	return false;
}

bool ccl_parsePatternSpec(circulog_t* self, const char* spec) {
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

bool parseOptions(char** argv) {
	bool endOptions= false;
	char *bundle, *opt, *optval, *endptr;
	while (*argv) {
		fprintf(stderr, "opt=%s endOptions=%d\n", *argv, endOptions);
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
					if (!processOption('\xFF', opt, optval, &argv))
						return false;
				}
			} else {
				// process bundled short opts
				bundle= *argv++;
				++bundle;
				while (*bundle)
					if (!processOption(*bundle++, NULL, NULL, &argv))
							return false;
			}
		} else {
			if (opts.targetFname) {
				fprintf(stderr, "Only one filename allowed (at argument \"%s\")\n", argv[0]);
				return false;
			}
			opts.targetFname= *argv++;
		}
	}
	return true;
}

bool processOption(char shortOpt, char* longOpt, char* optVal, char*** argv) {
	int i, count;
	char **array, **item;
	char buf[2]= { shortOpt, '\0' };
	char *name= longOpt? longOpt : buf;
	bool parsed;
	
	for (i=sizeof(optionSpec)/sizeof(*optionSpec) - 1; i >= 0; i--) {
		if (optionSpec[i].shortName == shortOpt || (longOpt && strcmp(optionSpec[i].longName, longOpt)==0)) {
			if (optionSpec[i].type == 'b') {
				if (optVal) {
					fprintf(stderr, "Unexpected value given for option \"%s\"\n", name);
					return false;
				}
				
				*((bool*) optionSpec[i].dest)= true;
				
			} else {
				// option required for all but boolean
				if (!optVal) {
					if (**argv)
						optVal= *(*argv)++;
					else {
						fprintf(stderr, "Missing required value for option \"%s\"\n", name);
						return false;
					}
				}
				
				parsed= false;
				switch (optionSpec[i].type) {
				case 'i': // int
					parsed= parseInt((long *)optionSpec[i].dest, optVal);
					break;
				case 's': // string
					*((char const **) optionSpec[i].dest)= optVal;
					parsed= true;
					break;
				case 'S': // Size
					parsed= parseSize((long long *)optionSpec[i].dest, optVal);
					break;
				case '[': // array of string
					array= *((char***)optionSpec[i].dest);
					for (item= array; item && *item; item++);
					count= item - array;
					array= (char**) realloc(array, (count+2)*sizeof(const char*));
					if (!array) {
						perror("malloc(spec)");
						abort();
					}
					array[count]= optVal;
					array[count+1]= NULL;
					*((char***)optionSpec[i].dest)= array;
					parsed= true;
				default:  // error in spec
					fprintf(stderr, "(internal error)\n");
					exit(-1);
				}
					
				if (!parsed) {
					fprintf(stderr, "Invalid value \"%s\" for option \"%s\"\n", optVal, name);
					return false;
				}
			}
			return true;
		}
	}
	
	fprintf(stderr, "Unknown option \"%s\"\n", name);
	return false;
}

bool parseInt(long* dest, char* src) {
	char *endptr= src;
	*dest= strtol(src, &endptr, 10);
	return !endptr[0];
}

bool parseSize(long long* dest, char* src) {
	char *endptr= src;
	long long num= strtoll(src, &endptr, 10);
	switch (*endptr) {
	case 'T': if (strcmp(endptr, "T")) return false;
		num <<= 40;
		break;
	case 'G': if (strcmp(endptr, "G")) return false;
		num <<= 30;
		break;
	case 'M': if (strcmp(endptr, "M")) return false;
		num <<= 20;
		break;
	case 'K': if (strcmp(endptr, "K")) return false;
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
		"\ncirculog version %d.%d.%d\n\n"
		"Usage: circulog [options] LOG_NAME\n"
		"  option summary:\n",
		(version_number>>24)&0xFF,
		(version_number>>16)&0xFF,
		(version_number>>8)&0xFF
	);
	for (i=0; i < (sizeof(optionSpec)/sizeof(*optionSpec)); i++) {
		fprintf(stream==1? stdout:stderr,
			"  %c%c --%s\n", optionSpec[i].shortName? '-':' ', optionSpec[i].shortName? optionSpec[i].shortName :' ',
				optionSpec[i].longName, optionSpec[i].type == 'b'? "" : "=VALUE");
	}
	fprintf(stream == 1? stdout:stderr, "\n");
	exit(exitcode);
}

void exit_runtime_fail() {
	fprintf(stderr, "ERROR: Unrecoverable, exiting.\n");
	abort();
}
