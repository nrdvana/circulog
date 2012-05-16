#include "circulog.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
	bool wantHelp;
	bool wantVersion;
	const char* targetFname;
	bool quickTS;
	long long logSize;
	int maxMsgSize;
	bool createIfMissing;
	bool forceCreate;
} options_t;

static options_t opts;

typedef struct {
	char shortName;
	char* longName;
	char type;
	void* dest;
} option_spec_t;

static const option_spec_t optionSpec[]= {
	{ 'h', "help",    'b', &opts.wantHelp },
	{ 'v', "version", 'b', &opts.wantVersion },
};

static int VERSION= 0;

bool parseOptions(char** argv);
void exit_usage(int stream, int exitcode);
void exit_version();

int main(int argc, char** argv) {
	memset(&opts, 0, sizeof(opts));
	if (!parseOptions(argv+1))
		exit_usage(2, 2);
	if (opts.wantHelp) exit_usage(1,1);
	if (opts.wantVersion) exit_version();
	return 0;
}

bool processOption(char shortOpt, char* longOpt, char* optVal, char*** argv);

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

bool parseInt(long* dest, char* src);
bool parseSize(long long* dest, char* src);

bool processOption(char shortOpt, char* longOpt, char* optVal, char*** argv) {
	int i;
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
					*((const char**) optionSpec[i].dest)= optVal;
					parsed= true;
					break;
				case 'S': // Size
					parsed= parseSize((long long *)optionSpec[i].dest, optVal);
					break;
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
		"circulog version %d.%d.%d-%d\n",
		(VERSION>>24)&0xFF,
		(VERSION>>16)&0xFF,
		(VERSION>>8)&0xFF,
		(VERSION)&0xFF
	);
	exit(1);
}

void exit_usage(int stream, int exitcode) {
	int i;
	fprintf(stream==1? stdout:stderr,
		"\ncirculog version %d.%d.%d-%d\n\n"
		"Usage: circulog [options] LOG_NAME\n"
		"  option summary:\n",
		(VERSION>>24)&0xFF,
		(VERSION>>16)&0xFF,
		(VERSION>>8)&0xFF,
		(VERSION)&0xFF
	);
	for (i=0; i < (sizeof(optionSpec)/sizeof(*optionSpec)); i++) {
		fprintf(stream==1? stdout:stderr,
			"  %c%c --%s\n", optionSpec[i].shortName? '-':' ', optionSpec[i].shortName? optionSpec[i].shortName :' ',
				optionSpec[i].longName, optionSpec[i].type == 'b'? "" : "=VALUE");
	}
	fprintf(stream == 1? stdout:stderr, "\n");
	exit(exitcode);
}
