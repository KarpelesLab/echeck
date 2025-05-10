#ifndef GETOPT_WIN_H
#define GETOPT_WIN_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal getopt implementation for Windows.
 * This provides just enough functionality to support the main.c code.
 */

/* Option structure for getopt_long */
struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

/* Values for the 'has_arg' field */
#define no_argument        0
#define required_argument  1
#define optional_argument  2

/* External variables needed by getopt implementation */
extern char *optarg;
extern int optind, opterr, optopt;

/* Function declarations */
int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

/* Implementation of external variables */
#ifndef GETOPT_IMPLEMENTATION_DEFINED
#define GETOPT_IMPLEMENTATION_DEFINED

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = '?';

/* Implementation of getopt */
int getopt(int argc, char * const argv[], const char *optstring) {
    static int optpos = 1;
    const char *arg;
    
    /* Reset optind at the beginning */
    if (optind == 0) {
        optind = 1;
        optpos = 1;
    }
    
    /* Check if we're done or the current argument doesn't start with a dash */
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;
    }
    
    /* Special case for "--" argument (end of options) */
    if (argv[optind][1] == '-' && argv[optind][2] == '\0') {
        optind++;
        return -1;
    }
    
    /* Get the option character */
    optopt = argv[optind][optpos++];
    
    /* Find the option in optstring */
    arg = strchr(optstring, optopt);
    
    /* Unknown option or missing argument */
    if (!arg) {
        if (opterr && *optstring != ':') {
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], optopt);
        }
        /* If we've processed all characters in this option, move to the next one */
        if (argv[optind][optpos] == '\0') {
            optind++;
            optpos = 1;
        }
        return '?';
    }
    
    /* Option takes an argument */
    if (arg[1] == ':') {
        if (argv[optind][optpos] != '\0') {
            /* Argument is the rest of the current arg */
            optarg = &argv[optind][optpos];
            optind++;
            optpos = 1;
        } else if (arg[2] == ':' || optind + 1 >= argc) {
            /* Optional argument not present */
            optarg = NULL;
            optind++;
            optpos = 1;
            if (arg[2] != ':' && *optstring != ':') {
                if (opterr) {
                    fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], optopt);
                }
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            /* Argument is the next arg */
            optarg = argv[optind + 1];
            optind += 2;
            optpos = 1;
        }
    } else {
        /* Option doesn't take an argument */
        optarg = NULL;
        /* If we've processed all characters in this option, move to the next one */
        if (argv[optind][optpos] == '\0') {
            optind++;
            optpos = 1;
        }
    }
    
    return optopt;
}

/* Implementation of getopt_long */
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    /* Check if this argument starts with "--" (long option) */
    if (optind < argc && argv[optind][0] == '-' && argv[optind][1] == '-') {
        int i;
        char *option = argv[optind] + 2;
        char *value = NULL;
        size_t option_len;
        
        /* Handle special case "--" (end of options) */
        if (*option == '\0') {
            optind++;
            return -1;
        }
        
        /* See if the option has a value after '=' */
        value = strchr(option, '=');
        if (value) {
            option_len = value - option;
            value++; /* Skip the '=' */
        } else {
            option_len = strlen(option);
        }
        
        /* Find the matching long option */
        for (i = 0; longopts[i].name; i++) {
            if (strncmp(longopts[i].name, option, option_len) == 0 && 
                longopts[i].name[option_len] == '\0') {
                
                /* Set the index of the matched option */
                if (longindex) {
                    *longindex = i;
                }
                
                /* Handle arguments */
                if (longopts[i].has_arg == required_argument || 
                    longopts[i].has_arg == optional_argument) {
                    if (value) {
                        /* Value provided after '=' */
                        optarg = value;
                    } else if (longopts[i].has_arg == required_argument) {
                        /* Required argument should be the next parameter */
                        if (optind + 1 < argc) {
                            optarg = argv[optind + 1];
                            optind++;
                        } else {
                            /* Missing required argument */
                            if (opterr && *optstring != ':') {
                                fprintf(stderr, "%s: option '--%s' requires an argument\n",
                                        argv[0], longopts[i].name);
                            }
                            optopt = longopts[i].val;
                            optind++;
                            return *optstring == ':' ? ':' : '?';
                        }
                    } else {
                        /* Optional argument not provided */
                        optarg = NULL;
                    }
                } else {
                    /* No argument expected */
                    if (value) {
                        /* Unexpected argument */
                        if (opterr) {
                            fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n",
                                    argv[0], longopts[i].name);
                        }
                        optind++;
                        return '?';
                    }
                    optarg = NULL;
                }
                
                optind++;
                
                /* If flag is set, store val there and return 0, otherwise return val */
                if (longopts[i].flag) {
                    *(longopts[i].flag) = longopts[i].val;
                    return 0;
                } else {
                    return longopts[i].val;
                }
            }
        }
        
        /* Unknown option */
        if (opterr) {
            fprintf(stderr, "%s: unrecognized option '--%s'\n", argv[0], option);
        }
        optind++;
        return '?';
    }
    
    /* Not a long option, use regular getopt */
    return getopt(argc, argv, optstring);
}

#endif /* GETOPT_IMPLEMENTATION_DEFINED */

#ifdef __cplusplus
}
#endif

#endif /* GETOPT_WIN_H */