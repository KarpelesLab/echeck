#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "echeck.h"

/* Command-line options */
struct options {
    int verbose;
    int quiet;
    int raw;
    char *mrenclave;
    char *mrsigner;
    char *cert_file;
};

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [OPTIONS] <certificate.pem>\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help              Display this help message\n");
    fprintf(stderr, "  -v, --verbose           Verbose output\n");
    fprintf(stderr, "  -q, --quiet             Quiet mode (only errors)\n");
    fprintf(stderr, "  -r, --raw               Raw output (no formatting)\n");
    fprintf(stderr, "  --mrenclave=<hash>      Verify specific MRENCLAVE value (hex)\n");
    fprintf(stderr, "  --mrsigner=<hash>       Verify specific MRSIGNER value (hex)\n");
}

/* Convert hex string to binary */
int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    
    /* Each byte needs 2 hex characters */
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) {
        return 0;
    }
    
    for (size_t i = 0; i < hex_len; i += 2) {
        char hex_byte[3] = {hex[i], hex[i+1], 0};
        char *endptr;
        bin[i/2] = (unsigned char)strtol(hex_byte, &endptr, 16);
        
        /* If endptr doesn't point to the end of the string, conversion failed */
        if (*endptr != '\0') {
            return 0;
        }
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    struct options opts = {0};
    int opt, option_index = 0;
    
    struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"verbose",   no_argument,       0, 'v'},
        {"quiet",     no_argument,       0, 'q'},
        {"raw",       no_argument,       0, 'r'},
        {"mrenclave", required_argument, 0, 'e'},
        {"mrsigner",  required_argument, 0, 's'},
        {0, 0, 0, 0}
    };
    
    /* Parse command-line options */
    while ((opt = getopt_long(argc, argv, "hvqr", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                opts.verbose = 1;
                break;
            case 'q':
                opts.quiet = 1;
                break;
            case 'r':
                opts.raw = 1;
                break;
            case 'e':
                opts.mrenclave = optarg;
                break;
            case 's':
                opts.mrsigner = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Ensure there's at least one non-option argument (certificate file) */
    if (optind >= argc) {
        fprintf(stderr, "Error: Certificate file is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Get certificate file path */
    opts.cert_file = argv[optind];
    
    /* Set global verbose flag based on command-line options */
    global_verbose_flag = opts.verbose;
    
    /* Initialize OpenSSL (using runtime linking if enabled) */
    if (!initialize_openssl()) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL\n");
        return 1;
    }
    
    /* Load certificate */
    void *cert = load_certificate(opts.cert_file);
    if (!cert) {
        fprintf(stderr, "Error: Failed to load certificate from %s\n", opts.cert_file);
        return 1;
    }
    
    /* Extract SGX quote */
    echeck_quote_t *quote = extract_quote(cert);
    if (!quote) {
        fprintf(stderr, "Error: No SGX Quote extension found in certificate\n");
        free_certificate(cert);
        return 1;
    }

    if (!opts.quiet && opts.verbose) {
        fprintf(stderr, "SGX Quote extracted successfully\n");
    }
    
    /* Get quote information */
    echeck_quote_info_t info;
    if (!get_quote_info(quote, &info)) {
        fprintf(stderr, "Error: Failed to get quote information\n");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }
    
    /* Verify the quote */
    echeck_verification_result_t result;
    if (!verify_quote(cert, quote, &result)) {
        fprintf(stderr, "Error: Failed to verify quote\n");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }
    
    if (!result.valid) {
        fprintf(stderr, "Error: SGX quote verification failed: %s\n", 
                result.error_message ? result.error_message : "Unknown error");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }

    /* Verify custom MRENCLAVE and MRSIGNER if specified */
    if (opts.mrenclave || opts.mrsigner) {
        unsigned char expected_mrenclave[32] = {0};
        unsigned char expected_mrsigner[32] = {0};
        
        /* Parse MRENCLAVE if provided */
        if (opts.mrenclave) {
            if (!hex_to_bin(opts.mrenclave, expected_mrenclave, sizeof(expected_mrenclave))) {
                fprintf(stderr, "Error: Invalid MRENCLAVE format (expected 64 hex characters)\n");
                free_quote(quote);
                free_certificate(cert);
                return 1;
            }
        }
        
        /* Parse MRSIGNER if provided */
        if (opts.mrsigner) {
            if (!hex_to_bin(opts.mrsigner, expected_mrsigner, sizeof(expected_mrsigner))) {
                fprintf(stderr, "Error: Invalid MRSIGNER format (expected 64 hex characters)\n");
                free_quote(quote);
                free_certificate(cert);
                return 1;
            }
        }
        
        /* Verify against expected values */
        if (!verify_quote_measurements(quote, 
                                      opts.mrenclave ? expected_mrenclave : NULL, 
                                      opts.mrsigner ? expected_mrsigner : NULL)) {
            fprintf(stderr, "Error: Measurements verification failed\n");
            free_quote(quote);
            free_certificate(cert);
            return 1;
        }
        
        if (!opts.quiet && opts.verbose) {
            if (opts.mrenclave) {
                fprintf(stdout, "MRENCLAVE verification passed\n");
            }
            if (opts.mrsigner) {
                fprintf(stdout, "MRSIGNER verification passed\n");
            }
        }
    }
    
    /* Print verification results based on output mode */
    if (opts.raw) {
        /* Raw output format for machine readability */
        fprintf(stdout, "mrenclave=");
        for (int i = 0; i < 32; i++) {
            fprintf(stdout, "%02x", info.mr_enclave[i]);
        }
        fprintf(stdout, "\n");
        
        fprintf(stdout, "mrsigner=");
        for (int i = 0; i < 32; i++) {
            fprintf(stdout, "%02x", info.mr_signer[i]);
        }
        fprintf(stdout, "\n");
        
        fprintf(stdout, "isvprodid=%d\n", info.isv_prod_id);
        fprintf(stdout, "isvsvn=%d\n", info.isv_svn);
    } else if (!opts.quiet) {
        /* Normal Unix-like output with optional verbosity */
        if (opts.verbose) {
            fprintf(stdout, "SGX Quote verification successful\n");
            fprintf(stdout, "MRENCLAVE: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", info.mr_enclave[i]);
            }
            fprintf(stdout, "\n");
            
            fprintf(stdout, "MRSIGNER: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", info.mr_signer[i]);
            }
            fprintf(stdout, "\n");
            
            fprintf(stdout, "ISV Product ID: %d\n", info.isv_prod_id);
            fprintf(stdout, "ISV SVN: %d\n", info.isv_svn);
        } else {
            /* Simple verification success message */
            fprintf(stdout, "SGX quote verification successful\n");
        }
    }
    
    /* Cleanup */
    free_quote(quote);
    free_certificate(cert);
    
    return 0;
}