#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
/* Windows-specific includes */
#include <Windows.h>
/* Windows doesn't have unistd.h or getopt.h, use a third-party implementation */
#include "../include/getopt_win.h"
#else
/* Unix-specific includes */
#include <unistd.h>
#include <getopt.h>
#endif

#include <openssl/sha.h>

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
    
    /* Set global verbose mode based on command-line options */
    set_verbose_mode(opts.verbose);
    
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
    echeck_quote_t *quote_obj = extract_quote(cert);

    if (!quote_obj) {
        fprintf(stderr, "Error: No SGX Quote extension found in certificate\n");
        free_certificate(cert);
        return 1;
    }

    if (!opts.quiet) {
        if (opts.verbose) {
            fprintf(stderr, "SGX Quote extracted\n");
        }
    }

    /* Get quote info */
    echeck_quote_info_t quote_info;
    if (!get_quote_info(quote_obj, &quote_info)) {
        fprintf(stderr, "Error: Failed to get quote info\n");
        free_quote(quote_obj);
        free_certificate(cert);
        return 1;
    }

    /* We don't need direct access to the quote structure anymore */
    
    /* Use the verification API to verify the quote */
    echeck_verification_result_t verify_result;
    if (!verify_quote(cert, quote_obj, &verify_result)) {
        fprintf(stderr, "Error: Quote verification failed\n");
        if (verify_result.error_message) {
            fprintf(stderr, "%s\n", verify_result.error_message);
        }
        free_quote(quote_obj);
        free_certificate(cert);
        return 1;
    }

    if (opts.verbose && !opts.quiet) {
        fprintf(stdout, "Quote verification successful\n");
    }

    /* Verify custom MRENCLAVE if specified */
    if (opts.mrenclave) {
        unsigned char expected_mrenclave[32];
        if (!hex_to_bin(opts.mrenclave, expected_mrenclave, sizeof(expected_mrenclave))) {
            fprintf(stderr, "Error: Invalid MRENCLAVE format (expected 64 hex characters)\n");
            free_quote(quote_obj);
            free_certificate(cert);
            return 1;
        }

        if (memcmp(quote_info.mr_enclave, expected_mrenclave, sizeof(expected_mrenclave)) != 0) {
            fprintf(stderr, "Error: MRENCLAVE value does not match expected value\n");
            free_quote(quote_obj);
            free_certificate(cert);
            return 1;
        }

        if (opts.verbose && !opts.quiet) {
            fprintf(stdout, "MRENCLAVE verification passed\n");
        }
    }

    /* Verify custom MRSIGNER if specified */
    if (opts.mrsigner) {
        unsigned char expected_mrsigner[32];
        if (!hex_to_bin(opts.mrsigner, expected_mrsigner, sizeof(expected_mrsigner))) {
            fprintf(stderr, "Error: Invalid MRSIGNER format (expected 64 hex characters)\n");
            free_quote(quote_obj);
            free_certificate(cert);
            return 1;
        }

        if (memcmp(quote_info.mr_signer, expected_mrsigner, sizeof(expected_mrsigner)) != 0) {
            fprintf(stderr, "Error: MRSIGNER value does not match expected value\n");
            free_quote(quote_obj);
            free_certificate(cert);
            return 1;
        }

        if (opts.verbose && !opts.quiet) {
            fprintf(stdout, "MRSIGNER verification passed\n");
        }
    }
    
    /* Print verification results based on output mode */
    if (opts.raw) {
        /* Raw output format for machine readability */
        fprintf(stdout, "mrenclave=");
        for (int i = 0; i < 32; i++) {
            fprintf(stdout, "%02x", quote_info.mr_enclave[i]);
        }
        fprintf(stdout, "\n");

        fprintf(stdout, "mrsigner=");
        for (int i = 0; i < 32; i++) {
            fprintf(stdout, "%02x", quote_info.mr_signer[i]);
        }
        fprintf(stdout, "\n");

        fprintf(stdout, "isvprodid=%d\n", quote_info.isv_prod_id);
        fprintf(stdout, "isvsvn=%d\n", quote_info.isv_svn);
    } else if (!opts.quiet) {
        /* Normal Unix-like output with optional verbosity */
        if (opts.verbose) {
            fprintf(stdout, "SGX Quote verification successful\n");
            fprintf(stdout, "MRENCLAVE: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", quote_info.mr_enclave[i]);
            }
            fprintf(stdout, "\n");

            fprintf(stdout, "MRSIGNER: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", quote_info.mr_signer[i]);
            }
            fprintf(stdout, "\n");

            fprintf(stdout, "ISV Product ID: %d\n", quote_info.isv_prod_id);
            fprintf(stdout, "ISV SVN: %d\n", quote_info.isv_svn);
        } else {
            /* Simple verification success message */
            fprintf(stdout, "SGX quote verification successful\n");
        }
    }

    /* Cleanup */
    free_quote(quote_obj);
    free_certificate(cert);
    
    /* 
     * Modern OpenSSL (3.0+) doesn't need explicit cleanup calls. 
     * The following deprecated functions are no longer needed:
     * - EVP_cleanup()
     * - ERR_free_strings()
     *
     * OpenSSL 3.0+ handles cleanup automatically.
     */
    
    return 0;
}