#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "echeck.h"
#include "echeck_internal.h"

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
    X509 *cert = load_certificate(opts.cert_file);
    if (!cert) {
        fprintf(stderr, "Error: Failed to load certificate from %s\n", opts.cert_file);
        return 1;
    }
    
    /* Extract SGX quote */
    sgx_quote_buffer_t quote_buffer = {0};
    
    if (!extract_sgx_quote(cert, &quote_buffer)) {
        fprintf(stderr, "Error: No SGX Quote extension found in certificate\n");
        X509_free(cert);
        return 1;
    }

    if (!opts.quiet) {
        if (opts.verbose) {
            fprintf(stderr, "SGX Quote extracted: %d bytes\n", quote_buffer.length);
        }
    }
    
    /* Calculate hash of certificate's public key */
    unsigned char pubkey_hash[SHA256_DIGEST_LENGTH];
    unsigned int pubkey_hash_len = 0;
    
    if (!compute_pubkey_hash(cert, pubkey_hash, &pubkey_hash_len)) {
        fprintf(stderr, "Error: Failed to compute public key hash\n");
        free(quote_buffer.data);
        X509_free(cert);
        return 1;
    }
    
    /* Get quote structure */
    const sgx_quote_t *quote = (const sgx_quote_t *)quote_buffer.data;
    
    /* Verify report data matches certificate public key hash */
    if (!verify_report_data(quote, pubkey_hash, pubkey_hash_len)) {
        fprintf(stderr, "Error: Report data does not match certificate public key hash\n");
        fprintf(stderr, "The enclave that created this quote did not know this certificate's public key\n");
        free(quote_buffer.data);
        X509_free(cert);
        return 1;
    }
    
    if (opts.verbose && !opts.quiet) {
        fprintf(stdout, "Certificate public key hash verified: ");
        for (int i = 0; i < pubkey_hash_len; i++) {
            fprintf(stdout, "%02x", pubkey_hash[i]);
        }
        fprintf(stdout, "\n");
    }

    /* Verify custom MRENCLAVE if specified */
    if (opts.mrenclave) {
        unsigned char expected_mrenclave[32];
        if (!hex_to_bin(opts.mrenclave, expected_mrenclave, sizeof(expected_mrenclave))) {
            fprintf(stderr, "Error: Invalid MRENCLAVE format (expected 64 hex characters)\n");
            free(quote_buffer.data);
            X509_free(cert);
            return 1;
        }
        
        if (memcmp(quote->report_body.mr_enclave, expected_mrenclave, sizeof(expected_mrenclave)) != 0) {
            fprintf(stderr, "Error: MRENCLAVE value does not match expected value\n");
            free(quote_buffer.data);
            X509_free(cert);
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
            free(quote_buffer.data);
            X509_free(cert);
            return 1;
        }
        
        if (memcmp(quote->report_body.mr_signer, expected_mrsigner, sizeof(expected_mrsigner)) != 0) {
            fprintf(stderr, "Error: MRSIGNER value does not match expected value\n");
            free(quote_buffer.data);
            X509_free(cert);
            return 1;
        }
        
        if (opts.verbose && !opts.quiet) {
            fprintf(stdout, "MRSIGNER verification passed\n");
        }
    }
    
    /* Verify the SGX quote */
    sgx_verification_result_t result;
    
    if (!verify_sgx_quote(quote_buffer.data, quote_buffer.length, &result)) {
        fprintf(stderr, "Error: SGX quote verification failed\n");
        free(quote_buffer.data);
        X509_free(cert);
        return 1;
    }
    
    /* Print verification results based on output mode */
    if (opts.raw) {
        /* Raw output format for machine readability */
        fprintf(stdout, "mrenclave=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            quote->report_body.mr_enclave[0], quote->report_body.mr_enclave[1],
            quote->report_body.mr_enclave[2], quote->report_body.mr_enclave[3],
            quote->report_body.mr_enclave[4], quote->report_body.mr_enclave[5],
            quote->report_body.mr_enclave[6], quote->report_body.mr_enclave[7],
            quote->report_body.mr_enclave[8], quote->report_body.mr_enclave[9],
            quote->report_body.mr_enclave[10], quote->report_body.mr_enclave[11],
            quote->report_body.mr_enclave[12], quote->report_body.mr_enclave[13],
            quote->report_body.mr_enclave[14], quote->report_body.mr_enclave[15],
            quote->report_body.mr_enclave[16], quote->report_body.mr_enclave[17],
            quote->report_body.mr_enclave[18], quote->report_body.mr_enclave[19],
            quote->report_body.mr_enclave[20], quote->report_body.mr_enclave[21],
            quote->report_body.mr_enclave[22], quote->report_body.mr_enclave[23],
            quote->report_body.mr_enclave[24], quote->report_body.mr_enclave[25],
            quote->report_body.mr_enclave[26], quote->report_body.mr_enclave[27],
            quote->report_body.mr_enclave[28], quote->report_body.mr_enclave[29],
            quote->report_body.mr_enclave[30], quote->report_body.mr_enclave[31]);
            
        fprintf(stdout, "mrsigner=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            quote->report_body.mr_signer[0], quote->report_body.mr_signer[1],
            quote->report_body.mr_signer[2], quote->report_body.mr_signer[3],
            quote->report_body.mr_signer[4], quote->report_body.mr_signer[5],
            quote->report_body.mr_signer[6], quote->report_body.mr_signer[7],
            quote->report_body.mr_signer[8], quote->report_body.mr_signer[9],
            quote->report_body.mr_signer[10], quote->report_body.mr_signer[11],
            quote->report_body.mr_signer[12], quote->report_body.mr_signer[13],
            quote->report_body.mr_signer[14], quote->report_body.mr_signer[15],
            quote->report_body.mr_signer[16], quote->report_body.mr_signer[17],
            quote->report_body.mr_signer[18], quote->report_body.mr_signer[19],
            quote->report_body.mr_signer[20], quote->report_body.mr_signer[21],
            quote->report_body.mr_signer[22], quote->report_body.mr_signer[23],
            quote->report_body.mr_signer[24], quote->report_body.mr_signer[25],
            quote->report_body.mr_signer[26], quote->report_body.mr_signer[27],
            quote->report_body.mr_signer[28], quote->report_body.mr_signer[29],
            quote->report_body.mr_signer[30], quote->report_body.mr_signer[31]);
            
        fprintf(stdout, "version=%d\n", quote->version);
        fprintf(stdout, "signtype=%d\n", quote->sign_type);
        fprintf(stdout, "isvprodid=%d\n", quote->report_body.isv_prod_id);
        fprintf(stdout, "isvsvn=%d\n", quote->report_body.isv_svn);
    } else if (!opts.quiet) {
        /* Normal Unix-like output with optional verbosity */
        if (opts.verbose) {
            fprintf(stdout, "SGX Quote verification successful\n");
            fprintf(stdout, "MRENCLAVE: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", quote->report_body.mr_enclave[i]);
            }
            fprintf(stdout, "\n");
            
            fprintf(stdout, "MRSIGNER: ");
            for (int i = 0; i < 32; i++) {
                fprintf(stdout, "%02x", quote->report_body.mr_signer[i]);
            }
            fprintf(stdout, "\n");
            
            fprintf(stdout, "ISV Product ID: %d\n", quote->report_body.isv_prod_id);
            fprintf(stdout, "ISV SVN: %d\n", quote->report_body.isv_svn);
        } else {
            /* Simple verification success message */
            fprintf(stdout, "SGX quote verification successful\n");
        }
    }
    
    /* Cleanup */
    free(quote_buffer.data);
    X509_free(cert);
    
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