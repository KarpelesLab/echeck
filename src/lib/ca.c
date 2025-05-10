#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "echeck.h"
#include "echeck_internal.h"
/* OpenSSL headers are accessed through openssl_runtime.h included in common.h */

/* Intel SGX Root CA certificate in PEM format */
static const char intel_sgx_root_ca[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n"
"aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
"cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
"BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\n"
"A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
"aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
"AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n"
"1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n"
"uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n"
"MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
"ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n"
"Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n"
"KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\n"
"AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n"
"-----END CERTIFICATE-----\n";

/* The list could be expanded to include additional CA certificates */

/**
 * Get a stack of trusted CA certificates for SGX validation.
 * This function loads the built-in Intel SGX Root CA certificates.
 *
 * @return A pointer to a stack of X509 certificates, or NULL on error.
 *         The caller is responsible for freeing the stack with sk_X509_pop_free().
 */
STACK_OF(X509) *get_trusted_ca_stack(void) {
    STACK_OF(X509) *ca_stack = NULL;
    BIO *mem_bio = NULL;
    X509 *cert = NULL;
    
    /* Load the trusted CA certificates */
    
    /* Create a memory BIO for the certificate data */
    mem_bio = BIO_new_mem_buf(intel_sgx_root_ca, -1); /* -1 means use strlen */
    if (!mem_bio) {
        print_openssl_error("Error creating memory BIO for CA certificate");
        return NULL;
    }


    /* Create a new certificate stack */
    ca_stack = sk_X509_new_null();  /* Using our macro which redirects to OPENSSL_sk_new_null */
    if (!ca_stack) {
        print_openssl_error("Error creating certificate stack");
        BIO_free(mem_bio);
        return NULL;
    }


    /* Read the PEM-formatted certificate */
    cert = PEM_read_bio_X509(mem_bio, NULL, NULL, NULL);
    if (!cert) {
        print_openssl_error("Error loading built-in CA certificate");
        sk_X509_free(ca_stack);
        BIO_free(mem_bio);
        return NULL;
    }


    /* Add the certificate to the stack */
    
    if (!sk_X509_push(ca_stack, cert)) {  /* Using our macro which redirects to OPENSSL_sk_push */
        print_openssl_error("Error adding certificate to stack");
        X509_free(cert);
        sk_X509_free(ca_stack);
        BIO_free(mem_bio);
        return NULL;
    }
    
    
    /* Additional CA certificates could be added here */
    
    /* Free the BIO */
    BIO_free(mem_bio);
    
    
    /* Return the certificate stack */
    if (global_verbose_flag) {
        fprintf(stderr, "Loaded %d built-in CA certificates for SGX validation\n", sk_X509_num(ca_stack));
    }
    return ca_stack;
}