/**
 * @file echeck_quote.h
 * @brief Internal definition of quote structure
 */

#ifndef ECHECK_QUOTE_H
#define ECHECK_QUOTE_H

#include "echeck.h"
#include "sgx_types.h"

/**
 * @brief Internal quote structure
 */
struct echeck_quote_t {
    unsigned char *data;      /* Raw quote data */
    size_t data_size;         /* Size of raw quote data */
    sgx_quote_t *quote;       /* Parsed quote structure (points within data) */
};

/**
 * @brief Create a new quote structure from raw data
 * 
 * @param data Raw quote data
 * @param size Size of quote data
 * @return echeck_quote_t* New quote structure or NULL on error
 */
echeck_quote_t* echeck_quote_create(unsigned char *data, size_t size);

/**
 * @brief Free a quote structure
 * 
 * @param quote Quote structure to free
 */
void echeck_quote_free(echeck_quote_t *quote);

#endif /* ECHECK_QUOTE_H */