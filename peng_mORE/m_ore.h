#ifndef __M_ORE_H__
#define __M_ORE_H__

#include <pbc/pbc.h>
#include <stdbool.h>

#include "crypto.h"

static const int PLAINTEXT_BIT = 64;

/* system parameters */
typedef struct {
    bool initialized;
    int nbits;
    element_t g;
    pairing_t pairing;
} ore_pp;

/* master secret key */
typedef struct {
    bool initialized;
    element_t s;
    element_t sk0;
    element_t pk1;
    element_t pk2;
} ore_master_secret_key;

/* query key */
typedef struct {
    bool initialized;
    element_t s;
    element_t sk1;
    element_t sk2;
    element_t pk0;
} ore_query_key;

typedef struct {
    element_t gr;
    element_t yr;
} ore_kmap_out;

typedef struct {
    element_t r1;
    element_t r2;
} ore_rsp_arr;

/* ciphertext */
typedef struct {
    bool initialized;
    int nbits;
    ore_kmap_out c01;
    ore_kmap_out c02;
    element_t xi;
    element_t ct[PLAINTEXT_BIT];
} ore_ciphertext;

/* token */
typedef struct {
    bool initialized;
    int nbits;
    ore_kmap_out t00;
    element_t eta;
    ore_rsp_arr t[PLAINTEXT_BIT];
} ore_token;

/**
 * Initialize an ore_pp type by setting its parameters, number of bits.
 * 
 * @param[out] params           - The params to initialize.
 * @param[in] nbits             - The number of bits of an input to the encryption scheme.
 * @param[in] param             - The param information.
 * @param[in] count             - The size of param.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_params(ore_pp* params, int nbits, char* param, size_t count);

/**
 * Initialize a master secret key and a query key with the parameters described by params.
 * 
 * @param[out] msk              - The master secret key to initialize.
 * @param[out] qk               - The query key to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_key(ore_master_secret_key* msk, ore_query_key* qk, ore_pp* params);

/**
 * Initialize a ciphertext with the parameters described by params.
 * 
 * @param[out] ctxt             - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_ciphertext(ore_ciphertext* ctxt, ore_pp* params);

/**
 * Initialize a token with the parameters described by params.
 * 
 * @param[out] token            - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_token(ore_token* token, ore_pp* params);

/**
 * The key generation algorithm.
 * 
 * The master secret key and query key must be initialized (by a call to init_ore_key) before calling this function.
 * 
 * @param[out] msk              - The generated master secret key.
 * @param[out] qk               - The generated query key.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_key_gen(ore_master_secret_key* msk, ore_query_key* qk, ore_pp* params);

/**
 * The encryption algorithm.
 * 
 * The ciphertext must be initialized (by a call to init_ore_ciphertext) before calling this function.
 * 
 * @param[out] ctxt             - The ciphertext to store the encrypt result.
 * @param[in] msk               - The master secret key.
 * @param[in] msg               - The plaintext in uint64_t format.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_enc(ore_ciphertext* ctxt, ore_master_secret_key* msk, uint64_t msg, ore_pp* params);

/**
 * The token generation algorithm.
 * 
 * The token must be initialized (by a call to init_ore_token) before calling this function.
 * 
 * @param[out] token            - The token to store the TGen result.
 * @param[in] qk                - The query key.
 * @param[in] msg               - The plaintext in uint64_t format.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_token_gen(ore_token* token, ore_query_key* qk, uint64_t msg, ore_pp* params);

/**
 * The comparison algorithm.
 * 
 * Both ciphertext and token must be initialized before calling this function.
 * 
 * @param[out] b                - A flag bit.
 * @param[in] ctxt              - The ciphertext.
 * @param[in] token             - The token.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_cmp(int* b, ore_ciphertext* ctxt, ore_token* token, ore_pp* params);

/**
 * Clear a master secreat key and a query key.
 *
 * @param[in] msk               - The master secreat key to clear.
 * @param[in] qk                - The query key to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_key(ore_master_secret_key* msk, ore_query_key* qk);

/**
 * Clear a ciphertext.
 *
 * @param[in] ctxt              - The ciphertext to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext* ctxt);

/**
 * Clear a token.
 *
 * @param[in] token             - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_token(ore_token* token);

/**
 * Clear the ore params.
 *
 * @param[in] params            - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_params(ore_pp* params);

#endif /* __M_ORE_H__ */