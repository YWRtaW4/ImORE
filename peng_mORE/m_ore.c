#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>

#include "tool.h"
#include "crypto.h"
#include "m_ore.h"

/**
 * KMap function computes (g^r, pk^r)<--KMap(g, pk, r).
*/
void kmap(ore_kmap_out* kout, element_t pk, element_t g, element_t r)
{
    element_pow_zn(kout->gr, g, r);
    element_pow_zn(kout->yr, pk, r);
}

/**
 * The commit generation algorithm.
 * 
 * @param[out] cmt              - The commitment.
 * @param[out] st               - The state.
 * @param[in] g                 - The generator of G.
 * @param[in] rnd               - The randomness.
*/
void commit(element_t cmt, element_t st, element_t g, element_t rnd)
{
    element_pow_zn(cmt, g, rnd); //cmt=g^rnd
    element_set(st, rnd); //st=rnd
}

/**
 * The response algorithm.
 * 
 * @param[out] rsp              - The response.
 * @param[in] sk                - The secret key.
 * @param[in] st                - The state.
 * @param[in] ch                - The challenge.
*/
void response(element_t rsp, element_t sk, element_t st, element_t ch)
{
    element_mul(rsp, sk, ch);
    element_sub(rsp, st, rsp); //rsp = st - sk*ch
}

/**
 * The commitment recovery algorithm.
 * 
 * @param[out] cmt              - The recovered challenge.
 * @param[in] pk                - The public key.
 * @param[in] ch                - The challenge.
 * @param[in] rsp               - The response.
 * @param[in] g                 - The generator of G.
 * @param[in] pairing           - The pairing used.
*/
void recovery(element_t cmt, ore_kmap_out* pk, element_t ch, element_t rsp, element_t g, pairing_t pairing)
{
    element_t tmp;

    element_init_G1(tmp, pairing);

    element_pow_zn(cmt, pk->gr, rsp);
    element_pow_zn(tmp, pk->yr, ch);
    element_mul(cmt, cmt, tmp);

    element_clear(tmp);
}

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
int init_ore_params(ore_pp* params, int nbits, char* param, size_t count)
{
    params->initialized = true;
    params->nbits = nbits;

    if(!count)
    {
        pbc_die("input error");
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    pairing_init_set_buf(params->pairing, param, count);

    if(pairing_is_symmetric(params->pairing))
    {
        return ERROR_PAIRING_IS_SYMMETRIC;
    }

    element_init_G1(params->g, params->pairing);
    element_random(params->g);

    return ERROR_NONE;
}

/**
 * Initialize a master secret key and a query key with the parameters described by params.
 * 
 * @param[out] msk              - The master secret key to initialize.
 * @param[out] qk               - The query key to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_key(ore_master_secret_key* msk, ore_query_key* qk, ore_pp* params)
{
    if(params == NULL)
    {
        return ERROR_NULL_POINTER;
    }
    if(!params->initialized)
    {
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    element_init_Zr(msk->s, params->pairing);
    element_init_Zr(msk->sk0, params->pairing);
    element_init_G1(msk->pk1, params->pairing);
    element_init_G1(msk->pk2, params->pairing);
    msk->initialized = true;

    element_init_Zr(qk->s, params->pairing);
    element_init_Zr(qk->sk1, params->pairing);
    element_init_Zr(qk->sk2, params->pairing);
    element_init_G1(qk->pk0, params->pairing);
    qk->initialized = true;

    return ERROR_NONE;
}

/**
 * Initialize a ciphertext with the parameters described by params.
 * 
 * @param[out] ctxt             - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_ciphertext(ore_ciphertext* ctxt, ore_pp* params)
{
    if(ctxt == NULL || params == NULL)
    {
        return ERROR_NULL_POINTER;
    }
    if(!params->initialized)
    {
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    int i;

    ctxt->nbits = params->nbits;

    element_init_G1(ctxt->c01.gr, params->pairing);
    element_init_G1(ctxt->c01.yr, params->pairing);
    element_init_G1(ctxt->c02.gr, params->pairing);
    element_init_G1(ctxt->c02.yr, params->pairing);
    element_init_Zr(ctxt->xi, params->pairing);
    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(ctxt->ct[i], params->pairing);
    }

    ctxt->initialized = true;
    return ERROR_NONE;
}

/**
 * Initialize a token with the parameters described by params.
 * 
 * @param[out] token            - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_token(ore_token* token, ore_pp* params)
{   
    if(token == NULL || params == NULL)
    {
        return ERROR_NULL_POINTER;
    }
    if(!params->initialized)
    {
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    int i;

    token->nbits = params->nbits;

    element_init_G1(token->t00.gr, params->pairing);
    element_init_G1(token->t00.yr, params->pairing);
    element_init_Zr(token->eta, params->pairing);

    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(token->t[i].r1, params->pairing);
        element_init_Zr(token->t[i].r2, params->pairing);
    }

    token->initialized = true;
    return ERROR_NONE;
}

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
int ore_key_gen(ore_master_secret_key* msk, ore_query_key* qk, ore_pp* params)
{
    if(!msk->initialized)
    {
        return ERROR_MSKEY_NOT_INITIALIZED;
    }
    if(!qk->initialized)
    {
        return ERROR_QKEY_NOT_INITIALIZED;
    }

    element_random(msk->s);
    element_set(qk->s, msk->s);
    element_random(msk->sk0);
    element_random(qk->sk1);
    element_random(qk->sk2);

    element_pow_zn(qk->pk0, params->g, msk->sk0);
    element_pow_zn(msk->pk1, params->g, qk->sk1);
    element_pow_zn(msk->pk2, params->g, qk->sk2);

    return ERROR_NONE;
}

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
int ore_enc(ore_ciphertext* ctxt, ore_master_secret_key* msk, uint64_t msg, ore_pp* params)
{
    if(!ctxt->initialized)
    {
        return ERROR_CTXT_NOT_INITIALIZED;
    }
    if(!msk->initialized)
    {
        return ERROR_MSKEY_NOT_INITIALIZED;
    }

    int i, buf_len;

    element_t r, u0, rnd, cmt;
    element_t st[params->nbits];
    
    byte u_byte[PRF_OUTPUT_BYTES];
    byte hash[SHA256_OUTPUT_BYTES];
    byte key_byte[PRF_OUTPUT_BYTES];
    byte* xi_byte;
    byte* hash1_input;

    rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute)*params->nbits);
    for(i = 0; i < params->nbits; i++)
    {
        permute[i].index = i;
        permute[i].rando = rand();
    }
    qsort(permute, params->nbits, sizeof(permute), comp);

    element_init_Zr(r, params->pairing);
    element_random(r);

    element_init_Zr(u0, params->pairing);
    element_init_Zr(rnd, params->pairing);
    element_init_G1(cmt, params->pairing);
    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(st[i], params->pairing);
    }

    xi_byte = (byte *)malloc(SHA256_OUTPUT_BYTES*params->nbits);
    memset(xi_byte, 0, SHA256_OUTPUT_BYTES*params->nbits);

    buf_len = element_length_in_bytes(cmt);
    hash1_input = (byte *)malloc(sizeof(byte)*(buf_len+SHA256_OUTPUT_BYTES));
    memset(hash1_input, 0, buf_len+SHA256_OUTPUT_BYTES);
    
    kmap(&ctxt->c01, msk->pk1, params->g, r);
    kmap(&ctxt->c02, msk->pk2, params->g, r);

    memset(key_byte, 0, sizeof(key_byte));
    element_to_bytes(key_byte, msk->s);

    for(i = 0; i < params->nbits; i++)
    {
        encode(u_byte, key_byte, (byte *)&msg, sizeof(msg), permute[i].index, params->nbits);
        HMAC_SHA256(hash, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u0, hash);
        element_mul(rnd, u0, r);
        commit(cmt, st[i], params->g, rnd);
        element_to_bytes(hash1_input, cmt);
        memcpy(hash1_input+buf_len, hash, SHA256_OUTPUT_BYTES);
        sha_256(xi_byte+i*SHA256_OUTPUT_BYTES, SHA256_OUTPUT_BYTES, hash1_input, buf_len+SHA256_OUTPUT_BYTES);
    }

    sha_256(hash, SHA256_OUTPUT_BYTES, xi_byte, SHA256_OUTPUT_BYTES*params->nbits);
    element_from_bytes(ctxt->xi, hash);

    for(i = 0; i < params->nbits; i++)
    {
        response(ctxt->ct[i], msk->sk0, st[i], ctxt->xi);
    }

    element_clear(r);
    element_clear(u0);
    element_clear(rnd);
    element_clear(cmt);
    for(i = 0; i < params->nbits; i++)
    {
        element_clear(st[i]);
    }

    free(xi_byte);
    free(hash1_input);
    free(permute);

    return ERROR_NONE;
}

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
int ore_token_gen(ore_token* token, ore_query_key* qk, uint64_t msg, ore_pp* params)
{
    if(!token->initialized)
    {
        return ERROR_TOKEN_NOT_INITIALIZED;
    }
    if(!qk->initialized)
    {
        return ERROR_QKEY_NOT_INITIALIZED;
    }

    int i, buf_len;

    element_t r, rnd, cmt;
    element_t state1[params->nbits];
    element_t state2[params->nbits];
    mpz_t u_opr_one, u_add_one, u_sub_one;

    byte u_byte[PRF_OUTPUT_BYTES];
    byte u_opr_one_byte[SHA256_OUTPUT_BYTES];
    byte hash[SHA256_OUTPUT_BYTES];
    byte key_byte[PRF_OUTPUT_BYTES];
    byte* hash1_input;
    byte* eta_byte;

    rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute)*params->nbits);
    for(i = 0; i < params->nbits; i++)
    {
        permute[i].index = i;
        permute[i].rando = rand();
    }
    qsort(permute, params->nbits, sizeof(permute), comp);

    element_init_Zr(r, params->pairing);
    element_random(r);

    mpz_init(u_opr_one);
    mpz_init(u_add_one);
    mpz_init(u_sub_one);
    element_init_Zr(rnd, params->pairing);
    element_init_G1(cmt, params->pairing);

    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(state1[i], params->pairing);
        element_init_Zr(state2[i], params->pairing);
    }

    eta_byte = (byte *)malloc(sizeof(hash)*params->nbits*2);
    memset(eta_byte, 0, SHA256_OUTPUT_BYTES*params->nbits*2);

    buf_len = element_length_in_bytes(cmt);
    hash1_input = (byte *)malloc(sizeof(byte)*(buf_len+SHA256_OUTPUT_BYTES));
    memset(hash1_input, 0, buf_len+SHA256_OUTPUT_BYTES);

    kmap(&token->t00, qk->pk0, params->g, r);

    memset(key_byte, 0, sizeof(key_byte));
    element_to_bytes(key_byte, qk->s);

    for(i = 0; i < params->nbits; i++)
    {
        encode(u_byte, key_byte, (byte *)&msg, sizeof(msg), permute[i].index, params->nbits);
        mpz_import(u_opr_one, 32, 1, 1, -1, 0, u_byte);

        mpz_add_ui(u_add_one, u_opr_one, 1);
        mpz_export(u_opr_one_byte, NULL, 1, 1, -1, 0, u_add_one);
        HMAC_SHA256(hash, SHA256_OUTPUT_BYTES, key_byte, u_opr_one_byte, SHA256_OUTPUT_BYTES);
        element_from_bytes(rnd, hash);
        element_mul(rnd, rnd, r);
        commit(cmt, state1[i], params->g, rnd);
        element_to_bytes(hash1_input, cmt);
        memcpy(hash1_input+buf_len, hash, SHA256_OUTPUT_BYTES);
        sha_256(eta_byte+i*2*SHA256_OUTPUT_BYTES, SHA256_OUTPUT_BYTES, hash1_input, buf_len+SHA256_OUTPUT_BYTES);

        memset(u_opr_one_byte, 0, SHA256_OUTPUT_BYTES);
        memset(hash1_input, 0, buf_len+SHA256_OUTPUT_BYTES);

        mpz_sub_ui(u_sub_one, u_opr_one, 1);
        mpz_export(u_opr_one_byte, NULL, 1, 1, -1, 0, u_sub_one);
        HMAC_SHA256(hash, SHA256_OUTPUT_BYTES, key_byte, u_opr_one_byte, SHA256_OUTPUT_BYTES);
        element_from_bytes(rnd, hash);
        element_mul(rnd, rnd, r);
        commit(cmt, state2[i], params->g, rnd);
        element_to_bytes(hash1_input, cmt);
        memcpy(hash1_input+buf_len, hash, SHA256_OUTPUT_BYTES);
        sha_256(eta_byte+(2*i+1)*SHA256_OUTPUT_BYTES, SHA256_OUTPUT_BYTES, hash1_input, buf_len+SHA256_OUTPUT_BYTES);
    }

    sha_256(hash, SHA256_OUTPUT_BYTES, eta_byte, SHA256_OUTPUT_BYTES*params->nbits*2);
    element_from_bytes(token->eta, hash);

    for(i = 0; i < params->nbits; i++)
    {
        response(token->t[i].r1, qk->sk1, state1[i], token->eta);
        response(token->t[i].r2, qk->sk2, state2[i], token->eta);
    }

    element_clear(r);
    element_clear(rnd);
    element_clear(cmt);

    for(i = 0; i < params->nbits; i++)
    {
        element_clear(state1[i]);
        element_clear(state2[i]);
    }

    free(permute);
    free(eta_byte);
    free(hash1_input);

    return ERROR_NONE;
}

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
int ore_cmp(int* b, ore_ciphertext* ctxt, ore_token* token, ore_pp* params)
{
    if(!ctxt->initialized)
    {
        return ERROR_CTXT_NOT_INITIALIZED;
    }
    if(!token->initialized)
    {
        return ERROR_TOKEN_NOT_INITIALIZED;
    }

    int i, j, bit;
    element_t rec0[params->nbits];
    element_t rec1[params->nbits];
    element_t rec2[params->nbits];

    bool break_flag = false;

    for(i = 0; i < params->nbits; i++)
    {
        element_init_G1(rec0[i], params->pairing);
        element_init_G1(rec1[i], params->pairing);
        element_init_G1(rec2[i], params->pairing);

        recovery(rec0[i], &token->t00, ctxt->xi, ctxt->ct[i], params->g, params->pairing);
        recovery(rec1[i], &ctxt->c01, token->eta, token->t[i].r1, params->g, params->pairing);
        recovery(rec2[i], &ctxt->c02, token->eta, token->t[i].r2, params->g, params->pairing);
    }

    for(i = 0; i < params->nbits; i++)
    {   
        for(j = 0; j < params->nbits; j++)
        {
            if(element_cmp(rec0[i], rec1[j]) == 0)
            {
                bit = 1;
                break_flag = true;
                break;
            }
            else if(element_cmp(rec0[i], rec2[j]) == 0)
            {
                bit = -1;
                break_flag = true;
                break;
            }
            else
            {
                bit = 0;
            }
        }

        if(break_flag == true) break;
    }

    *b = bit;

    for(i = 0; i < params->nbits; i++)
    {
        element_clear(rec0[i]);
        element_clear(rec1[i]);
        element_clear(rec2[i]);
    }

    return ERROR_NONE;
}

/**
 * Clear a master secreat key and a query key.
 *
 * @param[in] msk               - The master secreat key to clear.
 * @param[in] qk                - The query key to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_key(ore_master_secret_key* msk, ore_query_key* qk)
{
    if(msk == NULL || qk == NULL)
    {
        return ERROR_NONE;
    }

    element_clear(msk->s);
    element_clear(msk->sk0);
    element_clear(msk->pk1);
    element_clear(msk->pk2);

    element_clear(qk->s);
    element_clear(qk->sk1);
    element_clear(qk->sk2);
    element_clear(qk->pk0);

    return ERROR_NONE;
}

/**
 * Clear a ciphertext.
 *
 * @param[in] ctxt              - The ciphertext to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext* ctxt)
{
    if(ctxt == NULL)
    {
        return ERROR_NONE;
    }

    int i;

    element_clear(ctxt->c01.gr);
    element_clear(ctxt->c01.yr);
    element_clear(ctxt->c02.gr);
    element_clear(ctxt->c02.yr);
    element_clear(ctxt->xi);

    for(i = 0; i < ctxt->nbits; i++)
    {
        element_clear(ctxt->ct[i]);
    }

    return ERROR_NONE;
}

/**
 * Clear a token.
 *
 * @param[in] token             - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_token(ore_token* token)
{
    if(token == NULL)
    {
        return ERROR_NONE;
    }

    int i;

    element_clear(token->t00.gr);
    element_clear(token->t00.yr);
    element_clear(token->eta);

    for(i = 0; i < token->nbits; i++)
    {
        element_clear(token->t[i].r1);
        element_clear(token->t[i].r2);
    }

    return ERROR_NONE;
}

/**
 * Clear the ore params.
 *
 * @param[in] params            - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_params(ore_pp* params)
{
    if(params == NULL)
    {
        return ERROR_NONE;
    }

    element_clear(params->g);
    pairing_clear(params->pairing);
    
    return ERROR_NONE;
}