#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>

#include "tool.h"
#include "crypto.h"
#include "p_ore.h"

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
 * Initialize a master secret key and a comparison key with the parameters described by params.
 * 
 * @param[out] msk              - The master secret key to initialize.
 * @param[out] ck               - The comparison key to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params)
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
    element_init_Zr(msk->r, params->pairing);
    element_init_Zr(msk->x0, params->pairing);
    element_init_Zr(msk->x1, params->pairing);
    element_init_Zr(msk->x2, params->pairing);
    msk->initialized = true;
    
    element_init_G1(ck->y0, params->pairing);
    element_init_G1(ck->y1, params->pairing);
    element_init_G1(ck->y2, params->pairing);
    ck->initialized = true;

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
    element_init_Zr(ctxt->xi, params->pairing);
    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(ctxt->inter_ct[i].z0, params->pairing);
        element_init_Zr(ctxt->inter_ct[i].z1, params->pairing);
        element_init_Zr(ctxt->inter_ct[i].z2, params->pairing);
    }
    ctxt->initialized = true;

    return ERROR_NONE;
}

/**
 * The key generation algorithm.
 * 
 * The master secret key and comparison key must be initialized (by a call to init_ore_key) before calling this function.
 * 
 * @param[out] msk              - The generated master secret key.
 * @param[out] ck               - The generated comparison key.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_key_gen(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params)
{
    if(!msk->initialized)
    {
        return ERROR_MSKEY_NOT_INITIALIZED;
    }
    if(!ck->initialized)
    {
        return ERROR_QKEY_NOT_INITIALIZED;
    }

    element_random(msk->s);
    element_random(msk->r);
    element_random(msk->x0);
    element_random(msk->x1);
    element_random(msk->x2);

    element_pow_zn(ck->y0, params->g, msk->x0);
    element_pow_zn(ck->y1, params->g, msk->x1);
    element_pow_zn(ck->y2, params->g, msk->x2);

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

    int i;
    element_t g_pow_r, w, tmp;
    element_t u[PLAINTEXT_BIT*3];
    byte key_byte[PRF_OUTPUT_BYTES];
    byte u_byte[PRF_OUTPUT_BYTES];
    byte u_opr_one_byte[SHA256_OUTPUT_BYTES];
    byte xi_byte[SHA256_OUTPUT_BYTES];
    element_t u_opr_one;
    mpz_t mpz_u;

    int g_byte_length = element_length_in_bytes(params->g);
    int size = g_byte_length+PRF_OUTPUT_BYTES;
    byte* hash1_input = (byte *)malloc(size*3*params->nbits);
    memset(hash1_input, 0, size*3*params->nbits);

    byte* w_byte = (byte *)malloc(sizeof(byte)*g_byte_length);
    memset(w_byte, 0, g_byte_length);

    rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute)*params->nbits);
    for(i = 0; i < params->nbits; i++)
    {
        permute[i].index = i;
        permute[i].rando = rand();
    }
    qsort(permute, params->nbits, sizeof(permute), comp);

    element_init_G1(g_pow_r, params->pairing);
    element_pow_zn(g_pow_r, params->g, msk->r);
    element_init_G1(w, params->pairing);
    element_init_Zr(tmp, params->pairing);
    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(u[3*i], params->pairing);
        element_init_Zr(u[3*i+1], params->pairing);
        element_init_Zr(u[3*i+2], params->pairing);
    }

    element_init_Zr(u_opr_one, params->pairing);
    mpz_init(mpz_u);

    memset(key_byte, 0, sizeof(key_byte));
    element_to_bytes(key_byte, msk->s);

    for(i = 0; i < params->nbits; i++)
    {
        encode(u_byte, key_byte, (byte *)&msg, sizeof(msg), permute[i].index, params->nbits);
        mpz_import(mpz_u, 32, 1, 1, -1, 0, u_byte);

        HMAC_SHA256(u_opr_one_byte, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES); //u_{i,0}
        element_from_bytes(u[i*3], u_opr_one_byte);
        memcpy(hash1_input+i*3*size, u_opr_one_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u_opr_one, u_opr_one_byte);
        element_pow_zn(w, g_pow_r, u_opr_one);
        element_to_bytes(w_byte, w);
        memcpy(hash1_input+i*3*size+PRF_OUTPUT_BYTES, w_byte, g_byte_length);

        mpz_add_ui(mpz_u, mpz_u, 1); //u+1
        mpz_export(u_byte, NULL, 1, 1, -1, 0, mpz_u);
        HMAC_SHA256(u_opr_one_byte, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES); //u_{i,1}
        element_from_bytes(u[i*3+1], u_opr_one_byte);
        memcpy(hash1_input+(3*i+1)*size, u_opr_one_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u_opr_one, u_opr_one_byte);
        element_pow_zn(w, g_pow_r, u_opr_one);
        element_to_bytes(w_byte, w);
        memcpy(hash1_input+(3*i+1)*size+PRF_OUTPUT_BYTES, w_byte, g_byte_length);

        mpz_sub_ui(mpz_u, mpz_u, 2); //u-1
        mpz_export(u_byte, NULL, 1, 1, -1, 0, mpz_u);
        HMAC_SHA256(u_opr_one_byte, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES); //u_{i,2}
        element_from_bytes(u[i*3+2], u_opr_one_byte);
        memcpy(hash1_input+(3*i+2)*size, u_opr_one_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u_opr_one, u_opr_one_byte);
        element_pow_zn(w, g_pow_r, u_opr_one);
        element_to_bytes(w_byte, w);
        memcpy(hash1_input+(3*i+2)*size+PRF_OUTPUT_BYTES, w_byte, g_byte_length);
    }

    sha_256(xi_byte, SHA256_OUTPUT_BYTES, hash1_input, size*3*params->nbits);
    element_from_bytes(ctxt->xi, xi_byte);

    for(i = 0; i < params->nbits; i++)
    {
        element_mul(tmp, ctxt->xi, msk->x0);
        element_mul(ctxt->inter_ct[i].z0, u[i*3], msk->r);
        element_sub(ctxt->inter_ct[i].z0, ctxt->inter_ct[i].z0, tmp);

        element_mul(tmp, ctxt->xi, msk->x1);
        element_mul(ctxt->inter_ct[i].z1, u[i*3+1], msk->r);
        element_sub(ctxt->inter_ct[i].z1, ctxt->inter_ct[i].z1, tmp);

        element_mul(tmp, ctxt->xi, msk->x2);
        element_mul(ctxt->inter_ct[i].z2, u[i*3+2], msk->r);
        element_sub(ctxt->inter_ct[i].z2, ctxt->inter_ct[i].z2, tmp);
    }

    element_clear(g_pow_r);
    element_clear(w);
    element_clear(tmp);
    for(i = 0; i < params->nbits; i++)
    {
        element_clear(u[3*i]);
        element_clear(u[3*i+1]);
        element_clear(u[3*i+2]);
    }
    element_clear(u_opr_one);
    mpz_clear(mpz_u);
    free(w_byte);
    free(permute);
    free(hash1_input);

    return ERROR_NONE;
}

/**
 * The comparison algorithm.
 * 
 * Both ciphertext and comparison key must be initialized before calling this function.
 * 
 * @param[out] b                - A flag bit.
 * @param[in] ctxt1             - The first ciphertext.
 * @param[in] ctxt2             - The second ciphertext.
 * @param[in] ck                - The comparison key.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_cmp(int* b, ore_ciphertext* ctxt1, ore_ciphertext* ctxt2, ore_cmp_key* ck, ore_pp* params)
{
    element_t v0[params->nbits];
    element_t v1[params->nbits];
    element_t v2[params->nbits];
    element_t tmp;
    bool break_flag = false;
    int i, j, bit;

    for(i = 0; i < params->nbits; i++)
    {
        element_init_G1(v0[i], params->pairing);
        element_init_G1(v1[i], params->pairing);
        element_init_G1(v2[i], params->pairing);
    }
    element_init_G1(tmp, params->pairing);

    for(i = 0; i < params->nbits; i++)
    {
        element_pow_zn(v0[i], params->g, ctxt1->inter_ct[i].z0);
        element_pow_zn(tmp, ck->y0, ctxt1->xi);
        element_mul(v0[i], v0[i], tmp);

        element_pow_zn(v1[i], params->g, ctxt2->inter_ct[i].z1);
        element_pow_zn(tmp, ck->y1, ctxt2->xi);
        element_mul(v1[i], v1[i], tmp);

        element_pow_zn(v2[i], params->g, ctxt2->inter_ct[i].z2);
        element_pow_zn(tmp, ck->y2, ctxt2->xi);
        element_mul(v2[i], v2[i], tmp);
    }

    for(i = 0; i < params->nbits; i++)
    {
        for(j = 0; j < params->nbits; j++)
        {
            if(element_cmp(v0[i], v1[j]) == 0)
            {
                bit = 1;
                break_flag = true;
                break;
            }
            else if(element_cmp(v0[i], v2[j]) == 0)
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
        element_clear(v0[i]);
        element_clear(v1[i]);
        element_clear(v2[i]);
    }
    element_clear(tmp);

    return ERROR_NONE;
}

/**
 * Clear a master secreat key and a comparison key.
 *
 * @param[in] msk               - The master secreat key to clear.
 * @param[in] ck                - The comparison key to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck)
{
    if(msk == NULL || ck == NULL)
    {
        return ERROR_NONE;
    }

    element_clear(msk->s);
    element_clear(msk->r);
    element_clear(msk->x0);
    element_clear(msk->x1);
    element_clear(msk->x2);

    element_clear(ck->y0);
    element_clear(ck->y1);
    element_clear(ck->y2);

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

    element_clear(ctxt->xi);
    for(i = 0; i < ctxt->nbits; i++)
    {
        element_clear(ctxt->inter_ct[i].z0);
        element_clear(ctxt->inter_ct[i].z1);
        element_clear(ctxt->inter_ct[i].z2);
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