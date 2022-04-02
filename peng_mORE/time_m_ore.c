#include <stdio.h>
#include <time.h>

#include "m_ore.h"
#include "errors.h"

static int _err;
#define ERR_CHECK(x)            \
    if ((_err = x) != ERROR_NONE) \
    {                             \
    return _err;                \
    }

int main(int argc, char **argv)
{
    const uint32_t NBITS[] = {8, 16, 24, 32, 48, 64};

    const int N_ENC_TRIALS = 100;
    const int N_TGEN_TRIALS = 100;
    const int N_CMP_TRIALS = 100;

    uint32_t nbits_len = sizeof(NBITS) / sizeof(int);

    printf("n = bit length of plaintext space\n\n");
    printf("%2s %12s %15s %15s %12s %16s %16s %18s %18s %16s\n", "n", "enc iter", "enc avg (ms)", "enc total (s)", "cmp iter", "cmp avg (ms)", "cmp total (s)", "ctxt_len (bytes)", "token_len (bytes)", "token_gen (ms)");

    ore_pp params;
    ore_ciphertext ctxt;
    ore_token token;
    ore_master_secret_key msk;
    ore_query_key qk;

    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);

    uint64_t byte_len_of_ctxt = 0;
    uint64_t byte_len_of_token = 0;

    uint64_t mask, msg;

    for(int i = 0; i < nbits_len; i++)
    {
        ERR_CHECK(init_ore_params(&params, NBITS[i], param, count));
        ERR_CHECK(init_ore_key(&msk, &qk, &params));
        ERR_CHECK(init_ore_ciphertext(&ctxt, &params));
        ERR_CHECK(init_ore_token(&token, &params));

        ERR_CHECK(ore_key_gen(&msk, &qk, &params));

        mask = (NBITS[i] == 64) ? 0xffffffff : (uint64_t)(1 << NBITS[i]) - 1;

        //time test for ore_enc
        clock_t start_time = clock();
        int enc_trials = N_ENC_TRIALS / (i + 1);
        for(int j = 0; j < enc_trials; j++)
        {
            if(NBITS[i] == 64)
            {
                msg = rand() & mask;
                msg <<= 32;
                msg += rand() & mask;
            }
            else
            {
                msg = rand() & mask;
            }
            ERR_CHECK(ore_enc(&ctxt, &msk, msg, &params));
        }
        double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double enc_time = enc_time_elapsed / enc_trials * 1000;
        byte_len_of_ctxt = element_length_in_bytes(ctxt.c01.gr)*3 + element_length_in_bytes(ctxt.xi) + element_length_in_bytes(ctxt.ct[0])*NBITS[i];
        // byte_len_of_ctxt =  element_length_in_bytes_compressed(ctxt.c01.gr)*3 + element_length_in_bytes(ctxt.xi) + element_length_in_bytes(ctxt.ct[0])*NBITS[i];

        //time test for ore_token_gen
        int token_gen_trials = N_TGEN_TRIALS / (i + 1);
        start_time = clock();
        for(int j = 0; j < token_gen_trials; j++)
        {
            if(NBITS[i] == 64)
            {
                msg = rand() & mask;
                msg <<= 32;
                msg += rand() & mask;
            }
            else
            {
                msg = rand() & mask;
            }
            ERR_CHECK(ore_token_gen(&token, &qk, msg, &params));
        }
        double token_gen_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double token_gen_time = token_gen_time_elapsed / token_gen_trials * 1000;
        byte_len_of_token = element_length_in_bytes(token.t00.gr)*2 + element_length_in_bytes(token.eta) + element_length_in_bytes(token.t[0].r1)*2*NBITS[i];
        // byte_len_of_token = element_length_in_bytes_compressed(token.t00.gr)*2 + element_length_in_bytes(token.eta) + element_length_in_bytes(token.t[0].r1)*2*NBITS[i];

        //time_test for ore_cmp
        int res;

        start_time = clock();
        for(int j = 0; j < N_CMP_TRIALS; j++)
        {
            ore_cmp(&res, &ctxt, &token, &params);
        }
        double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double cmp_time = cmp_time_elapsed / N_CMP_TRIALS * 1000;

        printf("%2d %12d %15.2f %15.2f %12d %16.2f %16.2f %18lu %18lu %16.2f\n",
           NBITS[i], enc_trials, enc_time, enc_time_elapsed, N_CMP_TRIALS, cmp_time,
           cmp_time_elapsed, byte_len_of_ctxt, byte_len_of_token, token_gen_time);

        ERR_CHECK(clear_ore_key(&msk, &qk));
        ERR_CHECK(clear_ore_ciphertext(&ctxt));
        ERR_CHECK(clear_ore_token(&token));
    }

    ERR_CHECK(clear_ore_params(&params));

    return 0;
}