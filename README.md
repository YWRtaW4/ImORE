# ImORE
This is the implementation of the paper sigmaORE: Efficient Order-Revealing Encryption from Sigma Protocols with Map-Invariance Property.

If you have any questions, please contact <cpeng@whu.edu.cn>

## Prerequisites ##
Required environment
- [OpenSSL-1.1.1](https://www.openssl.org/source/)
- [GMP-6.2.0](https://gmplib.org/)
- [PBC-0.5.14](https://crypto.stanford.edu/pbc/download.html)
## Installation ##
``` shell
git clone git@github.com:YWRtaW4/ImORE.git
cd peng_mORE (or peng_pORE)
make
```
## Run the test ##
Run the correctness check by 
``` shell
# Requires type-d parameter of PBC library as input to generate asymmetric pairing
./tests/test_m_ore (or test_p_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```
Run the benchmark by
``` shell
./tests/time_m_ore (or time_p_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```

## Cash et al.'s scheme, Li et al.'s scheme and Lv et al.'s scheme ##
We also implemented the scheme of Cash et al. at /cash_scheme, the scheme of Li et al. at /li_scheme and the scheme of Lv et al. at /lv_scheme.

See the paper of Cash et al. at [Springer](https://link.springer.com/chapter/10.1007/978-3-030-03326-2_7),  paper of Li et al. at [ACM](https://dl.acm.org/doi/abs/10.1145/3321705.3329829) and paper of Lv et al. at [Springer](https://link.springer.com/chapter/10.1007%2F978-3-030-88428-4_3).

Run the correctness check by 
``` shell
cd cash_scheme (or li_scheme, lv_schme)
make
./tests/test_cash_ore (or ./tests/test_li_ore, ./tests/test_lv_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```
Run the benchmark by
``` shell
./tests/time_cash_ore (or ./tests/time_li_ore, ./tests/time_lv_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```
