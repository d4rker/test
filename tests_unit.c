#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "wallet.h"
#include "bip32.h"
#include "utils.h"
#include "random.h"
#include "utest.h"
#include "uECC.h"
#include "ecc.h"

int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;

static void test(void)
{
    HDNode node;
    char str[112];
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];
    hdnode_from_seed(utils_hex_to_uint8("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),64, &node);
    memcpy(private_key_master,node.private_key,32);
    memcpy(chain_code_master,node.chain_code,32);

    char path[] = "m/0/2147483647'/1/2147483646'/2";
    wallet_generate_key(&node, path, private_key_master, chain_code_master);
    hdnode_serialize_public(&node, str, sizeof(str));
    printf("the seed hex:%s\n","fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    printf("the path:%s\n",path);
    printf("the path's public key:%s\n",str);
}

static void sign(void)
{
   uint8_t sig[64], sig2[64], priv_key[32], msg[32], der[256];
    int der_len;
    // secp256k1
    random_bytes(priv_key, sizeof(priv_key), 0);
    random_bytes(msg, sizeof(msg), 0);

    printf("%s\n",utils_uint8_to_hex(priv_key,sizeof(priv_key)));
    printf("%s\n",utils_uint8_to_hex(msg,sizeof(msg)));

    u_assert_int_eq(0, bitcoin_ecc.ecc_sign(priv_key, msg, sizeof(msg), sig, NULL,
                                                ECC_SECP256k1));
    u_assert_int_eq(0, !(der_len = ecc_sig_to_der(sig, der)));
    u_assert_int_eq(0, ecc_der_to_sig(der, der_len, sig2));
    u_assert_mem_eq(sig, sig2, sizeof(sig));

 }
int main(void)
{
    test();
    sign();
    return 0;
}
