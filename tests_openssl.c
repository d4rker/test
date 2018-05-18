#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>

#include "ecc.h"
#include "random.h"
#include "utils.h"

uint8_t priv_bytes[32] = {
    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };

const char message[] = "This is a very confidential message\n";
const char digest_exp[] = "4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01";

int main(int argc, char *argv[])
{
    uint8_t sig[64], pub_key33[33], pub_key65[65],hash[32];

    bitcoin_ecc.ecc_sign(priv_bytes, utils_hex_to_uint8(digest_exp), sizeof(digest_exp), sig, NULL, ECC_SECP256k1);
    //sign 
   

    bitcoin_ecc.ecc_get_public_key33(priv_key, pub_key33, ECC_SECP256k1);

    bitcoin_ecc.ecc_get_public_key65(priv_key, pub_key65, ECC_SECP256k1);
    
    bitcoin_ecc.ecc_verify(pub_key65, sig, msg, msg_len, curve)
    bitcoin_ecc.ecc_verify(pub_key33, sig, msg, msg_len, curve)
        
    // copy signature to the OpenSSL struct
    ECDSA_SIG *signature = ECDSA_SIG_new();
    BN_bin2bn(sig, 32, signature->r);
    BN_bin2bn(sig + 32, 32, signature->s);

    printf("%s\n",BN_bn2dec(signature->r));
    printf("%s\n",BN_bn2dec(signature->s));
    return 0;
}
