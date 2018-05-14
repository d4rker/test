/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"

#ifdef ENABLE_OPENSSL_TESTS
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif

#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"

#if !defined(VG_CHECK)
# if defined(VALGRIND)
#  include <valgrind/memcheck.h>
#  define VG_UNDEF(x,y) VALGRIND_MAKE_MEM_UNDEFINED((x),(y))
#  define VG_CHECK(x,y) VALGRIND_CHECK_MEM_IS_DEFINED((x),(y))
# else
#  define VG_UNDEF(x,y)
#  define VG_CHECK(x,y)
# endif
#endif

static int count = 64;

void random_scalar_order_test(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_rand256_test(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}


void test_ecdsa_end_to_end(void) {
    unsigned char extra[32] = {0x00};
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char privkey2[32];
    secp256k1_ecdsa_signature signature[6];
    secp256k1_scalar r, s;
    unsigned char sig[74];
    size_t siglen = 74;
    unsigned char pubkeyc[65];
    size_t pubkeyclen = 65;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey_tmp;
    unsigned char seckey[300];
    size_t seckeylen = 300;

    /* Generate a random key and message. */
    {
        secp256k1_scalar msg, key;
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_scalar_get_b32(message, &msg);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Verify exporting and importing public key. */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, secp256k1_rand_bits(1) == 1 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
    memset(&pubkey, 0, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);

    /* Verify negation changes the key and changes it back */
    memcpy(&pubkey_tmp, &pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) != 0);
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) == 0);

    /* Verify private key import and export. */
    CHECK(ec_privkey_export_der(ctx, seckey, &seckeylen, privkey, secp256k1_rand_bits(1) == 1));
    CHECK(ec_privkey_import_der(ctx, privkey2, seckey, seckeylen) == 1);
    CHECK(memcmp(privkey, privkey2, 32) == 0);

    /* Optionally tweak the keys using addition. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_add(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_mul(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Sign. */
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[4], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[1], message, privkey, NULL, extra) == 1);
    extra[31] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[2], message, privkey, NULL, extra) == 1);
    extra[31] = 0;
    extra[0] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[3], message, privkey, NULL, extra) == 1);
    CHECK(memcmp(&signature[0], &signature[4], sizeof(signature[0])) == 0);
    CHECK(memcmp(&signature[0], &signature[1], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[2], &signature[3], sizeof(signature[0])) != 0);
    /* Verify. */
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
    /* Test lower-S form, malleate, verify and fail, test again, malleate again */
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[0]));
    secp256k1_ecdsa_signature_load(ctx, &r, &s, &signature[0]);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 0);
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    CHECK(memcmp(&signature[5], &signature[0], 64) == 0);

    /* Serialize/parse DER and verify again */
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    memset(&signature[0], 0, sizeof(signature[0]));
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    /* Serialize/destroy/parse DER and verify again. */
    siglen = 74;
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    sig[secp256k1_rand_int(siglen)] += 1 + secp256k1_rand_int(255);
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 0 ||
          secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 0);
}
void run_ecdsa_end_to_end(void) {
    int i;
    for (i = 0; i < 64*count; i++) {
        test_ecdsa_end_to_end();
    }
}

int main(void) {
    run_ecdsa_end_to_end();
    printf("no problems found\n");
    return 0;
}
