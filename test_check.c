#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <check.h>
#include "check_mem.h"

#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>

#include "options.h"

#include "aes/aes.h"
#include "bignum.h"
#include "base32.h"
#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "ecdsa.h"
#include "pbkdf2.h"
#include "rand.h"
#include "sha2.h"
#include "sha3.h"
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519.h"
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "script.h"
#include "rfc6979.h"
#include "address.h"
#include "rc4.h"
#include "nem.h"

/*
 * This is a clever trick to make Valgrind's Memcheck verify code
 * is constant-time with respect to secret data.
 */

/* Call after secret data is written, before first use */
#define   MARK_SECRET_DATA(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
/* Call before secret data is freed or to mark non-secret data (public keys or signatures) */
#define UNMARK_SECRET_DATA(addr, len) VALGRIND_MAKE_MEM_DEFINED  (addr, len)

#define FROMHEX_MAXLEN 512

#define VERSION_PUBLIC  0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

#define DECRED_VERSION_PUBLIC  0x02fda926
#define DECRED_VERSION_PRIVATE 0x02fda4e8

const uint8_t *fromhex(const char *str)
{
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}


#define test_deterministic(KEY, MSG, K) do { \
	sha256_Raw((uint8_t *)MSG, strlen(MSG), buf); \
	init_rfc6979(fromhex(KEY), buf, &rng); \
	generate_k_rfc6979(&k, &rng); \
	bn_write_be(&k, buf); \
	ck_assert_mem_eq(buf, fromhex(K), 32); \
} while (0)

START_TEST(test_rfc6979)
{
	bignum256 k;
	uint8_t buf[32];
	rfc6979_state rng;

	test_deterministic("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", "sample", "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("trezor-crypto");
	TCase *tc;
	tc = tcase_create("rfc6979");
	tcase_add_test(tc, test_rfc6979);
	suite_add_tcase(s, tc);
	return s;
}

// run suite
int main(void)
{
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}
	return number_failed;
}
