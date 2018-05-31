#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "bip32.h"
#include "utils.h"
#include "ecc.h"


int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode);

int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;

    char *kp = strdup(keypath);
    if (!kp) {
        return 1;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, 32);
    memcpy(node->private_key, privkeymaster, 32);
    hdnode_fill_public_key(node);

    char *pch = strtok(kp + 2, delim);
    if (pch == NULL) {
        goto err;
    }
    int has_prm = 0;
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        size_t pch_len = strlens(pch);
        for ( ; i < pch_len; i++) {
            if (strchr(prime, pch[i])) {
                if (i != pch_len - 1) {
                    goto err;
                }
                prm = 1;
                has_prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }
        if (prm && pch_len == 1) {
            goto err;
        }
        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (hdnode_private_ckd_prime(node, idx) != 0) {
                goto err;
            }
        } else {
            if (hdnode_private_ckd(node, idx) != 0) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    if (!has_prm) {
        goto err;
    }
    free(kp);
    return 0;

err:
    free(kp);
    return 1;
}

static void test(char *path)
{
    HDNode node;
    char str[112];
    uint8_t private_key_master[32],chain_code_master[32];
    
    hdnode_from_seed(utils_hex_to_uint8("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),64, &node);
    memcpy(private_key_master,node.private_key,32);
    memcpy(chain_code_master,node.chain_code,32);

    wallet_generate_key(&node, path, private_key_master, chain_code_master);
    hdnode_serialize_public(&node, str, sizeof(str));
    printf("the path: %s\n",path);
    printf("the path's public key: %s\n",str);
    printf("\n");
    
    hdnode_serialize_private(&node, str, sizeof(str));
    printf("the path: %s\n",path);
    printf("the path's private key: %s\n",str);
    printf("\n");
    
}
int main(int argc, char **argv) 

{
    printf("Default seed is:fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542\n");

    if(argc!=2)
   {
 	printf("Error!\nUse:%s path\n",argv[0]);
        printf("Example: %s \"m/0/2147483647'/1/2147483646'/2\"\n",argv[0]);
        printf("Example: %s \"m/0'\"\n",argv[0]);
 	printf("Example: %s \"m/0'/1\"\n",argv[0]);
        exit(1);
   }
    if(argc==2)test(argv[1]);
    return 0;
}
