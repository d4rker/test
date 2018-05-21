#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "wallet.h"
#include "bip32.h"
#include "utils.h"
#include "ecc.h"

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdint.h>

static void test(char *path)
{
    HDNode node;
    char str[112];
    uint8_t private_key_master[32],chain_code_master[32];
    uint8_t msg[32],sig[64];
    int res;
    ECDSA_SIG *signature;
    

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

    memcpy(msg,utils_hex_to_uint8("546869732069732061207665727920636F6E666964656E7469616C206D657373616765"),sizeof(msg));
    res = bitcoin_ecc.ecc_sign(node.private_key, msg, sizeof(msg), sig, NULL,ECC_SECP256k1);
    
    printf("r: %s\n", BN_bn2dec(signature->r));printf("s: %s\n\n", BN_bn2dec(signature->s));
    
    printf("r: %s\n", BN_bn2hex(signature->r));printf("s: %s\n", BN_bn2hex(signature->s));
    printf("\nsig res=%d success!\n",res);

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
