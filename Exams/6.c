#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <string.h>

#define LEN 32
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

int main(int argc, char const *argv[]){

	OpenSSL_add_all_algorithms();

	unsigned char r1[LEN];
	unsigned char r2[LEN];
	unsigned char key_symm[LEN];
	unsigned char iv[EVP_CIPHER_get_block_size(EVP_aes_256_cbc())];


    RAND_load_file("/dev/random", 64); //optional on Linux
    
    RAND_bytes(r1,LEN);
    RAND_bytes(r1,LEN);

    int i=0;

    for (i = 0; i < LEN; i++){
    	key_symm[i] = r1[i] ^ r2[i]; 
    }

    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    bne = BN_new();
    BN_set_word(bne,e);

    rsa_keypair = RSA_new();
    RSA_generate_key_ex(rsa_keypair, bits, bne, NULL);

    FILE *fp; 
    fp = fopen("privkey.pem", "w");

    PEM_write_RSAPrivateKey(fp, rsa_keypair, EVP_aes_256_cbc, key_symm, strlen(key_symm), NULL, NULL);

    /*
		the payload is in the file
    */

	return 0;
}