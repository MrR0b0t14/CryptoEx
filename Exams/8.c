#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>



#define ENCRYPT 1
#define DECRYPT 0
#define MAX_ENC_LEN 1000000



void handle_errors(){
    ERR_print_errors_fp(stderr);
    return 1;
}


int envelop_MAC(RSA *rsa keypair, char *message, int message len, char *key, int keylenght, char* result);
/*
	RSA encrypt(public key, SHA_256( SHA 256 (message||key) ))
*/

int envelop_MAC(RSA *rsa keypair, char *message, int message len, char *key, int keylenght, char* result){

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	unsigned char iv[EVP_Cipher_get_block_size(EVP_aes_256_cbc())];

    RAND_load_file("/dev/random", 64);
    RAND_bytes(iv,16);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!EVP_CipherInit(ctx,EVP_aes_256_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char ciphertext[MAX_ENC_LEN];
    unsigned char final_ciphertext[MAX_ENC_LEN];

    int update_len, final_len;
    int ciphertext_len=0;

    if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,message,strlen(message)))
        handle_errors();
    ciphertext_len+=update_len;

    if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,key,keylenght)
        handle_errors();
    ciphertext_len+=update_len;

    if(!EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
	if(!EVP_CipherInit(ctx,EVP_aes_256_cbc(), key, iv, ENCRYPT))
        handle_errors();
    update_len=0; 
    final_len=0;
    ciphertext_len=0;


    EVP_CipherUpdate(ctx,final_ciphertext,&update_len,ciphertext,strlen(ciphertext));
    ciphertext_len+=update_len;
    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(keypair)];

    if ((int)strlen(final_ciphertext) > RSA_size(keypair)){
    	return 1;
    }

    if((encrypted_data_len = RSA_public_encrypt(strlen(final_ciphertext)+1, final_ciphertext, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();


    result = encrypted_data;

    return 0;

}