#include <stdio.h>
#include <openssl/rand.h>
#include <string.h>
#include <openssl/evp.h>

#define LEN 32
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

int main(int argc, char const *argv[]){

	OpenSSL_add_all_algorithms();

	RSA *bob_pubkey;
	FILE *file_in; /*suppose it already open*/

	unsigned char aes_key[LEN];
	unsigned char iv[16];

	RAND_load_file("/dev/random", 64);
	RAND_bytes(aes_key,LEN);
	RAND_bytes(iv,16);

    unsigned char encrypted_aes_key[RSA_size(bob_pubkey)];


	RSA_public_encrypt(strlen(aes_key)+1, aes_key, encrypted_aes_key, bob_pubkey, RSA_PKCS1_OAEP_PADDING);

	send_bob(encrypted_aes_key);
	send_bob(iv);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aes_256_cbc(), aes_key, iv, 1);

    unsigned char ciphertext[MAX_ENC_LEN];

    int update_len, final_len;
    int ciphertext_len=0;
    int n_read;
    unsigned char buffer[MAX_BUFFER];


    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
    	EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,buffer,n_read);
        ciphertext_len+=update_len;
    }

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len)

    ciphertext_len+=final_len;

    send_bob(ciphertext);

    EVP_CIPHER_CTX_free(ctx);



	return 0;
}