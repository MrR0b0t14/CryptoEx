#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

char *process(char *data, int lenght, RSA *rsa_priv_key);

char *process(char *data, int lenght, RSA *rsa_priv_key){

	unsigned char decrypted_data[RSA_size(rsa_priv_key)];

	if ((int)strlen(data) > RSA_size(rsa_priv_key)){
		return NULL
	}

	if(RSA_private_decrypt(strlen(data), (unsigned char*) data, decrypted_data, rsa_priv_key, RSA_PKCS1_OAEP_PADDING) == -1)
		return NULL;

	EVP_MD_CTX *md; 

	md = EVP_MD_CTX_new();
	
	EVP_DigestInit(md, EVP_sha256());
	EVP_DigestUpdate(md, decrypted_data, strlen(decrypted_data));
	
	unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;
    
    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

	unsigned char result[3];

	result[0] = decrypted_data[strlen(decrypted_data)-1];
	result[1] = md_value[md_len-1];
	result[2] = result[0] ^ result[1];

	return result;

}

