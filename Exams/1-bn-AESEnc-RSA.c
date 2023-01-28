#include <stdio.h>
#include <string.h>

#include <openssl/rand>
#include <openssl/rsa.h>
#include <openssl/pem.h>


int int main(int argc, char const *argv[])
{
    ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	BIGNUM *rand1 = BN_new();
	BIGNUM *rand2 = BN_new();

	if(RAND_load_file("/dev/random", 64) != 64)
	handle_errors();

	BN_rand(rand1, 128, 0, 1);
	BN_rand(rand2, 128, 0, 1);

	//k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
	//k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128

	BIGNUM *left_member_rand = BN_new();
	BIGNUM *diff_rand = BN_new();
	BIGNUM *k1 = BN_new();
	BIGNUM *k2 = BN_new();
	BIGNUM *mod = BN_new();
	BIGNUM *exp = BN_new();
	BIGNUM *base = BN_new();

	BN_CTX *ctx = BN_CTX_new();

	BN_dec2bn(&exp, "128");
	BN_dec2bn(&base, "2");
	BN_exp(mod, base, exp, ctx);

	BN_add(left_member_rand, rand1, rand2);
	BN_sub(diff_rand, rand1, rand2);

	BN_mul(k1, left_member_rand, diff_rand, ctx);
	BN_mod(k1, k1, mod);

	BN_mul(left_member_rand, rand1, rand2, ctx);
	BN_div(k2, left_member_rand, diff_rand, ctx);
	BN_mod(k2, k2, mod);

	char *c_k1 = BN_bn2hex(k1);
	char *c_k2 = BN_bn2hex(k2);

	ciphertext[strlen(c_k2) + 16];

	//I assume I already had a new iv
	EVP_CIPHER_CTX * aes_ctx= EVP_CIPHER_CTX_NEW();
	EVP_CipherInit(aes_ctx, EVP_aes_128_cbc(), c_k1, iv, 1);

	int update_len, final_len, ciphertext_len = 0;

	EVP_CipherUpdate(ctx, ciphertext, &update_len, c_k2, strlen(c_k2));
	
	ciphertext_len += update_len;
	EVP_CipherFinal_ex(ctx, ciphertext+ciphertext_len, &final_len);
	ciphertext_len += final_len;
	
	
	RSA *rsa_kp = NULL;
	BIGNUM *bne = NULL;

	int bits = 2048;
	unsigned long e = RSA_F4;

	bne = BN_new();
	BN_set_word(bne, e);

	rsa_kp = RSA_new();
	RSA_generate_key_ex(rsa_kp, bits, bne, NULL);

	int enc_data_len;
	unsigned char enc_data[RSA_size(rsa_kp)];

	enc_data_len = RSA_public_encrypt(strlen(ciphertext)+1, ciphertext, enc_data, rsa_kp, RSA_PKCS1_OAEP_PADDING);


	EVP_CIPHER_CTX_free(aes_ctx);
	BN_CTX_free(ctx);

	return 0;
}
