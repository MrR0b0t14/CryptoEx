#include <stdio.h>
#include <string.h>

#include <openssl/rand>
#include <openssl/rsa.h>
#include <openssl/pem.h>


int int main(int argc, char const *argv[])
{
    OpenSSL_add_all_algorithms();

	unsigned char r1[16], r2[16];

	RAND_load_file("dev/random", 64);
	RAND_bytes(r1, 16);
	RAND_bytes(r2, 16);

	BIGNUM *rand1 = BN_new();
	BIGNUM *rand2 = BN_new();

	BN_dec2bn(&rand1, r1);
	BN_dec2bn(&rand2, r2);

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *var1 = BN_new();
	BIGNUM *var2 = BN_new();

	BN_add(var1, rand1, rand2);
	BN_sub(var1, rand1, rand2);

	BIGNUM *exp = BN_new();
	BIGNUM *base = BN_new();
	BIGNUM *mod = BN_new();
	BN_dec2bn(&exp, "128");
	BN_dec2bn(&base, "2");
	BN_exp(mod, base, exp, ctx);

	BIGNUM *k1 = BN_new();
	BIGNUM *k2 = BN_new();

	BN_mul(k1, var1, var2, ctx);
	BN_div(k2, NULL, var1, var2, ctx);

	BN_mod(k1, k1, mod);
	BN_mod(k2, k2, mod);

	char *c_k1 = BN_bn2hex(k1);
	char *c_k2 = BN_bn2hex(k2);

	ciphertext[strlen(c_k2) + 16];

	//I assume I already had a new iv
	EVP_CIPHER_CTX * aes_ctx= EVP_CIPHER_CTX_NEW();
	EVP_CipherInit(aes_ctx, EVP_aes_128_cbc(), c_k1, iv, 1);

	int update_len, final_len, ciphertext_len = 0;

	EVP_CipherUpdate(ctx, ciphertext, &update_len, c_k2, strlen(c_k2));
	EVP_CipherFinal_ex(ctx, ciphertext+ciphertext_len, &final_len);

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