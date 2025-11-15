#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#define MSG_SIZE (1024*1024)
#define AES_KEY_SIZE 32
#define IV_LEN 12
#define TAG_LEN 16

void err() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

void print_hex(const char *label, unsigned char *buf, size_t len) {
    printf("%s\n", label);
    for (size_t i = 0; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n\n");
}


EVP_PKEY* gen_rsa() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    unsigned int bits = 2048;
    unsigned int exponent = 65537;

    if (!ctx)
        err();

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        err();

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("pubexp", &exponent);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
        err();

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        err();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int aes_gcm_encrypt(unsigned char *pt, int ptlen,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *ct, unsigned char *tag) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ctlen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen);
    ctlen = len;

    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ctlen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ctlen;
}

int aes_gcm_decrypt(unsigned char *ct, int ctlen,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *tag, unsigned char *pt) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ptlen;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, pt, &ptlen, ct, ctlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    if (EVP_DecryptFinal_ex(ctx, pt + ptlen, &len) <= 0)
        err();

    ptlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ptlen;
}

int rsa_encrypt(EVP_PKEY *pk,
                unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen) {

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(pk, NULL);
    if (!c) err();

    if (EVP_PKEY_encrypt_init(c) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_oaep_md(c, EVP_sha256()) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(c, EVP_sha256()) <= 0) err();

    /* Query output length first */
    size_t need = 0;
    if (EVP_PKEY_encrypt(c, NULL, &need, in, inlen) <= 0) err();
    if (*outlen < need) {
        EVP_PKEY_CTX_free(c);
        fprintf(stderr, "rsa_encrypt: output buffer too small (need %zu, have %zu)\n", need, *outlen);
        return 0;
    }

    if (EVP_PKEY_encrypt(c, out, outlen, in, inlen) <= 0) err();

    EVP_PKEY_CTX_free(c);
    return 1;
}

int rsa_decrypt(EVP_PKEY *sk,
                unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen) {

    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(sk, NULL);
    if (!c) err();

    if (EVP_PKEY_decrypt_init(c) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_oaep_md(c, EVP_sha256()) <= 0) err();
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(c, EVP_sha256()) <= 0) err();

    size_t need = 0;
    if (EVP_PKEY_decrypt(c, NULL, &need, in, inlen) <= 0) err();
    if (*outlen < need) {
        EVP_PKEY_CTX_free(c);
        fprintf(stderr, "rsa_decrypt: output buffer too small (need %zu, have %zu)\n", need, *outlen);
        return 0;
    }

    if (EVP_PKEY_decrypt(c, out, outlen, in, inlen) <= 0) err();

    EVP_PKEY_CTX_free(c);
    return 1;
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_PKEY *key = gen_rsa();

    unsigned char *M = malloc(MSG_SIZE);
    unsigned char *M2 = malloc(MSG_SIZE);
    RAND_bytes(M, MSG_SIZE);

    unsigned char K[AES_KEY_SIZE];
    RAND_bytes(K, AES_KEY_SIZE);

    unsigned char iv[IV_LEN];
    RAND_bytes(iv, IV_LEN);

    unsigned char *C = malloc(MSG_SIZE+16);
    unsigned char tag[TAG_LEN];

    int clen = aes_gcm_encrypt(M, MSG_SIZE, K, iv, C, tag);

    size_t rk_size = EVP_PKEY_size(key);
    unsigned char *CK = malloc(rk_size);
    size_t CK_len = rk_size;

    rsa_encrypt(key, K, AES_KEY_SIZE, CK, &CK_len);

    unsigned char *K2 = malloc(rk_size);
    size_t K2_len = rk_size;

    rsa_decrypt(key, CK, CK_len, K2, &K2_len);

    int dlen = aes_gcm_decrypt(C, clen, K2, iv, tag, M2);

    print_hex("The AES key in hex K:", K, AES_KEY_SIZE);
    print_hex("First 32 bytes of M:", M, 32);
    print_hex("Printing Crsa:", CK, CK_len);
    print_hex("First 32 bytes of Caes:", C, 32);
    print_hex("Decrypted AES key K2:", K2, AES_KEY_SIZE);
    print_hex("Decrypted first 32 bytes of M:", M2, 32);
    if (memcmp(M, M2, MSG_SIZE) != 0)
        err();

    free(M);
    free(M2);
    free(C);
    free(CK);
    free(K2);
    EVP_PKEY_free(key);
    return 0;
}