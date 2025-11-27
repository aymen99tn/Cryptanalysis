#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define FW_PATH "crypto.img"
#define FW_SIZE 2048

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1e6;
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

static void ensure_firmware(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size == FW_SIZE) return;

    FILE *f = fopen(path, "wb");
    if (!f) die("fopen firmware");

    unsigned char *buf = malloc(FW_SIZE);
    if (!buf) die("malloc firmware");
    if (RAND_bytes(buf, FW_SIZE) != 1) die("RAND_bytes");
    if (fwrite(buf, 1, FW_SIZE, f) != FW_SIZE) die("fwrite firmware");

    free(buf);
    fclose(f);
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen read");

    if (fseek(f, 0, SEEK_END) != 0) die("fseek");
    long sz = ftell(f);
    if (sz < 0) die("ftell");
    rewind(f);

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) die("malloc read");
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) die("fread");
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

static unsigned int sha3_hash(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("EVP_MD_CTX_new");
    unsigned int out_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) die("EVP_DigestInit_ex");
    if (EVP_DigestUpdate(ctx, data, len) != 1) die("EVP_DigestUpdate");
    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) die("EVP_DigestFinal_ex");

    EVP_MD_CTX_free(ctx);
    return out_len;
}

static EVP_PKEY *generate_rsa(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");

    unsigned int bits = 2048;
    unsigned int exp = 65537;
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_BITS, &bits);
    params[1] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &exp);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(ctx) != 1) die("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1) die("EVP_PKEY_CTX_set_params");

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) die("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static size_t rsa_sign(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
                       unsigned char **sig) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) die("EVP_MD_CTX_new");

    if (EVP_DigestSignInit(mctx, NULL, EVP_sha3_256(), NULL, pkey) != 1) die("EVP_DigestSignInit");
    if (EVP_DigestSignUpdate(mctx, msg, msg_len) != 1) die("EVP_DigestSignUpdate");

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mctx, NULL, &sig_len) != 1) die("EVP_DigestSignFinal size");

    *sig = malloc(sig_len);
    if (!*sig) die("malloc sig");
    if (EVP_DigestSignFinal(mctx, *sig, &sig_len) != 1) die("EVP_DigestSignFinal");

    EVP_MD_CTX_free(mctx);
    return sig_len;
}

static int rsa_verify(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
                      const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) die("EVP_MD_CTX_new verify");

    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha3_256(), NULL, pkey) != 1) die("EVP_DigestVerifyInit");
    if (EVP_DigestVerifyUpdate(mctx, msg, msg_len) != 1) die("EVP_DigestVerifyUpdate");

    int rc = EVP_DigestVerifyFinal(mctx, sig, sig_len);
    EVP_MD_CTX_free(mctx);
    return rc == 1;
}

int main(void) {
    ensure_firmware(FW_PATH);

    size_t fw_len = 0;
    unsigned char *fw = read_file(FW_PATH, &fw_len);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = sha3_hash(fw, fw_len, hash);

    EVP_PKEY *pkey = generate_rsa();

    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1) die("get n");
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) die("get e");
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) != 1) die("get d");

    char *d_hex = BN_bn2hex(d);
    char *n_hex = BN_bn2hex(n);
    char *e_hex = BN_bn2hex(e);

    printf("---------------------------KeyGen:\n");
    printf("RSA signing key d = %s\n", d_hex);
    printf("RSA verification key vk = (e, n) = (%s, %s)\n", e_hex, n_hex);

    printf("---------------------------Signing:\n");
    print_hex("Hash of the crypto.img file = ", hash, hash_len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    struct timespec s1, s2, v1, v2;

    clock_gettime(CLOCK_MONOTONIC, &s1);
    sig_len = rsa_sign(pkey, fw, fw_len, &sig);
    clock_gettime(CLOCK_MONOTONIC, &s2);
    print_hex("Signature σ = ", sig, sig_len);
    printf("Signing time: %.3f ms\n", elapsed_ms(s1, s2));

    printf("---------------------------Verification:\n");
    clock_gettime(CLOCK_MONOTONIC, &v1);
    int verified = rsa_verify(pkey, fw, fw_len, sig, sig_len);
    clock_gettime(CLOCK_MONOTONIC, &v2);
    printf("Verification result: %s\n", verified ? "valid" : "invalid");
    printf("Verification time: %.3f ms\n", elapsed_ms(v1, v2));

    printf("Comparison note: compare these timings with ECDSA.c (P-256); RSA-2048 signing is typically slower while verification is faster.\n");

    OPENSSL_free(d_hex);
    OPENSSL_free(n_hex);
    OPENSSL_free(e_hex);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    free(sig);
    free(fw);
    EVP_PKEY_free(pkey);
    return 0;
}