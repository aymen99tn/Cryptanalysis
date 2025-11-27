#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

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

static EVP_PKEY *generate_ec(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");

    const char *curve = "prime256v1";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(ctx) != 1) die("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1) die("EVP_PKEY_CTX_set_params");

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) die("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static size_t ec_sign(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
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

static int ec_verify(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
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

    EVP_PKEY *pkey = generate_ec();

    BIGNUM *priv = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) die("get priv");

    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) != 1) die("pub size");
    unsigned char *pub = malloc(pub_len);
    if (!pub) die("malloc pub");
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, &pub_len) != 1) die("get pub");

    char *priv_hex = BN_bn2hex(priv);

    printf("---------------------------KeyGen:\n");
    printf("ECDSA signing key x = %s\n", priv_hex);
    print_hex("ECDS verification key vk = ", pub, pub_len);

    printf("---------------------------Signing:\n");
    print_hex("Hash of the crypto.img file = ", hash, hash_len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    struct timespec s1, s2, v1, v2;

    clock_gettime(CLOCK_MONOTONIC, &s1);
    sig_len = ec_sign(pkey, fw, fw_len, &sig);
    clock_gettime(CLOCK_MONOTONIC, &s2);
    print_hex("Signature σ = ", sig, sig_len);
    printf("Signing time: %.3f ms\n", elapsed_ms(s1, s2));

    printf("---------------------------Verification:\n");
    clock_gettime(CLOCK_MONOTONIC, &v1);
    int verified = ec_verify(pkey, fw, fw_len, sig, sig_len);
    clock_gettime(CLOCK_MONOTONIC, &v2);
    printf("Verification result: %s\n", verified ? "valid" : "invalid");
    printf("Verification time: %.3f ms\n", elapsed_ms(v1, v2));

    OPENSSL_free(priv_hex);
    BN_free(priv);
    free(pub);
    free(sig);
    free(fw);
    EVP_PKEY_free(pkey);
    return 0;
}
