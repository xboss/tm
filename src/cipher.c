#include "cipher.h"

#include <assert.h>
#include <openssl/aes.h>
#include <string.h>

#include "utils.h"

static const int align_size = 16;
static char *pkcs7_padding(const char *in, int in_len, int *out_len) {
    int remainder = in_len % align_size;
    int padding_size = remainder == 0 ? align_size : align_size - remainder;
    *out_len = in_len + padding_size;
    char *out = (char *)malloc(*out_len);
    memcpy(out, in, in_len);
    memset(out + in_len, padding_size, padding_size);
    return out;
}

static int pkcs7_unpadding(const char *in, int in_len) {
    char padding_size = in[in_len - 1];
    return (int)padding_size;
}

char *pwd2key(const char *pwd) {
    size_t pwd_len = strnlen(pwd, CIPHER_KEY_LEN);

    char *key = (char *)_CALLOC(1, CIPHER_KEY_LEN + 1);
    memcpy(key, pwd, pwd_len);
    return key;
}

char *aes_encrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    if (!key || !iv) {
        return NULL;
    }
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        return NULL;
    }

    char *after_padding_buf = pkcs7_padding(in, in_len, out_len);
    char *out_buf = (char *)malloc(*out_len);
    memset(out_buf, 0, *out_len);
    AES_cbc_encrypt((const unsigned char *)after_padding_buf, (unsigned char *)out_buf, *out_len, &aes_key,
                    (unsigned char *)iv, AES_ENCRYPT);
    _FREE_IF(after_padding_buf);
    return out_buf;
}

char *aes_decrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len) {
    if (!key || !iv) {
        return NULL;
    }
    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char *)key, 128, &aes_key);
    char *out_buf = malloc(in_len);
    memset(out_buf, 0, in_len);
    AES_cbc_encrypt((const unsigned char *)in, (unsigned char *)out_buf, in_len, &aes_key, (unsigned char *)iv,
                    AES_DECRYPT);
    *out_len = in_len - pkcs7_unpadding(out_buf, in_len);
    return out_buf;
}