#ifndef _CIPHER_H
#define _CIPHER_H

#define CIPHER_KEY_LEN 16
#define CIPHER_IV_LEN 16

char *aes_encrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len);
char *aes_decrypt(const char *key, const char *iv, const char *in, int in_len, int *out_len);
char *pwd2key(const char *pwd);

#endif  // CIPHER_H