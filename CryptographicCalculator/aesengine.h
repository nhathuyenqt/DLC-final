#ifndef AESENGINE_H
#define AESENGINE_H
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

class AESengine
{
public:
    AESengine();
    unsigned char* encrypt(const char *plain_const, int plaintext_len, int keysize,const char *key_const,const char *iv_const,int *cipher_len);
    unsigned char* decrypt(const char *cipher_const, int ciphertext_len, int keysize, const char *key_const, const char *iv_const, int *plain_len);
    char* encrypt_file(const char *filepath, const char *mode, int keysize, const char *key_const, const char *iv_const);
    char* decrypt_file(const char *filepath, const char *mode, int keysize, const char *key_const, const char *iv_const);
};

#endif // AESENGINE_H
