#ifndef HMACENGINE_H
#define HMACENGINE_H
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>

class HMACengine
{
public:
    HMACengine();
    unsigned char* calculate(const char* filepath, const char* key, int *hmac_len,int mode, int* signal);
};

#endif // HMACENGINE_H
