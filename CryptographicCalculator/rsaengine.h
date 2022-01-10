#ifndef RSAENGINE_H
#define RSAENGINE_H
#include "gmp.h"
#include "time.h"

struct secket_key
{
    mpz_t p;
    mpz_t q;
    mpz_t d_p;
    mpz_t d_q;
    mpz_t I_p;
};

class RSAengine
{
public:
    RSAengine();
    void genKey(mpz_t, mpz_t, unsigned int, unsigned int);
    char* encrypt_rsa(const char* txt_m, const char* txt_n,const char* txt_e);
    char* encrypt_rsa_ascii(const char* txt_m, const char* txt_n,const char* txt_e);
    char* decrypt_rsa(const char* c, const char* txt_n,const char* txt_d);
    char* sign_rsa(const char *str, const char *d, const char *n);
    char* verify_rsa(const char *str, const char *e, const char *n);

};

#endif // RSAENGINE_H
