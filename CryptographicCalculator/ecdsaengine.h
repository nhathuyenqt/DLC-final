#ifndef ECDSAENGINE_H
#define ECDSAENGINE_H

#include "gmp.h"
#include "time.h"
#include "QString"

#define MAX 99999
#define SIZE 1024

struct Point{
    mpz_t x, y;
};

class ECDSAengine{
public:
    ECDSAengine();
    ~ECDSAengine();
    void generate_key_pair();
    void sign(QString msg);
    void convertToDER(mpz_t r, mpz_t s);
    void convertDerToRaw(const char* der, mpz_t r, mpz_t s);
    bool verify(QString msg, mpz_t r, mpz_t s);
    char* hash(char* msg);


    mpz_t s, r;
    char* der;
    mpz_t a, b, p, n, d;
    Point G, Q;
};

#endif // ECDSAENGINE_H
