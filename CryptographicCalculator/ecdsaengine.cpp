#include "ecdsaengine.h"
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>
#include "QMessageBox"

#include "QCryptographicHash"

using namespace std;

mpz_t seed;
gmp_randstate_t state;

const char*p_str = "115792089210356248762697446949407573530086143415290314195533631308867097853951";
const char* a_str = "-3";
const char* b_str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const char*Gx_str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const char* Gy_str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const char* n_str = "115792089210356248762697446949407573529996955224135760342422259061068512044369";
int addition(Point *R, Point P, Point Q, mpz_t p, mpz_t a, mpz_t b);
int multiple(Point *R, Point P, mpz_t k, mpz_t p, mpz_t a, mpz_t b);
int multiple2(Point *R, Point P, mpz_t k, mpz_t p, mpz_t a, mpz_t b);

ECDSAengine::ECDSAengine()
{

    mpz_inits(this->n, this->a, this->b, this->p, this->G.x, this->G.y, this->d, this->Q.x, this->Q.y, NULL);
    mpz_set_str(this->p, p_str, 10);
    mpz_set_str(this->n, n_str, 10);

    mpz_set_str(this->G.x, Gx_str, 16);
    mpz_set_str(this->G.y, Gy_str, 16);

    mpz_set_si(this->a, -3);
    mpz_set_str(this->b, b_str, 16);
    gmp_printf("\bsize of n %d\nn = %#Zx\n",strlen(n_str), this->n);
    gmp_printf("Gx = %#Zx\n", this->G.x);
    gmp_printf("Gy = %#Zx\n", this->G.y);
    gmp_printf("p = %#Zx\n", this->p);


    gmp_printf("\n\nn = %Zd\n", this->n);
    gmp_printf("Gx = %Zd\n", this->G.x);
    gmp_printf("Gy = %Zd\n", this->G.y);
    gmp_printf("p = %Zd\na = %Zd\nb = %Zd\n", this->p, this->a, this->b);

}

ECDSAengine::~ECDSAengine(){
//    mpz_clears(this->d, this->Q.x, this->Q.y, this->r, this->s, NULL);
}

void ECDSAengine::generate_key_pair(){

    mpz_inits(this->Q.x, this->Q.y, this->d, NULL);
    mpz_init(seed);
    mpz_set_ui(seed, time(NULL));
    gmp_randinit_mt(state);
    gmp_randseed(state, seed);

    while (mpz_cmp_ui(this->d, 1) < 0) // [1, n-1]
    {
        mpz_urandomb(this->d, state,256);
    }

    multiple(&this->Q, this->G, this->d, p, a, b);

    gmp_printf("\nKey pair:\nd = %#Zx \n", this->d);
    gmp_printf("Qx = %#Zx\nQy = %#Zx\n\n", this->Q.x, this->Q.y);

}

void ECDSAengine::sign(QString msg){
    gmp_printf("________SIGN_______ \n");
    QString hash_string = QString(QCryptographicHash::hash((msg.toUtf8()), QCryptographicHash::Sha256).toHex());
    std::string hash_strtmp = hash_string.toStdString();
    const char* hash_str = hash_strtmp.c_str();
    qDebug("Hash %s ", hash_str);

    mpz_t hash;
    mpz_init_set_str(hash, hash_str, 16);

    gmp_printf("  %#Zx \n", hash);
    gmp_printf("priv %#Zx \n", this->d);
    Point P;
    mpz_t k, tmp;
    mpz_inits(tmp, P.x, P.y, NULL);
    mpz_init_set_ui(s, 0);
    mpz_init_set_ui(r, 0);
    mpz_init_set_ui(k, 0);
    mpz_init(seed);
    mpz_set_ui(seed, time(NULL));
    gmp_randinit_mt(state);
    gmp_randseed(state, seed);


    while (true){
        while(true){
            while(true){
                mpz_urandomm(k, state, n);
                if (mpz_cmp_ui(k, 1) >= 0)
                    break;
            }
                    // P = kG
            multiple(&P, this->G, k, this->p, this->a, this->b);

            gmp_printf("result \n&px = %#Zx\n py = %#Zx\n", P.x, P.y);
            char*k_str = (char*)malloc(MAX);
            mpz_get_str(k_str, 16, k);
            char*p_str = (char*)malloc(MAX);
            mpz_get_str(p_str, 16, P.x);

            mpz_mod(r, P.x, n);
            if (mpz_cmp_ui(r, 0) > 0)
                break;

        }
        gmp_printf("\nkeke = %#Zx\n", k);
        mpz_invert(this->s, k, n);
        gmp_printf("Invert k %#Zx\n\n", this->s);
        mpz_mul(tmp, this->r, this->d);
        mpz_mod(tmp, tmp, n);
        gmp_printf("\nCal r =  %#Zx\n d = %#Zx\n", r, this->d);
        gmp_printf("Cal r*d %#Zx\n\n", tmp);
        mpz_add(tmp, tmp, hash);
        gmp_printf("hash %#Zx\n\n", hash);
        gmp_printf("rd + hash %#Zx\n\n", tmp);
        mpz_mul(this->s, this->s, tmp);
        gmp_printf("k^-1(rd + hash) %#Zx\n\n", this->s);
        mpz_mod(this->s, this->s, n);
        gmp_printf("mod n %#Zx\n\n", this->s);
        if (mpz_cmp_ui(this->s,0) > 0){
            this->convertToDER(this->r, this->s);
            break;
        }
    }
    gmp_printf("_______END_SIGN_______ \n");
    mpz_clears(k, tmp, hash, P.x, P.y, NULL);
}

bool ECDSAengine::verify(QString msg, mpz_t r, mpz_t s){
//void ECDSA::verify(char* msg, mpz_t r, mpz_t s){

    gmp_printf("________VERIFY_______ \n");
    gmp_printf("Qx = %#Zx\nQy = %#Zx\nd = %#Zx\n", this->Q.x, this->Q.y, this->d);
    gmp_printf("s = %#Zx\nr = %#Zx\nn = %#Zx\n", s, r, n);
    mpz_t n_sub_1;
    mpz_init(n_sub_1);
    mpz_sub_ui(n_sub_1, n, 1);
    if (mpz_cmp_ui(s, 1)<0 or mpz_cmp(s, n_sub_1)>0 or mpz_cmp_ui(r, 1)<0 or mpz_cmp(r, n_sub_1)>0){
        printf("Reject signature 1 \n");
        return false;
    }

    QString hash_string = QString(QCryptographicHash::hash((msg.toUtf8()), QCryptographicHash::Sha256).toHex());
    std::string hash_strtmp = hash_string.toStdString();
    const char* hash_str = hash_strtmp.c_str();
    qDebug("Hash %s ", hash_str);

    mpz_t e;
    mpz_init_set_str(e, hash_str, 16);

    mpz_t w, u1, u2;
    mpz_inits(w, u1, u2, NULL);
    mpz_invert(w, s, this->n);
    mpz_mul(u1, e, w);
    mpz_mod(u1, u1, this->n);

    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, this->n);

    gmp_printf("\nu1 =  %#Zx \nu2 = %#Zx\n", u1, u2);
    Point P1, P2, P;
    mpz_inits(P1.x, P1.y, P2.x, P2.y, P.x, P.y, NULL);

    multiple(&P1, this->G, u1, this->p, this->a, this->b);
    gmp_printf("u1*G : \n %#Zx \n  %#Zx\n", P1.x, P1.y);
    multiple(&P2, this->Q, u2, this->p, this->a, this->b);
    gmp_printf("u2*Q : \n %#Zx \n  %#Zx\n", P2.x, P2.y);
    addition(&P, P1, P2, this->p, this->a, this->b);
    gmp_printf("P : \n %#Zx \n  %#Zx\n", P.x, P.y);
    mpz_t x;
    mpz_init(x);
    mpz_mod(x, P.x, n);

    if (mpz_cmp(r, x) == 0){
        gmp_printf("True %#Zx  %#Zx \n", r, x);
        return true;
    }
    else{
        gmp_printf("False  %#Zx  %#Zx  \n", r, x);
        return false;
    }
}

void ECDSAengine::convertToDER(mpz_t r, mpz_t s){
    char* der = (char*)malloc(MAX);
    char* s_str = (char*)malloc(SIZE);
    char* r_str = (char*)malloc(SIZE);
    char* s_final = (char*)malloc(SIZE);
    char* r_final = (char*)malloc(SIZE);
    char* b1 = (char*)malloc(2);
    char* b2 = (char*)malloc(2);
    char* b3 = (char*)malloc(2);
    mpz_get_str(s_str, 16, s);
    mpz_get_str(r_str, 16, r);
    strcpy(s_final, "");
    if (strlen(s_str)%2 >0)
        strcpy(s_final, "0");
    strcat(s_final, s_str);
    int x = 0;
    strcpy(r_final, "");
    if ((strlen(r_str)+strlen(s_final))%4>0){
        x = 4 - (strlen(r_str)+strlen(s_final))%4;
        switch(x){
        case 1:
            strcpy(r_final, "0");

            break;
        case 2:
             strcpy(r_final, "00");
              break;
        case 3:
              strcpy(r_final, "000");
              break;
        }
    }

    strcat(r_final, r_str);
    int l = strlen(s_final);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_ui(tmp, l/2);
    mpz_get_str(b3, 16, tmp);

    l = strlen(r_final);
    mpz_set_ui(tmp, l/2);
    mpz_get_str(b2, 16, tmp);

    l = strlen(s_final) + strlen(r_final) + 8;
    mpz_set_ui(tmp, l/2);
    mpz_get_str(b1, 16, tmp);
    sprintf(der, "30%s02%s%s02%s%s",b1, b2, r_final, b3, s_final);
    this->der = (char*)malloc(strlen(der));
    strcpy(this->der, der);
}

void ECDSAengine::convertDerToRaw(const char* der, mpz_t r, mpz_t s){
    char b1_str[2];
    char b2_str[2];

    printf("%s\n len = %zu\n", der, strlen(der));
    memcpy(b1_str, der+6, 2);
    int b1 = std::stol(b1_str, nullptr, 16)*2;
    char r_str[b1];
    memcpy(r_str, der + 8, b1);
    r_str[b1] = '\0';
    qDebug("Verify2\nr = %s", r_str);
    mpz_set_str(r, r_str, 16);
    printf("b1 = %d\nr = %s\nlen = %zu\n", b1, r_str, strlen(r_str));
    memcpy(b2_str, der+8+b1+2, 2);
    int b2= std::stol(b2_str, nullptr, 16)*2;
    char s_str[b2];
    memcpy(s_str, der + 8+ b1+4, b2);
    s_str[b2] = '\0';
    printf("b2 = %d\ns = %s\nlen = %zu\n", b2, s_str, strlen(s_str));
    qDebug("Verify2\ns = %s", s_str);
    mpz_set_str(s, s_str, 16);

}

int doublement(Point *R, Point P, mpz_t p, mpz_t a, mpz_t b){

    // if ((sur_courbe(P, p, a, b) == 0)){
    //     printf("P is not on the curve.... \n");
    //     return -1;
    // }

    if (mpz_cmp_ui(P.y, 0) == 0){
        // if P is on the curve and P.y = 0 => 2.P = infinity
        mpz_init_set_si(R->x, -1);
        mpz_init_set_si(R->y, -1);
        return 1;
    }

    mpz_t lamda, above, below, tmp;
    mpz_inits(lamda, above, below, tmp, R->x, R->y, NULL);

    mpz_mul(above, P.x, P.x);
    mpz_mul_ui(above, above, 3);
    mpz_add(above, above, a);
    mpz_mul_ui(below, P.y, 2);
    mpz_invert(below, below, p);
    mpz_mul(lamda, above, below);
    mpz_mod(lamda, lamda, p);

    mpz_pow_ui(R->x, lamda, 2);
    mpz_mul_ui(tmp, P.x, 2);
    mpz_sub(R->x, R->x, tmp);
    mpz_mod(R->x, R->x, p);

    mpz_sub(R->y, P.x, R->x);
    mpz_mul(R->y, lamda, R->y);
    mpz_sub(R->y, R->y, P.y);
    mpz_mod(R->y, R->y, p);
    mpz_clears(lamda, above, below, tmp, NULL);
    return 0;
}


int addition(Point *R, Point P, Point Q, mpz_t p, mpz_t a, mpz_t b){

    // if ((sur_courbe(P, p, a, b) == 0) || (sur_courbe(Q, p, a, b) ==0)){
    //     return -1;
    // }



    if (mpz_cmp(P.x, Q.x) == 0){
        if (mpz_cmp(P.y, Q.y) == 0)
            return doublement(R, P, p, a, b);

        // if P and Q are on the curve and P.x = Q.x => P + Q = infinity
        mpz_init_set_si(R->x, -1);
        mpz_init_set_si(R->y, -1);
        return 1;
    }
    if (mpz_cmp_ui(P.x, 0) == 0 && mpz_cmp_ui(P.y, 0) == 0){
        mpz_init_set(R->x, Q.x);
        mpz_init_set(R->y, Q.y);
        return 0;
    }

    if (mpz_cmp_ui(Q.x, 0) == 0 && mpz_cmp_ui(Q.y, 0) == 0){
        mpz_init_set(R->x, P.x);
        mpz_init_set(R->y, P.y);
        return 0;
    }

    mpz_t lamda, above, below;
    mpz_inits(lamda, above, below, R->x, R->y, NULL);
    mpz_sub(above, Q.y, P.y);
    mpz_sub(below, Q.x, P.x);
    mpz_invert(below, below, p);
    mpz_mul(lamda, above, below);
    mpz_mod(lamda, lamda, p);

    mpz_pow_ui(R->x, lamda, 2);
    mpz_sub(R->x, R->x, P.x);
    mpz_sub(R->x, R->x, Q.x);
    mpz_mod(R->x, R->x, p);

    mpz_sub(R->y, P.x, R->x);
    mpz_mul(R->y, lamda, R->y);
    mpz_sub(R->y, R->y, P.y);
    mpz_mod(R->y, R->y, p);

    mpz_clears(lamda, above, below, NULL);

    return 0;
}
int multiple(Point *R, Point P, mpz_t k, mpz_t p, mpz_t a, mpz_t b)
{
    gmp_printf("#multiple k = %#Zx\nP.x = %#Zx\nP.y =%#Zx\n",k, P.x, P.y);
    if (mpz_cmp_ui(P.y, 0) == 0)
    {
        printf("Py = 0\n");
        return -1;
    }

    char k_bin[MAX];
    mpz_get_str(k_bin, 2, k);

    Point Q;
    mpz_inits(R->x, R->y, Q.x, Q.y, NULL);
    mpz_set(Q.x, P.x);
    mpz_set(Q.y, P.y);

    int check = 1;
    int state = 0;

    for (int i = strlen(k_bin) - 1; i >= 0; i--)
    {
        if (k_bin[i] == '1')
        {
            if (check == 1)
            {
                mpz_set(R->x, Q.x);
                mpz_set(R->y, Q.y);
                check = 0;

            }
            else
            {
                state = addition(R, *R, Q, p, a, b); // R <- R + Q

                if (state == 1)
                    check = 1;
            }
        }
        // Q <- 2Q
        // gmp_printf("Rx = %Zd\nRy = %Zd\n\n", R->x, R->y);
        // gmp_printf("Qx = %Zd\nQy = %Zd\n", Q.x, Q.y);
        if (doublement(&Q, Q, p, a, b) == 1){
            return 0;
        }else{
            // gmp_printf("double Qx = %Zd\nQy = %Zd\n\n", Q.x, Q.y);
        }
    }
     return 0;
}

int multiple2(Point *R, Point P, mpz_t k, mpz_t p, mpz_t a, mpz_t b){


    if (mpz_cmp_ui(k, 0) == 0){
        mpz_set_ui(R->x, 0);
        mpz_set_ui(R->y, 0);
    }

    if (mpz_cmp_ui(k, 1) == 0){
        mpz_set(R->x, P.x);
        mpz_set(R->y, P.y);
    }

    if (mpz_cmp_ui(k, 1) > 0){
        int bit_size = mpz_sizeinbase(k, 2);

        Point T, RT, TT; // temp
        mpz_inits(T.x, T.y, NULL);
        mpz_inits(TT.x, TT.y, NULL);
        mpz_inits(RT.x, RT.y, NULL);
        mpz_set(T.x, P.x);
        mpz_set(T.y, P.y);
        mpz_set(TT.x, P.x);
        mpz_set(TT.y, P.y);
//        ec_point_set(&T, P.x, P.y);
//        ec_point_set(&TT, P.x, P.y);
        for (int i=0; i < bit_size; i++){
            if (mpz_tstbit(k, i) == 1){
                mpz_set(RT.x, R->x);
                mpz_set(RT.y, R->y);
//                ec_point_set(&RT, R->x, R->y);
                addition(R, RT, T, p, a, b);
            }
            doublement(&T, TT, p, a, b);
//            ec_point_set(&TT, T.x, T.y);
            mpz_set(TT.x, T.x);
            mpz_set(TT.y, T.y);
        }

    }
    return 1;
}



