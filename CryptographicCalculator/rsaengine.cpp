#include "rsaengine.h"
#include <QDebug>
#include <QCryptographicHash>
RSAengine::RSAengine()
{

}

void gen_prime(mpz_t res, unsigned long int k, unsigned long int e, gmp_randstate_t prng){


    mpz_t res_1, tmp, res_min;
    mpz_inits(res_1, tmp, res_min, NULL);
    mpz_set_ui(res_min,1);
    mpz_ui_pow_ui(res_min, 2, k-1);

    do{
        mpz_urandomb(res, prng, k);
        mpz_add(res, res, res_min);
        mpz_nextprime(res, res);
        mpz_sub_ui(res_1, res, 1);
        mpz_gcd_ui(tmp, res_1, e);

    } while (mpz_cmp_ui(tmp, 1) != 0);
    // gmp_printf("Random number is %Zu \n", res);

    mpz_clears(res_1, tmp, res_min, NULL);
}
void RSAengine::genKey(mpz_t n, mpz_t d, unsigned int k, unsigned int e){
    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_ui(prng, time(NULL));


    mpz_t p, q, tmp, p_1, q_1, e_z, phi_n;
    mpz_inits(p, q, n, d, tmp, p_1, q_1, phi_n, e_z,  NULL);
    mpz_set_ui(e_z, e);
    gen_prime(p, k/2-1, e, prng);
    gen_prime(q, k/2-1, e, prng);

    // Calculate n
    mpz_mul(n, p, q);
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    //calculate phi n
    mpz_mul(phi_n, p_1, q_1);
    mpz_invert(d, e_z, phi_n);
    gmp_printf("n = %Zx\n", n);
//    gmp_printf("p = %Zu\n", p);
//    gmp_printf("d = %Zu\n", d);
//    gmp_printf("q = %Zu\n", q);
}

char* RSAengine::encrypt_rsa(const char* txt_m, const char* txt_n, const char* txt_e){
    mpz_t c, m, n, e;
    char *result = (char*)malloc(strlen(txt_n)*4*sizeof(char));;
    mpz_inits(c ,m, n, e, NULL);
    mpz_set_str(m, txt_m, 16);
    mpz_set_str(n, txt_n, 16);
    mpz_set_str(e, txt_e, 10);
//    printf("txt_n = %s\n", txt_n);
//    gmp_printf("e = %Zx\n", e);
//    gmp_printf("n = %Zx\n", n);
    mpz_powm(c, m, e, n);
    mpz_get_str(result, 16, c);
    printf("res = %s\n", result);
    mpz_clears(c, m, n, e, NULL);
    return result;
}
char* RSAengine::encrypt_rsa_ascii(const char* txt_m, const char* txt_n, const char* txt_e){
    char *result = (char*)malloc(strlen(txt_n)*4*sizeof(char));
    char * hex_m= (char*)malloc(strlen(txt_n)*4*sizeof(char));
    // Convert plaintext to hexadecimal
    for (size_t i = 0; i < strlen(txt_m); i++)
        sprintf(hex_m + 2 * i, "%02x", txt_m[i]);
    result = encrypt_rsa(hex_m, txt_n, txt_e);
    free(hex_m);
    return result;
}



char* RSAengine::decrypt_rsa(const char* txt_c, const char* txt_n, const char* txt_d){
    mpz_t  c, m, n, d;
    char *result = (char*)malloc(strlen(txt_n)*4*sizeof(char));
    mpz_inits(c, m, n, d, NULL);
    mpz_set_str(c, txt_c, 16);
    mpz_set_str(n, txt_n, 16);
    mpz_set_str(d, txt_d, 16);
    printf("txt_c = %s\n", txt_c);
    gmp_printf("n = %Zx\n", n);
    gmp_printf("d = %Zx\n", d);
    mpz_powm(m, c, d, n);
    gmp_printf("m = %Zx\n", m);
    mpz_get_str(result, 16, m);
    mpz_clears(m, c, n, d, NULL);
    return result;
}

char* RSAengine::sign_rsa(const char *str, const char *txt_d, const char *txt_n){
    char *result = (char*)malloc(strlen(txt_n)*4*sizeof(char));
    qDebug() << "Hash sign: " << str;
    qDebug() << "txt_d: " << txt_d;
    qDebug() << "n = " << txt_n;
    mpz_t n, d, hash, ans;
    mpz_inits(n, d, ans, hash, NULL);
    mpz_set_str(n, txt_n, 16);
    mpz_set_str(d, txt_d, 16);
    mpz_set_str(hash, str, 16);
    mpz_powm(ans, hash, d, n);

    mpz_get_str(result, 16, ans);
    qDebug() << "result = " << result;
    mpz_clears(n, d, ans, hash, NULL);
    return result;
}
char* RSAengine::verify_rsa(const char *str, const char *txt_e, const char *txt_n){
    char *result = (char*)malloc(strlen(txt_n)*4*sizeof(char));
    mpz_t n, e, sign, ans;
    mpz_inits(n, e, ans, sign, NULL);
    mpz_set_str(n, txt_n, 16);
    mpz_set_str(e, txt_e, 10);
    mpz_set_str(sign, str, 16);
    qDebug() << "sign: " << str;
    qDebug() << "txt_d: " << txt_e;
    qDebug() << "n = " << txt_n;
    mpz_powm(ans, sign, e, n);
    mpz_get_str(result, 16, ans);
    qDebug() << "result = " << result;
    mpz_clears(n, e, ans, sign, NULL);
    return result;
}
