#ifndef DESENGINE_H
#define DESENGINE_H
#include "gmp.h"
#include "time.h"

class DESengine{
public:
    DESengine();
    char* desAlg(const char *text, const char* masterKeyHex, int choice);
    void generate_sub_key(char* masterKeyBin);
    void encrypt_one_block(char *block, char* masterKey, char* cipherBlock);
    void decrypt_one_block(char *cipherBlock, char* masterKey, char* plainBlock);
    void round_funtion(char half[32], char skey[48], char result[33]);
    int s_function(char block[7], int s[64]);
    void hex_to_bin(const char* hex, char *bin);
    void bin_to_hex( char* bin, char *hex);
private:
    char sub_key[17][49];
    // mpz_t sub_key[16];

};

#endif // DESENGINE_H
