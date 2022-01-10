#include "desengine.h"
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include "QMessageBox"
#include <math.h>

DESengine::DESengine()
{

}

int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};
int Expand[] = {32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1};
int S1[] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13};

int S2[] = {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9};

int S3[] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

int S4[] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

int S5[] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

int S6[] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

int S7[] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};

int S8[] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};
int P[] =    {16,  7, 20, 21,
            29, 12, 28, 17,
             1, 15, 23, 26,
             5, 18, 31, 10,
             2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25};
int final_permutation[] =
        {40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25};

int PC1[] = {57, 49,  41, 33,  25,  17,  9,
            1, 58,  50, 42,  34,  26, 18,
            10,  2,  59, 51,  43,  35, 27,
            19, 11,   3, 60,  52,  44, 36,
            63, 55,  47, 39,  31,  23, 15,
            7, 62,  54, 46,  38,  30, 22,
            14,  6,  61, 53,  45,  37, 29,
            21, 13,   5, 28,  20,  12,  4};
int PC2[] = {14, 17, 11, 24,  1,  5,
            3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};
char* DESengine:: desAlg(const char *text, const  char* masterKeyHex, int choice){
    char *textBin = (char*)malloc(strlen(text)*4*sizeof(char));
    char *masterKeyBin = (char*)malloc(strlen(masterKeyHex)*4*sizeof(char));

    this->hex_to_bin(masterKeyHex, masterKeyBin);

    this->hex_to_bin(text, textBin);

    char *outputBin = (char*)malloc(strlen(textBin));
    int nBlocks = 0;
    char block[64], outputBlock[64];

    qDebug("input txt = %s  len=%d ", textBin, strlen(textBin));
    while (nBlocks*64 < int(strlen(textBin))){
        qDebug("Block  %d ", nBlocks);
        memcpy(block, &textBin[nBlocks*64], 64);
        block[64] = '\0';
        if (choice ==1){
            this->encrypt_one_block(block, masterKeyBin, outputBlock);
             qDebug("cipher block  %s ", outputBlock);
        }else{
            this->decrypt_one_block(block, masterKeyBin, outputBlock);
            qDebug("decrypt block  %s ", outputBlock);
        }

        memcpy(&outputBin[nBlocks*64], outputBlock, 64);
        nBlocks +=1;
    }

    outputBin[strlen(textBin)] ='\0';
    char *outputHex = (char*)malloc(strlen(textBin)/4);
    this->bin_to_hex(outputBin, outputHex);

    return outputHex;
}

void DESengine::encrypt_one_block(char *block, char* masterKey, char* cipherBlock){

    this->generate_sub_key(masterKey);

    char m_ip[64];

    for (int i=0; i<64; i++){
        m_ip[i] = block[IP[i]-1];
    }

    m_ip[64] = '\0';


    char left[17][33];
    char right[17][33];

    memcpy(left[0], m_ip, 32);
    memcpy(right[0], &m_ip[32], 32);
    left[0][32] = '\0';
    right[0][32] = '\0';

    for (int round = 1; round<=16; round ++){
        //left[round] = right[round-1];
        memcpy(left[round], right[round-1], 32);
        char f[33];

        this->round_funtion(right[round-1], this->sub_key[round], f);

        f[32] = '\0';
        for (int i=0; i<32; i++){
            // calculate right XOR subkey
            right[round][i] = (f[i]-'0') ^ (left[round-1][i] - '0') + '0';
        }
        right[round][32] = '\0';
        left[round][32] = '\0';

    }
//    qDebug("left 16  %s  %d\n", left[16], strlen(left[16]));
//    qDebug("right %s\n", right[16]);
    char after_16_round[64];
    memcpy(after_16_round, right[16], 32);
    memcpy(&after_16_round[32], left[16], 32);
    after_16_round[64] = '\0';
    qDebug("after 16 round");
    qDebug(" %s ", after_16_round);
    for (int i=0; i<64; i++){
//         qDebug("%d   %c\n",i, after_16_round[i]);
        cipherBlock[i] = after_16_round[final_permutation[i] -1];
    }
    cipherBlock[64] = '\0';

}

void DESengine::decrypt_one_block(char *cipherBlock, char* masterKey, char* plainBlock){

    this->generate_sub_key(masterKey);

    char c_ip[64];

    for (int i=0; i<64; i++){
        c_ip[i] = cipherBlock[IP[i]-1];
    }

    c_ip[64] = '\0';


    char left[17][33];
    char right[17][33];

    memcpy(right[16], c_ip, 32);
    memcpy(left[16], &c_ip[32], 32);

    left[16][32] = '\0';
    right[16][32] = '\0';

    for (int round = 16; round>0; round --){
        //left[round] = right[round-1];
        memcpy(right[round-1], left[round], 32);
        char f[33];
        this->round_funtion(right[round-1], this->sub_key[round], f);

        f[32] = '\0';
        for (int i=0; i<32; i++){
            // calculate right XOR subkey
            left[round-1][i] = (f[i]-'0') ^ (right[round][i] - '0') + '0';
        }
        right[round-1][32] = '\0';
        left[round-1][32] = '\0';
    }
    char after_16_round[64];
    memcpy(after_16_round, left[0], 32);
    memcpy(&after_16_round[32], right[0], 32);
    after_16_round[64] = '\0';

    for (int i=0; i<64; i++){
        // qDebug("%d   %s\n",i, after_16_round[i]);
        plainBlock[i] = after_16_round[final_permutation[i] -1];
    }
    plainBlock[64] = '\0';

}

void DESengine::generate_sub_key(char* masterKeyBin){

    char key_pc1[58]; // 56 bits + 1 bit for sign + 1 bit for null

    //PC-1
    for(int i =0; i<56; i++){
        key_pc1[i] = masterKeyBin[PC1[i]-1];
    }

    char c[17][29];
    char d[17][29];

    memcpy(c[0], key_pc1, 28);
    memcpy(d[0], &key_pc1[28], 28);
    c[0][28] = '\0';
    d[0][28] = '\0';


    for (int i = 1; i<= 16; i++){
        if (i ==1 or i == 2 or i==9 or i ==16){
            memcpy(c[i], &c[i-1][1], 27);
            c[i][27] = c[i-1][0];
            c[i][28] = '\0';
            memcpy(d[i], &d[i-1][1], 27);
            d[i][27] = d[i-1][0];
            d[i][28] = '\0';
        }else{
            memcpy(c[i], &c[i-1][2], 26);
            c[i][26] = c[i-1][0];
            c[i][27] = c[i-1][1];
            c[i][28] = '\0';
            memcpy(d[i], &d[i-1][2], 27);
            d[i][26] = d[i-1][0];
            d[i][27] = d[i-1][1];
            d[i][28] = '\0';
        }

        // puts(c[i]);
        // puts(d[i]);
    }

    char tmp[57];
    for (int i = 1; i<=16; i++){
        memcpy(tmp, c[i], 28);
        memcpy(&tmp[28], d[i], 28);
        tmp[56] = '\0';
        for(int j=0; j<48; j++){
            this->sub_key[i][j] = tmp[PC2[j]-1];
        }
        this->sub_key[i][48] = '\0';
        // puts(tmp);
        // qDebug("sub key %d \n", i);
    }
    // for (int i=1; i<=16; i++){
    //     qDebug("sub key %d\n", i);
    //     puts(this->sub_key[i]);
    // }
}



void DESengine::round_funtion(char half[32], char skey[49], char result[33]){
    char processed_half[49];
    // qDebug("rhalf %s\n", half);
    qDebug("skey %s\n", skey);
    for (int i=0; i<48; i++){
        processed_half[i] = half[Expand[i]-1];
        // qDebug("processed_half  %c\n", processed_half[i]);
    }
    processed_half[48] = '\0';

    for (int i=0; i<48; i++){
        // calculate right XOR subkey
        processed_half[i] = (processed_half[i]-'0') ^ (skey[i] - '0') + '0';
        // qDebug("processed_half  %c\n", processed_half[i]);
    }

    char B[8][7];
    for (int i=0; i<8; i++){
        memcpy(B[i], &processed_half[i*6], 6);
        B[i][6] = '\0';
        // qDebug("B  %s\n", B[i]);
    }

    char processed_sbox_half[33];

    int a[8];

    char out[8][5];
    a[0] = s_function(B[0], S1);
    a[1] = s_function(B[1], S2);
    a[2] = s_function(B[2], S3);
    a[3] = s_function(B[3], S4);
    a[4] = s_function(B[4], S5);
    a[5] = s_function(B[5], S6);
    a[6] = s_function(B[6], S7);
    a[7] = s_function(B[7], S8);

    for (int i=0; i<8; i++){
        for(int j = 3; j>=0; j--){
            // qDebug("j = %d, a[i] = %d,  mod 2 = %d\n", j, a[i], a[i]%2);
            if (a[i]%2 == 0)
                out[i][j]='0';
            else
                out[i][j]='1';
            a[i] = a[i]/2;
        }
        out[i][4] = '\0';
        memcpy(&processed_sbox_half[i*4], out[i], 4);

    }
    processed_sbox_half[32] = '\0';
    // char after_permutation[33];
    for (int i= 0; i<32; i++)
        result[i] = processed_sbox_half[P[i]-1];
    result[32] = '\0';
    // qDebug("After permutaion %s\n", result);

}

int DESengine::s_function(char block[7], int s[64]){
    int row, col;

    row = 2*(int(block[0])-48) + int(block[5]) - 48;

    col = 8*(int(block[1])-48) + 4*(int(block[2])-48) + 2*(int(block[3])-48) + int(block[4])-48;
    // qDebug(" row = %d  col = %d\n", row, col);
    return s[row*16+col];
}

void DESengine::hex_to_bin(const char* hex, char *bin){

    mpz_t n;
    mpz_init(n);
    mpz_set_str(n, hex, 16);
    mpz_get_str(bin, 2, n);
    mpz_clear(n);
    int k = strlen(bin);
    qDebug("Binary converted1  len %d\n", strlen(bin));
    qDebug("Binary converted1  len %d\n", strlen(bin)%64);
    if (strlen(bin)%64 != 0){

        int t = 64 - (strlen(bin)%64);

        memmove(bin+t, bin, strlen(bin));
        for (int i = 0; i< t; i++)
            bin[i] = '0';
        qDebug("Binary convertedt  len %d\n",t);
        bin[k+t]  = '\0';
    }else{
         bin[strlen(bin)] = '\0';
    }
        qDebug("Binary converted2  len %d\n", strlen(bin));

    qDebug("Binary converted k = %d \n%s   len %d\n",k, bin, strlen(bin));
}

void DESengine::bin_to_hex( char* bin, char *hex){

    mpz_t n;
    mpz_init(n);
    mpz_set_str(n, bin, 2);
    mpz_get_str(hex, 16, n);
    mpz_clear(n);
    qDebug("Hex output %s\n", hex);
}
