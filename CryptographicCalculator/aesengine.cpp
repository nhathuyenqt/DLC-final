#include "aesengine.h"

AESengine::AESengine()
{

}

unsigned char* AESengine:: encrypt(const char *plain_const, int plaintext_len, int keysize, const char *key_const,const char *iv_const, int* cipher_len)
{
    unsigned char *key = (unsigned char *)key_const;
    unsigned char *iv = (unsigned char *)iv_const;
    unsigned char *plaintext = (unsigned char *)plain_const;

    int initlen = plaintext_len+16-(plaintext_len%16);
    unsigned char *ciphertext = (unsigned char*)malloc(initlen*sizeof(unsigned char));

    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    //init context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return (unsigned char*)"ERROR init context";

    //init encrypt operation
    if (keysize == 256) {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            return (unsigned char*)"ERROR encrypt init";
    }
    else {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            return (unsigned char*)"ERROR encrypt init";
    }

    //encrypt plaintext and get ciphertext output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return (unsigned char*)"ERROR encryption";
    ciphertext_len = len;

    //finalise encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return (unsigned char*)"ERROR finalise encryption";
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *cipher_len = ciphertext_len;
    return ciphertext;
}

int char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
}

void hex2bin(const char* src, unsigned char* target)
{
  while(*src && src[1])
  {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}


unsigned char* AESengine::decrypt(const char *cipher_const, int ciphertext_len, int keysize, const char *key_const, const char *iv_const, int *plain_len)
{
    unsigned char *key = (unsigned char *)key_const;
    unsigned char *iv = (unsigned char *)iv_const;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));
    hex2bin(cipher_const,ciphertext);

    int initlen = ciphertext_len+1;
    unsigned char *plaintext = (unsigned char*)malloc(initlen*sizeof(unsigned char));

    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return (unsigned char*)"ERROR init context";

    if (keysize == 256) {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            return (unsigned char*)"ERROR decrypt init";
    }
    else {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            return (unsigned char*)"ERROR decrypt init";
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return (unsigned char*)"ERROR decryption";
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return (unsigned char*)"ERROR finalise decryption";
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *plain_len = plaintext_len;
    plaintext[plaintext_len] = '\0';
    return plaintext;
}

char* AESengine::encrypt_file(const char *filepath, const char *mode, int keysize, const char *key_const, const char *iv_const)
{
    // Reading size of file
    FILE * inputfile = fopen(filepath, "rb");
    if (inputfile == NULL) return (char*)"File not exist";
    fseek(inputfile, 0, SEEK_END);
    long int size = ftell(inputfile);
    fclose(inputfile);
    // Reading data to array of unsigned chars
    inputfile = fopen(filepath, "rb");
    unsigned char *plaintext = (unsigned char *) malloc(size*sizeof(unsigned char));
    int bytes_read = fread(plaintext, sizeof(unsigned char), size, inputfile);
    fclose(inputfile);

    int plaintext_len = bytes_read;
    int initlen = plaintext_len+16-(plaintext_len%16);
    unsigned char *ciphertext = (unsigned char*)malloc(initlen*sizeof(unsigned char));

    unsigned char *key = (unsigned char *)key_const;
    unsigned char *iv = (unsigned char *)iv_const;

    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return (char*)"ERROR init context";

    if (keysize == 256) {
        if (strcmp(mode,"ECB")==0) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }
        else {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }

    }
    else {
        if (strcmp(mode,"ECB")==0) {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }
        else {
            if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }

    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return (char*)"ERROR encryption";
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return (char*)"ERROR finalise encryption";
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    \
    //Writing to file
    char *outfilepath = (char *)malloc((strlen(filepath)+15)*sizeof(char));
    strncpy(outfilepath,filepath,strlen(filepath));
    strncat(outfilepath,".encrypted",10);
    FILE * outputfile = fopen(outfilepath, "wb");
    int bytes_written = fwrite(ciphertext, sizeof(unsigned char), ciphertext_len, outputfile);
    fclose(outputfile);

    return outfilepath;
}

char* AESengine::decrypt_file(const char *filepath, const char *mode, int keysize, const char *key_const, const char *iv_const)
{
    // Reading size of file
    FILE * inputfile = fopen(filepath, "rb");
    if (inputfile == NULL) return (char *)"File not exist";
    fseek(inputfile, 0, SEEK_END);
    long int size = ftell(inputfile);
    fclose(inputfile);
    // Reading data to array of unsigned chars
    inputfile = fopen(filepath, "rb");
    unsigned char *ciphertext = (unsigned char *) malloc(size*sizeof(unsigned char));
    int bytes_read = fread(ciphertext, sizeof(unsigned char), size, inputfile);
    fclose(inputfile);

    int ciphertext_len = bytes_read;
    int initlen = ciphertext_len+1;
    unsigned char *plaintext = (unsigned char*)malloc(initlen*sizeof(unsigned char));

    unsigned char *key = (unsigned char *)key_const;
    unsigned char *iv = (unsigned char *)iv_const;

    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return (char*)"ERROR init context";

    if (keysize == 256) {
        if (strcmp(mode,"ECB")==0) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }
        else {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }

    }
    else {
        if (strcmp(mode,"ECB")==0) {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }
        else {
            if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                return (char*)"ERROR encrypt init";
        }

    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return (char*)"ERROR encryption";
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return (char*)"ERROR finalise encryption";
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    \
    //Writing to file
    char *outfilepath = (char *)malloc((strlen(filepath)+15)*sizeof(char));
    long int filepathlen= strlen(filepath)-1;
    strcpy(outfilepath,filepath);
    strncat(outfilepath,".decrypted",10);
    FILE * outputfile = fopen(outfilepath, "wb");
    int bytes_written = fwrite(plaintext, sizeof(unsigned char), plaintext_len, outputfile);
    fclose(outputfile);

    return outfilepath;
}
