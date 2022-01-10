#include "hmacengine.h"

HMACengine::HMACengine()
{

}

unsigned char* HMACengine:: calculate(const char* filepath, const char* key_const,int* hmac_len, int mode, int* signal)
{
    // Reading size of file
    FILE * inputfile = fopen(filepath, "rb");
    if (inputfile == NULL) {
        *signal = -1;
        return (unsigned char*)"File not exist";
    }
    fseek(inputfile, 0, SEEK_END);
    long int size = ftell(inputfile);
    fclose(inputfile);
    // Reading data to array of unsigned chars
    inputfile = fopen(filepath, "rb");
    unsigned char *data = (unsigned char *) malloc(size*sizeof(unsigned char));
    int bytes_read = fread(data, sizeof(unsigned char), size, inputfile);
    fclose(inputfile);

    int data_len = bytes_read;
    int keylen = strlen(key_const);

    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    if (mode == 1){
        result = HMAC(EVP_sha1(), key_const, keylen, (const unsigned char*) data, data_len, result, &resultlen);
    }
    else if (mode == 2) {
        result = HMAC(EVP_sha256(), key_const, keylen, (const unsigned char*) data, data_len, result, &resultlen);
    }
    else {
        result = HMAC(EVP_md5(), key_const, keylen, (const unsigned char*) data, data_len, result, &resultlen);
    }

    *hmac_len = resultlen;
    return result;
}
