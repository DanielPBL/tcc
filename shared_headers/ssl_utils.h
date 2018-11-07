#ifndef __SSL_UTILS__
#define __SSL_UTILS__

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

RSA* createPrivateRSA(const char *key);

bool RSASign(RSA* rsa, 
             const unsigned char* Msg, 
             size_t MsgLen,
             unsigned char** EncMsg, 
             size_t* MsgLenEnc);

void Base64Encode(const unsigned char* buffer, 
                  size_t length, 
                  char** base64Text);

unsigned char* signMessage(const char *privateKey, const unsigned char *plainText,
    size_t textLength, size_t *encMessageLength);

size_t calcDecodeLength(const char* b64input);

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);

RSA* createPublicRSA(const char *key);

bool RSAVerifySignature(RSA* rsa, 
                        unsigned char* MsgHash, 
                        size_t MsgHashLen, 
                        const unsigned char* Msg, 
                        size_t MsgLen, 
                        bool* Authentic);

bool verifySignature(const char *publicKey, const unsigned char *plainText,
    size_t textLength, unsigned char *signature, size_t encMessageLength);

char* load_file_to_buff(const char *fname);
char* pubkey_from_cert(const char *cert_file);

#ifdef __cplusplus
}
#endif

#endif
