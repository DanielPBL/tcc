#ifndef __CWT_H__
#define __CWT_H__

#include <cbor.h>
#include <stddef.h>
#include <stdbool.h>

#define CWT_TAG 61

#define CWT_EXP_TIME 60*60*1000

#define CWT_ISS 1
#define CWT_SUB 2
#define CWT_AUD 3
#define CWT_EXP 4
#define CWT_NBF 5
#define CWT_IAT 6
#define CWT_CTI 7
#define CWT_SCP 8
#define CWT_SIG 9

#ifdef __cplusplus
extern "C" {
#endif

/*
{
     / iss / 1: "coap://as.example.com",
     / sub / 2: "erikw",
     / aud / 3: "coap://light.example.com",
     / exp / 4: 1444064944,
     / nbf / 5: 1443944944,
     / iat / 6: 1443944944,
     / cti / 7: h'0b71'
}
*/

typedef struct cwt {
    char *iss;
    char *sub;
    char *aud;
    long int exp;
    long int nbf;
    long int iat;
    unsigned char *cti;
    char *scope;
    unsigned char *signature;

    size_t iss_len;
    size_t sub_len;
    size_t aud_len;
    size_t cti_len;
    size_t scp_len;
    size_t sig_len;
} cwt_t;

cwt_t* cwt_init();
cwt_t* cwt_parse_item(cbor_item_t *cbor_wt);
cwt_t* cwt_parse(const unsigned char *source, size_t source_size);
size_t cwt_serialize(cwt_t *cwt, unsigned char **buffer, size_t *buffer_size);
void cwt_free(cwt_t *cwt);

void cwt_build_string(unsigned char *str, char **dest, size_t *len);
void cwt_build_bytestring(unsigned char *str, size_t length, unsigned char **dest, size_t *len);
void cwt_set_iss(cwt_t *cwt, unsigned char *txt);
void cwt_set_sub(cwt_t *cwt, unsigned char *txt);
void cwt_set_aud(cwt_t *cwt, unsigned char *txt);
void cwt_set_cti(cwt_t *cwt, unsigned char *txt, size_t length);
void cwt_set_scope(cwt_t *cwt, unsigned char *txt);
void cwt_set_signature(cwt_t *cwt, unsigned char *txt, size_t length);

#ifdef __cplusplus
}
#endif

#endif