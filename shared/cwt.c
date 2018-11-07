#include "cwt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

cwt_t* cwt_init() {
    const unsigned char cti[] = {0x0, 0xb, 0x7, 0x1};
    cwt_t* cwt = NULL;

    cwt = malloc(sizeof(cwt_t));
    if (cwt) {
        memset(cwt, 0, sizeof(cwt_t));
        cwt->iat = time(NULL);
        cwt->exp = cwt->iat + CWT_EXP_TIME;
        cwt->nbf = cwt->iat;
        cwt->cti_len = sizeof(cti);
        cwt->cti = malloc(cwt->cti_len);
        memcpy(cwt->cti, cti, cwt->cti_len);
    }

    return cwt;
}

void cwt_free(cwt_t *cwt) {
    if (cwt) {
        if (cwt->iss)
            free(cwt->iss);
        if (cwt->sub)
            free(cwt->sub);
        if (cwt->aud)
            free(cwt->aud);
        if (cwt->cti)
            free(cwt->cti);
        if (cwt->signature)
            free(cwt->signature);
        
        free(cwt);
    }
}

cwt_t* cwt_parse_item(cbor_item_t *cbor_wt) {
    cwt_t *cwt = NULL;

    if (cbor_wt) {
        if (cbor_isa_tag(cbor_wt) && cbor_tag_value(cbor_wt) == CWT_TAG) {
            cbor_item_t *map = cbor_tag_item(cbor_wt);
            
            if (cbor_isa_map(map)) {
                struct cbor_pair *pairs = cbor_map_handle(map);
                size_t size = cbor_map_size(map);

                cwt = malloc(sizeof(cwt_t));
                for (int i = 0; i < size; ++i) {
                    if (cbor_isa_uint(pairs[i].key) &&
                        cbor_int_get_width(pairs[i].key) == CBOR_INT_16) {
                        switch (cbor_get_uint16(pairs[i].key)) {
                            case CWT_ISS:
                                if (cbor_isa_string(pairs[i].value)) {
                                    cwt_set_iss(cwt, cbor_string_handle(pairs[i].value));
                                }
                                break;
                            case CWT_SUB:
                                if (cbor_isa_string(pairs[i].value)) {
                                    cwt_set_sub(cwt, cbor_string_handle(pairs[i].value));
                                }
                                break;
                            case CWT_AUD:
                                if (cbor_isa_string(pairs[i].value)) {
                                    cwt_set_aud(cwt, cbor_string_handle(pairs[i].value));
                                }
                                break;
                            case CWT_EXP:
                                if (cbor_isa_uint(pairs[i].value) &&
                                    cbor_int_get_width(pairs[i].value) == CBOR_INT_32) {
                                    cwt->exp = cbor_get_uint32(pairs[i].value);
                                }
                                break;
                            case CWT_NBF:
                                if (cbor_isa_uint(pairs[i].value) &&
                                    cbor_int_get_width(pairs[i].value) == CBOR_INT_32) {
                                    cwt->nbf = cbor_get_uint32(pairs[i].value);
                                }
                                break;
                            case CWT_IAT:
                                if (cbor_isa_uint(pairs[i].value) &&
                                    cbor_int_get_width(pairs[i].value) == CBOR_INT_32) {
                                    cwt->iat = cbor_get_uint32(pairs[i].value);
                                }
                                break;
                            case CWT_CTI:
                                if (cbor_isa_bytestring(pairs[i].value)) {
                                    cwt_set_cti(cwt, cbor_bytestring_handle(pairs[i].value),
                                        cbor_bytestring_length(pairs[i].value));
                                }
                                break;
                            case CWT_SCP:
                                if (cbor_isa_string(pairs[i].value)) {
                                    cwt_set_scope(cwt, cbor_string_handle(pairs[i].value));
                                }
                                break;
                            case CWT_SIG:
                                if (cbor_isa_bytestring(pairs[i].value)) {
                                    cwt_set_signature(cwt, cbor_bytestring_handle(pairs[i].value),
                                        cbor_bytestring_length(pairs[i].value));
                                }
                                break;
                            default:
                                free(cwt);
                                cwt = NULL;
                                fprintf(stderr, "Claim %d desconhecido.", cbor_get_uint16(pairs[i].key));
                        }
                    }
                }
            }
        }
    }

    return cwt;    
}

cwt_t* cwt_parse(const unsigned char *source, size_t source_size) {
    struct cbor_load_result result;
    cbor_item_t *cbor_wt;
    cwt_t *cwt = NULL;

    cbor_wt = cbor_load(source, source_size, &result);
    if (cbor_wt) {
        cwt = cwt_parse_item(cbor_wt);
        cbor_decref(&cbor_wt);
    }

    return cwt;
}

void cwt_build_string(unsigned char *str, char **dest, size_t *len) {
    *len = strlen((char *) str) + 1;
    *dest = malloc(sizeof(char) * (*len));
    strcpy(*dest, (char *) str);
}

void cwt_build_bytestring(unsigned char *str, size_t length, unsigned char **dest, size_t *len) {
    *len = length;
    *dest = malloc(sizeof(unsigned char) * (*len));
    memcpy(*dest, str, length);
}

void cwt_set_iss(cwt_t *cwt, unsigned char *txt) {
    cwt_build_string(txt, &cwt->iss, &cwt->iss_len);
}

void cwt_set_sub(cwt_t *cwt, unsigned char *txt) {
    cwt_build_string(txt, &cwt->sub, &cwt->sub_len);
}

void cwt_set_aud(cwt_t *cwt, unsigned char *txt) {
    cwt_build_string(txt, &cwt->aud, &cwt->aud_len);
}

void cwt_set_cti(cwt_t *cwt, unsigned char *txt, size_t length) {
    cwt_build_bytestring(txt, length, &cwt->cti, &cwt->cti_len);
}

void cwt_set_scope(cwt_t *cwt, unsigned char *txt) {
    cwt_build_string(txt, &cwt->scope, &cwt->scp_len);
}

void cwt_set_signature(cwt_t *cwt, unsigned char *txt, size_t length) {
    cwt_build_bytestring(txt, length, &cwt->signature, &cwt->sig_len);
}

size_t cwt_serialize(cwt_t *cwt, unsigned char **buffer, size_t *buffer_size) {
    size_t size = CWT_SIG
        - (cwt->iss_len ? 0 : 1)
        - (cwt->sub_len ? 0 : 1)
        - (cwt->aud_len ? 0 : 1)
        - (cwt->exp ? 0 : 1)
        - (cwt->nbf ? 0 : 1)
        - (cwt->iat ? 0 : 1)
        - (cwt->cti_len ? 0 : 1)
        - (cwt->scp_len ? 0 : 1)
        - (cwt->sig_len ? 0 : 1);
    cbor_item_t *cbor_wt;
    cbor_item_t *map = cbor_new_definite_map(size);
    struct cbor_pair pair;
    
    if (cwt->iss) {
        pair.key = cbor_build_uint16(CWT_ISS);
        pair.value = cbor_build_string(cwt->iss);
        cbor_map_add(map, pair);
    }
    
    if (cwt->sub) {
        pair.key = cbor_build_uint16(CWT_SUB);
        pair.value = cbor_build_string(cwt->sub);
        cbor_map_add(map, pair);
    }
    
    if (cwt->aud) {
        pair.key = cbor_build_uint16(CWT_AUD);
        pair.value = cbor_build_string(cwt->aud);
        cbor_map_add(map, pair);
    }
    
    if (cwt->exp) {
        pair.key = cbor_build_uint16(CWT_EXP);
        pair.value = cbor_build_uint32(cwt->exp);
        cbor_map_add(map, pair);
    }
    
    if (cwt->nbf) {
        pair.key = cbor_build_uint16(CWT_NBF);
        pair.value = cbor_build_uint32(cwt->nbf);
        cbor_map_add(map, pair);
    }
    
    if (cwt->iat) {
        pair.key = cbor_build_uint16(CWT_IAT);
        pair.value = cbor_build_uint32(cwt->iat);
        cbor_map_add(map, pair);
    }
    
    if (cwt->cti) {
        pair.key = cbor_build_uint16(CWT_CTI);
        pair.value = cbor_build_bytestring(cwt->cti, cwt->cti_len);
        cbor_map_add(map, pair);
    }
    
    if (cwt->scope) {
        pair.key = cbor_build_uint16(CWT_SCP);
        pair.value = cbor_build_string(cwt->scope);
        cbor_map_add(map, pair);
    }
    
    if (cwt->signature) {
        pair.key = cbor_build_uint16(CWT_SIG);
        pair.value = cbor_build_bytestring(cwt->signature, cwt->sig_len);
        cbor_map_add(map, pair);
    }

    cbor_wt = cbor_build_tag(CWT_TAG, map); // 61 -> CBOR Web Token
    size = cbor_serialize_alloc(cbor_wt, buffer, buffer_size);
    cbor_decref(&cbor_wt);

    return size;
}

/* #include "ssl_utils.h"
#include "coappsk.h"
#include "servers.h"

#define PRIV_KEY "../certs/private.pem"

int main(int argc, char const *argv[]) {
    unsigned char *buffer;
    cwt_t *cwt;
    size_t buffer_len;
    char as_uri[500];
    char *priv_key;

    priv_key = load_file_to_buff(PRIV_KEY);
    if (priv_key == NULL) {
        fprintf(stderr, "Invalid private key suplied\n");
        return EXIT_FAILURE;
    }

    snprintf(as_uri, sizeof(as_uri), "coaps://[%s]:%s", AS_HOST, AS_PORT);
    cwt = cwt_init();
    cwt_set_iss(cwt, (unsigned char*) as_uri);
    cwt_set_sub(cwt, (unsigned char*) "Auth Server");
    cwt_set_aud(cwt, (unsigned char*) as_uri);
    cwt_set_scope(cwt, (unsigned char*)"pub:ps/lux;sub:ps/lux;pub:ps/gas;sub:ps/gas");
    size_t sig_len;
    unsigned char *signature = signMessage(priv_key, PSK, &sig_len);
    cwt_set_signature(cwt, signature, sig_len);

    cwt_serialize(cwt, &buffer, &buffer_len);
    cwt_free(cwt);
    cwt = cwt_parse(buffer, buffer_len);

    printf("ISS: %s\nSUB: %s\nAUD: %s\nSCOPE: %s\n",
        cwt->iss, cwt->sub, cwt->aud, cwt->scope);

    cwt_serialize(cwt, &buffer, &buffer_len);
    cwt_free(cwt);

    free(buffer);

    return 0;
} */
