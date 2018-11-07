#ifndef _COAP_UTILS_H_
#define _COAP_UTILS_H_

#include <coap2/coap.h>

#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

int cmdline_uri(char *arg, coap_optlist_t **optlist, coap_uri_t *uri);
int cmdline_input(char *text, coap_string_t *buf);
uint16_t get_default_port(const coap_uri_t *u);
coap_pdu_t *
coap_new_request(uint8_t pdu_type,
                 coap_context_t *ctx,
                 coap_session_t *session,
                 unsigned char m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length);
coap_session_t*
init_session(coap_context_t **ctx,
             const coap_uri_t *uri,
             coap_response_handler_t handler,
             const char *identity,
             uint8_t *key,
             unsigned int key_len);
int
resolve_address(const coap_str_const_t *server, struct sockaddr *dst);

#endif