#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <cbor.h>
#include <coap2/coap.h>

#include "coap_utils.h"

int cmdline_uri(char *arg, coap_optlist_t **optlist, coap_uri_t *uri) {
    unsigned char portbuf[2];
    #define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char *buf = _buf;
    size_t buflen;
    int res;

    if (coap_split_uri((unsigned char *)arg, strlen(arg), uri) < 0) {
      coap_log(LOG_ERR, "Invalid CoAP URI\n");
      return -1;
    }

    if (uri->port != get_default_port(uri)) {
        coap_insert_optlist(optlist,
            coap_new_optlist(COAP_OPTION_URI_PORT,
                coap_encode_var_safe(portbuf, sizeof(portbuf), (uri->port & 0xffff)), portbuf));
    }

    if (uri->path.length) {
        buflen = BUFSIZE;
        res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(optlist,
                coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf), coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

    if (uri->query.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(optlist,
                coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf), coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

  return 0;
}

int check_segment(const uint8_t *s, size_t length) {
    size_t n = 0;

    while (length) {
        if (*s == '%') {
            if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
                return -1;

            s += 2;
            length -= 2;
        }

        ++s; ++n; --length;
    }

    return n;
}

void decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {
    while (length--) {
        if (*seg == '%') {
            *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

            seg += 2; length -= 2;
        } else {
            *buf = *seg;
        }

        ++buf; ++seg;
    }
}

int cmdline_input(char *text, coap_string_t *buf) {
    int len;
    len = check_segment((unsigned char *)text, strlen(text));

    if (len < 0)
        return 0;

    buf->s = (unsigned char *)coap_malloc(len);
    if (!buf->s)
        return 0;

    buf->length = len;
    decode_segment((unsigned char *)text, strlen(text), buf->s);

    return 1;
}

uint16_t get_default_port(const coap_uri_t *u) {
    return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

coap_pdu_t *
coap_new_request(uint8_t pdu_type,
                 coap_context_t *ctx,
                 coap_session_t *session,
                 unsigned char m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
    coap_pdu_t *pdu;

    if (!(pdu = coap_new_pdu(session)))
        return NULL;

    pdu->type = pdu_type;
    pdu->tid = coap_new_message_id(session);
    pdu->code = m;

    if (options)
        coap_add_optlist_pdu(pdu, options);

    if (length) {
        coap_add_data(pdu, length, data);
    }

    return pdu;
}

coap_session_t*
init_session(coap_context_t **ctx,
             const coap_uri_t *uri,
             coap_response_handler_t handler,
             const char *identity,
             uint8_t *key,
             unsigned int key_len) {
    coap_str_const_t server;
    coap_address_t dst;
    uint16_t port;
    int res;
    coap_session_t* session;

    server = uri->host;
    port = uri->port;

    /* resolve destination address where server should be sent */
    res = resolve_address(&server, &dst.addr.sa);

    if (res < 0) {
        fprintf(stderr, "failed to resolve address\n");
        return NULL;
    }

    *ctx = coap_new_context(NULL);
    if (!*ctx) {
        coap_log(LOG_EMERG, "cannot create context\n");
        return NULL;
    }
    coap_context_set_keepalive(*ctx, 0);

    dst.size = res;
    dst.addr.sin.sin_port = htons(port);

    session = coap_new_client_session_psk(*ctx, NULL, &dst, COAP_PROTO_DTLS,
                identity, key, key_len);

    if (!session) {
        coap_log(LOG_EMERG, "cannot create client session\n");
        coap_free_context(*ctx);
        return NULL;
    }

    coap_register_option(*ctx, COAP_OPTION_BLOCK2);
    coap_register_response_handler(*ctx, handler);
    
    return session;
}

int
resolve_address(const coap_str_const_t *server, struct sockaddr *dst) {
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    static char addrstr[256];
    int error, len=-1;

    memset(addrstr, 0, sizeof(addrstr));
    if (server->length)
        memcpy(addrstr, server->s, server->length);
    else
        memcpy(addrstr, "localhost", 9);

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(addrstr, NULL, &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        switch (ainfo->ai_family) {
            case AF_INET6:
            case AF_INET:
                len = ainfo->ai_addrlen;
                memcpy(dst, ainfo->ai_addr, len);
                goto finish;
            default:
                break;
        }
    }

finish:
    freeaddrinfo(res);
    return len;
}