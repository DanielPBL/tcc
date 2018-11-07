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

#define BUFSIZE 40

#include <coap2/coap.h>
#include "coappsk.h"
#include "cwt.h"
#include "ssl_utils.h"
#include "servers.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* Dados SSL */
#define PRIV_KEY "../certs/private.pem"
static char *priv_key = NULL;


/* Conexão com Servidor de BD */
static coap_uri_t uri;
static coap_optlist_t *optlist = NULL;
static coap_context_t *ctx_db = NULL;
static coap_session_t *session_db = NULL;
/******************************/

static uint8_t key[MAX_KEY];
static ssize_t key_length = 0;
static const char *hint = HINT;

static coap_context_t *ctx_main;
static cwt_t *cwt = NULL;
static unsigned int wait_seconds = 90;
static int quit = 0;
/* reading is done when this flag is set */
static int ready = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
static void handle_sigint(int signum UNUSED_PARAM) {
    quit = 1;
}

static ssize_t cmdline_read_key(char *arg, unsigned char *buf, size_t maxlen) {
    size_t len = strnlen(arg, maxlen);

    if (len) {
        memcpy(buf, arg, len);
        return len;
    }

    return -1;
}

static coap_context_t* get_context(const char *node, const char *port) {
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    ctx = coap_new_context(NULL);

    if (!ctx) {
        return NULL;
    }

    /* Need PSK set up before we set up (D)TLS endpoints */
    coap_context_set_psk(ctx, hint, key, key_length);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr, addrs;
        coap_endpoint_t *ep_dtls = NULL;

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            addrs = addr;

            ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
            if (!ep_dtls) {
                coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
                continue;
            }

            if (ep_dtls)
                goto finish;
        }
    }
    
    fprintf(stderr, "no context available for interface '%s'\n", node);

finish:
    freeaddrinfo(result);
    return ctx;
}

static coap_session_t *
get_session(
  coap_context_t *ctx,
  const char *local_addr,
  const char *local_port,
  coap_proto_t proto,
  coap_address_t *dst,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
) {
    coap_session_t *session = NULL;


    if (local_addr) {
        int s;
        struct addrinfo hints;
        struct addrinfo *result = NULL, *rp;

        memset( &hints, 0, sizeof( struct addrinfo ) );
        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

        s = getaddrinfo( local_addr, local_port, &hints, &result );
        if (s != 0) {
            fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( s ) );
            return NULL;
        }

        /* iterate through results until success */
        for ( rp = result; rp != NULL; rp = rp->ai_next ) {
            coap_address_t bind_addr;
            if (rp->ai_addrlen <= sizeof(bind_addr.addr)) {
                coap_address_init(&bind_addr);
                bind_addr.size = rp->ai_addrlen;
                memcpy(&bind_addr.addr, rp->ai_addr, rp->ai_addrlen);
                
                session = coap_new_client_session_psk(ctx, &bind_addr, dst, proto,
                                identity, key, key_len);
                
                if (session)
                    break;
            }
        }

        freeaddrinfo( result );
    } else {
        session = coap_new_client_session_psk(ctx, NULL, dst, proto,
                        identity, key, key_len);
    }

    return session;
}

static int
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
                ;
        }
    }

finish:
    freeaddrinfo(res);
    return len;
}

static void finish() {
    if (session_db)
        coap_session_release(session_db);
    if (ctx_db)
        coap_free_context(ctx_db);
    if (priv_key)
        free(priv_key);

    coap_free_context(ctx_main);
    coap_cleanup();
}

static uint16_t
get_default_port(const coap_uri_t *u) {
    return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

/**
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static void
cmdline_uri(char *arg, coap_optlist_t **optlist) {
    unsigned char portbuf[2];
    unsigned char _buf[BUFSIZE];
    unsigned char *buf = _buf;
    size_t buflen;
    int res;

    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
        coap_log(LOG_ERR, "invalid CoAP URI\n");
        return;
    }

    if (uri.port != get_default_port(&uri)) {
        coap_insert_optlist(optlist,
                coap_new_optlist(COAP_OPTION_URI_PORT,
                                coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                    (uri.port & 0xffff)),
                portbuf));
    }

    if (uri.path.length) {
        buflen = BUFSIZE;
        res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(optlist,
                        coap_new_optlist(COAP_OPTION_URI_PATH,
                        coap_opt_length(buf),
                        coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

    coap_insert_optlist(optlist,
        coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
            coap_encode_var_safe(_buf, sizeof(_buf), 60), _buf));
}

static void
message_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {
    size_t len;
    unsigned char *databuf;

    coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           (received->code >> 5), received->code & 0x1F);
    if (coap_get_log_level() < LOG_DEBUG)
        coap_show_pdu(LOG_INFO, received);

    cwt = NULL;
    /* output the received data, if any */
    if (COAP_RESPONSE_CLASS(received->code) == 2) {
        /* There is no block option set, just read the data and we are done. */
        /* Gera CWT */
        if (coap_get_data(received, &len, &databuf)) {
            struct cbor_load_result result;
            cbor_item_t *cbor_auths;

            cbor_auths = cbor_load(databuf, len, &result);
            if (cbor_auths) {
                if (cbor_isa_string(cbor_auths)) {
                    char as_uri[500];
                    char bk_uri[500];

                    snprintf(as_uri, sizeof(as_uri), "coaps://[%s]:%s", AS_HOST, AS_PORT);
                    snprintf(bk_uri, sizeof(bk_uri), "coaps://[%s]:%s/ps", BK_HOST, BK_PORT);
                    cwt = cwt_init();
                    cwt_set_iss(cwt, (unsigned char*) as_uri);
                    cwt_set_sub(cwt, (unsigned char*) "Auth Server");
                    cwt_set_aud(cwt, (unsigned char*) bk_uri);
                    cwt_set_scope(cwt, cbor_string_handle(cbor_auths));
                    
                    unsigned char *cwt_buf;
                    size_t sig_len, buf_len, cwt_len = cwt_serialize(cwt, &cwt_buf, &buf_len);
                    unsigned char *signature = signMessage(priv_key, cwt_buf, cwt_len, &sig_len);
                    /*Sign the CWT*/
                    cwt_set_signature(cwt, signature, sig_len);
                    free(signature);
                    free(cwt_buf);
                }
                cbor_decref(&cbor_auths);
            }
        }
    } else {      /* no 2.05 */
        /* check if an error was signaled and output payload if so */
        if (COAP_RESPONSE_CLASS(received->code) >= 4) {
            fprintf(stderr, "%d.%02d", (received->code >> 5), received->code & 0x1F);

            if (coap_get_data(received, &len, &databuf)) {
                fprintf(stderr, " ");

                while(len--)
                    fprintf(stderr, "%c", *databuf++);
            }

            fprintf(stderr, "\n");
        }
    }

    /* our job is done, we can exit at any time */
    ready = 1;
}

static void init_db_session() {
    char port_str[NI_MAXSERV] = "0";
    char node_str[NI_MAXHOST] = "";
    char user[MAX_USER + 1] = USER;
    unsigned char key[MAX_KEY] = PSK;
    char db_uri[500];
    static coap_str_const_t server;
    coap_address_t dst;
    uint16_t port;
    int res;

    snprintf(db_uri, sizeof(db_uri), "coaps://[%s]:%s/auths", DB_HOST, DB_PORT);
    cmdline_uri(db_uri, &optlist);
    server = uri.host;
    port = uri.port;

    /* resolve destination address where server should be sent */
    res = resolve_address(&server, &dst.addr.sa);

    if (res < 0) {
        fprintf(stderr, "failed to resolve address\n");
        exit(1);
    }

    ctx_db = coap_new_context(NULL);
    if (!ctx_db) {
        coap_log( LOG_EMERG, "cannot create context\n" );
        finish();
        return;
    }
    coap_context_set_keepalive(ctx_db, 0);

    dst.size = res;
    dst.addr.sin.sin_port = htons(port);

    session_db = get_session(
        ctx_db, node_str[0] ? node_str : NULL, port_str, COAP_PROTO_DTLS,
        &dst, user, key, (unsigned)key_length
    );

    if (!session_db) {
        coap_log( LOG_EMERG, "cannot create client session\n" );
        finish();
        return;
    }

    coap_register_option(ctx_db, COAP_OPTION_BLOCK2);
    coap_register_response_handler(ctx_db, message_handler);
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 unsigned char m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
    coap_pdu_t *pdu;
    (void)ctx;

    if (!(pdu = coap_new_pdu(session)))
        return NULL;

    pdu->type = COAP_MESSAGE_CON;
    pdu->tid = coap_new_message_id(session);
    pdu->code = m;

    if (options)
        coap_add_optlist_pdu(pdu, options);

    if (length) {
        coap_add_data(pdu, length, data);
    }

    return pdu;
}

static bool get_user_cwb(unsigned char *data, size_t size) {
    unsigned int wait_ms;
    coap_pdu_t  *pdu;
    int result;

    if (!(pdu = coap_new_request(ctx_db, session_db, COAP_REQUEST_GET, &optlist, data, size))) {
        return false;
    }

    coap_log(LOG_DEBUG, "sending CoAP request:\n");
    if (coap_get_log_level() < LOG_DEBUG)
        coap_show_pdu(LOG_INFO, pdu);

    cwt = NULL;
    ready = 0;
    coap_send(session_db, pdu);

    wait_ms = wait_seconds * 1000;
    coap_log(LOG_DEBUG, "timeout is set to %u seconds\n", wait_seconds);

    while (!(ready && coap_can_exit(ctx_db))) {
        result = coap_run_once(ctx_db, wait_ms);

        if (result >= 0) {
            if ( wait_ms > 0) {
                if ( (unsigned)result >= wait_ms ) {
                    info("Timeout\n");
                    break;
                } else {
                    wait_ms -= result;
                }
            }
        }
    }

    if (cwt)
        return true;
    
    return false;
}

static void
hnd_get_token(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
    size_t size;
    unsigned char *data;

    coap_get_data(request, &size, &data);

    /* Assuming `data` contains `size` bytes of input data */
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    response->code = COAP_RESPONSE_404;

    if (cbor_isa_map(item) && cbor_map_size(item) == 2) {
        struct cbor_pair *pairs = cbor_map_handle(item);

        if (cbor_isa_string(pairs[0].key) && cbor_isa_string(pairs[1].key)) {
            size_t str_len1 = cbor_string_length(pairs[0].key),
                   str_len2 = cbor_string_length(pairs[1].key);
            
            char *keystr1 = malloc(str_len1 + 1),
                 *keystr2 = malloc(str_len2 + 1);
            
            memcpy(keystr1, cbor_string_handle(pairs[0].key), str_len1);
            keystr1[str_len1] = '\0';
            memcpy(keystr2, cbor_string_handle(pairs[1].key), str_len2);
            keystr2[str_len2] = '\0';

            if ((strcmp(keystr1, "user") == 0) && (strcmp(keystr2, "pass") == 0) &&
                cbor_isa_string(pairs[0].value) && cbor_isa_string(pairs[1].value)) {
                if (get_user_cwb(data, size) == true) {
                    unsigned char *buffer;
                    size_t buffer_size, length = cwt_serialize(cwt, &buffer, &buffer_size);

                    response->code = COAP_RESPONSE_200;
                    coap_add_data_blocked_response(resource, session, request, response, token,
                        COAP_MEDIATYPE_APPLICATION_CBOR, -1, length, buffer);

                    free(buffer);
                    cwt_free(cwt);
                }
            }

            free(keystr1);
            free(keystr2);
        }
    }
    /* Deallocate the result */
    cbor_decref(&item);
}

static void init_resources(coap_context_t *ctx) {
    coap_resource_t *r;

    r = coap_resource_init(coap_make_str_const("token"), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get_token);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
    coap_add_attr(r, coap_make_str_const("title"),
        coap_make_str_const("\"Gera um CWT para um determinado cliente\""), 0);
    coap_add_resource(ctx, r);
}

int main(int argc, char const *argv[]) {
    char addr_str[NI_MAXHOST] = AS_HOST;
    char port_str[NI_MAXSERV] = AS_PORT;
    coap_log_t log_level = LOG_DEBUG;
    unsigned wait_ms;

    key_length = cmdline_read_key(PSK, key, MAX_KEY);
    if (key_length < 0) {
        coap_log(LOG_CRIT, "Invalid PSK key specified\n");
        return EXIT_FAILURE;
    }

    priv_key = load_file_to_buff(PRIV_KEY);
    if (priv_key == NULL) {
        coap_log(LOG_CRIT, "Invalid private key suplied\n");
        return EXIT_FAILURE;
    }

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);

    ctx_main = get_context(addr_str, port_str);
    if (!ctx_main) {
        return EXIT_FAILURE;
    }

    init_resources(ctx_main);
    init_db_session();

    signal(SIGINT, handle_sigint);

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    while (!quit) {
        int result = coap_run_once(ctx_main, wait_ms);

        if (result < 0) {
            break;
        } else if (result && (unsigned)result < wait_ms) {
            /* decrement if there is a result wait time returned */
            wait_ms -= result;
        } else {
            /*
            * result == 0, or result >= wait_ms
            * (wait_ms could have decremented to a small value, below
            * the granularity of the timer in coap_run_once() and hence
            * result == 0)
            */
            if (result) {
                /* result must have been >= wait_ms, so reset wait_ms */
                wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
            }
        }
    }

    finish();

    return EXIT_SUCCESS;
}
