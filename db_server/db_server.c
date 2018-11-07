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

#include <my_global.h>
#include <mysql.h>
#include <cbor.h>

#include <coap2/coap.h>
#include "coappsk.h"
#include "db_cred.h"
#include "servers.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static uint8_t key[MAX_KEY];
static ssize_t key_length = 0;
static const char *hint = HINT;

static MYSQL *con;

static int quit = 0;

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
        coap_endpoint_t *ep_dtls;

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

static int get_user_auths(char *login, char *pass, char *auths, unsigned long bsize) {
    char query[] = "SELECT auths FROM Users WHERE login=? AND pass=SHA2(?, 0)";
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[3];

    char str_data[1000];
    unsigned long length;
    my_bool is_null, error;

    memset(bind, 0, sizeof(bind));
    stmt = mysql_stmt_init(con);
    if (stmt == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    
    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
        fprintf(stderr, "%s\n", mysql_stmt_error(stmt));
        return -1;
    }

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = login;
    bind[0].buffer_length = strlen(login);

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = pass;
    bind[1].buffer_length = strlen(pass);
    
    if (mysql_stmt_bind_param(stmt, bind) != 0) {
        fprintf(stderr, "%s\n", mysql_stmt_error(stmt));
        return -1;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "%s\n", mysql_stmt_error(stmt));
        return -1;
    }

    bind[2].buffer_type = MYSQL_TYPE_STRING;
    bind[2].buffer = str_data;
    bind[2].buffer_length = sizeof(str_data);
    bind[2].is_null = &is_null;
    bind[2].length = &length;
    bind[2].error = &error;

    if (mysql_stmt_bind_result(stmt, &bind[2]) != 0) {
        fprintf(stderr, "%s\n", mysql_stmt_error(stmt));
        return -1;
    }

    while (mysql_stmt_fetch(stmt) == 0) {
        if (is_null == 0) {
            strncpy(auths, str_data, bsize);
            mysql_stmt_free_result(stmt);
            return 0;
        }
    }

    mysql_stmt_free_result(stmt);

    return -1;
}

static void
hnd_get_auths(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
    char auths[500];
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
                str_len1 = cbor_string_length(pairs[0].value);
                str_len2 = cbor_string_length(pairs[1].value);
                keystr1 = realloc(keystr1, str_len1 + 1);
                keystr2 = realloc(keystr2, str_len2 + 1);
                memcpy(keystr1, cbor_string_handle(pairs[0].value), str_len1);
                keystr1[str_len1] = '\0';
                memcpy(keystr2, cbor_string_handle(pairs[1].value), str_len2);
                keystr2[str_len2] = '\0';

                if (get_user_auths(keystr1, keystr2, auths, sizeof(auths)) == 0) {
                    cbor_item_t *sauths = cbor_build_string(auths);
                    unsigned char *buffer;
                    size_t buffer_size, length = cbor_serialize_alloc(sauths, &buffer, &buffer_size);

                    response->code = COAP_RESPONSE_200;
                    coap_add_data_blocked_response(resource, session, request, response, token,
                        COAP_MEDIATYPE_APPLICATION_CBOR, -1, length, buffer);

                    free(buffer);
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

    r = coap_resource_init(coap_make_str_const("auths"), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get_auths);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
    coap_add_attr(r, coap_make_str_const("title"),
        coap_make_str_const("\"Autentica um cliente e obtém sua lista de autorizações\""), 0);
    coap_add_resource(ctx, r);
}

static void init_db() {
    con = mysql_init(NULL);

    if (con == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        quit = 1;
        return;
    }

    if (mysql_real_connect(con, DB_SERVER, DB_USER, DB_PASS, DB_DATABASE, 0, NULL, 0) == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
        con = NULL;
        quit = 1;
        return;
    }
}

int main(int argc, char const *argv[]) {
    coap_context_t  *ctx;
    char addr_str[NI_MAXHOST] = DB_HOST;
    char port_str[NI_MAXSERV] = DB_PORT;
    coap_log_t log_level = LOG_DEBUG;
    unsigned wait_ms;

    key_length = cmdline_read_key(PSK, key, MAX_KEY);
    if (key_length < 0) {
        coap_log( LOG_CRIT, "Invalid PSK key specified\n" );
        return EXIT_FAILURE;
    }

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);

    ctx = get_context(addr_str, port_str);
    if (!ctx) {
        return EXIT_FAILURE;
    }

    init_resources(ctx);
    init_db();

    signal(SIGINT, handle_sigint);

    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    while (!quit) {
        int result = coap_run_once(ctx, wait_ms);

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

    coap_free_context(ctx);
    coap_cleanup();

    if (con != NULL) {
        mysql_close(con);
    }

    return EXIT_SUCCESS;
}
