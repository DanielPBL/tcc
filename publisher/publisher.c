#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <cbor.h>
#include <coap2/coap.h>

#include "coappsk.h"
#include "cwt.h"
#include "ssl_utils.h"
#include "servers.h"
#include "coap_utils.h"

#define WAIT_SECONDS 90

bool ready = false;
cbor_item_t *cwt = NULL;

bool get_cwt(coap_response_handler_t handler);
void
cwt_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id);

int main(int argc, char **argv) {
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_optlist_t *optlist = NULL;
    coap_string_t payload = { 0, NULL };
    coap_uri_t uri;
    char link[500];
    int opt;
    bool oauth = false;
    long log_level, num_msgs = 1;

  	while ((opt = getopt(argc, argv, "v:N:o")) != -1) {
		switch (opt) {
			case 'v':
				log_level = strtol(optarg, NULL, 10);
				printf("Debugging Level set to %ld\n", log_level);
				break;
			case 'N':
				num_msgs = strtol(optarg, NULL, 10);
				printf("Number of messages per second: %ld\n", num_msgs);
				break;
			case 'o':
				printf("OAth Enabled\n");
				oauth = true;
				break;
			default:
				exit(1);
		}
	}

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);

    if (optind < argc) {
        if (cmdline_uri(argv[optind], &optlist, &uri) < 0) {
            fprintf(stderr, "Erro ao conectar ao BROKER. URI inválido!\n");
            exit(1);
        }
    } else {
        fprintf(stderr, "É necessário informar o URI do broker\n");
        exit(1);
    }

    if (oauth) {
        if (!get_cwt(cwt_handler)) {
            fprintf(stderr, "Erro ao obter o CWT\n");
            exit(1);
        }
    }

    session = init_session(&ctx, &uri, NULL, USER, (uint8_t *)PSK, strlen(PSK));
    if (session == NULL) {
        fprintf(stderr, "Erro ao conectar ao Broker\n");
        exit(1);
    }
    
    /***************** Criação do TÓPICO **********************/
    /* Preallocate the map structure */
    size_t map_size = 1 + oauth;
    cbor_item_t *root = cbor_new_definite_map(map_size);
    /* Add the content */
    cmdline_input("<lux>;if=\"sensor\";ct=0;rt=\"candela\"", &payload);

    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_uint8(1)),
        .value = cbor_move(cbor_build_bytestring(payload.s, payload.length))
    });

    if (oauth) {
        cbor_map_add(root, (struct cbor_pair) {
            .key = cbor_move(cbor_build_uint8(1)),
            .value = cbor_move(cwt)
        });
    }
    /* Output: `length` bytes of data in the `buffer` */
    unsigned char *buffer;
    size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);
    coap_pdu_t  *pdu;
    uint8_t buf[2];
    unsigned int wait_ms;
    int result;

    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
        coap_encode_var_safe(buf, sizeof(buf), 40), buf));
    if (!(pdu = coap_new_request(COAP_MESSAGE_CON, ctx, session, COAP_REQUEST_POST,
        &optlist, buffer, length))) {
        return false;
    }

    coap_log(LOG_DEBUG, "sending CoAP request:\n");
    if (coap_get_log_level() < LOG_DEBUG)
        coap_show_pdu(LOG_INFO, pdu);

    coap_send(session, pdu);

    wait_ms = WAIT_SECONDS * 1000;
    coap_log(LOG_DEBUG, "timeout is set to %u seconds\n", WAIT_SECONDS);

    while (!coap_can_exit(ctx)) {
        result = coap_run_once(ctx, wait_ms);

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

    free(buffer);
    cbor_decref(&root);
    coap_session_release(session);
    /***************** Criação do TÓPICO **********************/

    coap_delete_optlist(optlist);
    optlist = NULL;
    snprintf(link, sizeof(link), "%s/lux", argv[optind]);
    cmdline_uri(link, &optlist, &uri);

    /**************** Publicar no TÓPICO **********************/
    session = init_session(&ctx, &uri, NULL, USER, (uint8_t *)PSK, strlen(PSK));
    /* Preallocate the map structure */
    root = cbor_new_definite_map(map_size);
    /* Add the content */
    cmdline_input("1000", &payload);

    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_uint8(1)),
        .value = cbor_move(cbor_build_bytestring(payload.s, payload.length))
    });

    if (oauth) {
        cbor_map_add(root, (struct cbor_pair) {
            .key = cbor_move(cbor_build_uint8(1)),
            .value = cbor_move(cwt)
        });
    }
    /* Output: `length` bytes of data in the `buffer` */
    length = cbor_serialize_alloc(root, &buffer, &buffer_size);

    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
        coap_encode_var_safe(buf, sizeof(buf), 0), buf));
    
    /***************** REPETIÇÃO *****************/
    time_t begin = time(NULL),
           loop = time(NULL) - 1;
    long count = 0;
    while (time(NULL) - begin < 60) {
        if (time(NULL) - loop > 0) {
            count = 0;
            loop = time(NULL);
        }

        while (count < num_msgs) {
            if (!(pdu = coap_new_request(COAP_MESSAGE_NON, ctx, session, COAP_REQUEST_PUT,
                &optlist, buffer, length))) {
                return false;
            }
            coap_send(session, pdu);
            count++;
        }

        while (!coap_can_exit(ctx)) {
            result = coap_run_once(ctx, 1000);

            if (result >= 1000) {
                coap_log(LOG_ERR, "Not all messages could be sent.\n");
            } else {
                coap_log(LOG_INFO, "Sent all messages in %d ms.\n", result);
            }
        }
    }
    /***************** REPETIÇÃO *****************/

    free(buffer);
    cbor_decref(&root);
    coap_session_release(session);
    /**************** Publicar no TÓPICO **********************/

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}

bool get_cwt(coap_response_handler_t handler) {
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_optlist_t *optlist = NULL;
    coap_uri_t uri;
    char link[500];

    //Pede CWT ao AS
    snprintf(link, sizeof(link), "coaps://[%s]:%s/token", AS_HOST, AS_PORT);
    cmdline_uri(link, &optlist, &uri);
    session = init_session(&ctx, &uri, handler, USER, (uint8_t *)PSK, strlen(PSK));
    if (session == NULL) {
        fprintf(stderr, "Erro ao conectar ao AS\n");
        exit(1);
    }

    /* Preallocate the map structure */
    cbor_item_t *root = cbor_new_definite_map(2);
    /* Add the content */
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("user")),
        .value = cbor_move(cbor_build_string("daniel"))
    });
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("pass")),
        .value = cbor_move(cbor_build_string("daniel"))
    });
    /* Output: `length` bytes of data in the `buffer` */
    unsigned char *buffer;
    size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);
    unsigned int wait_ms;
    coap_pdu_t  *pdu;
    int result;

    if (!(pdu = coap_new_request(COAP_MESSAGE_CON, ctx, session,
        COAP_REQUEST_GET, &optlist, buffer, length))) {
        return false;
    }

    coap_log(LOG_DEBUG, "sending CoAP request:\n");
    if (coap_get_log_level() < LOG_DEBUG)
        coap_show_pdu(LOG_INFO, pdu);

    ready = false;
    coap_send(session, pdu);

    wait_ms = WAIT_SECONDS * 1000;
    coap_log(LOG_DEBUG, "timeout is set to %u seconds\n", WAIT_SECONDS);

    while (!(ready && coap_can_exit(ctx))) {
        result = coap_run_once(ctx, wait_ms);

        if (result >= 0) {
            if (wait_ms > 0) {
                if ((unsigned)result >= wait_ms) {
                    info("Timeout\n");
                    break;
                } else {
                    wait_ms -= result;
                }
            }
        }
    }

    free(buffer);
    cbor_decref(&root);

    return ready && (cwt != NULL);
}

void
cwt_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id) {
    size_t len;
    unsigned char *databuf;

    coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           (received->code >> 5), received->code & 0x1F);
    if (coap_get_log_level() < LOG_DEBUG)
        coap_show_pdu(LOG_INFO, received);

    /* output the received data, if any */
    if (COAP_RESPONSE_CLASS(received->code) == 2) {
        /* There is no block option set, just read the data and we are done. */
        /* Gera CWT */
        if (coap_get_data(received, &len, &databuf)) {
            struct cbor_load_result result;
            cwt = cbor_load(databuf, len, &result);
            if (cwt == NULL) {
                printf("Algo deu errado!\n");
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
