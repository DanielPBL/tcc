#ifndef COAP_RD_H
#define COAP_RD_H

#include <stdio.h>
#include <string.h>
#include <coap2/coap.h>

#define COAP_RESOURCE_CHECK_TIME 2

#define RD_ROOT_STR   "rd"
#define RD_ROOT_SIZE  2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef struct rd_t {
  UT_hash_handle hh;      /**< hash handle (for internal use only) */
  coap_string_t uri_path; /**< the actual key for this resource */

  size_t etag_len;        /**< actual length of @c etag */
  unsigned char etag[8];  /**< ETag for current description */

  coap_string_t data;     /**< points to the resource description  */
} rd_t;

rd_t * rd_new(void);

void rd_delete(rd_t *rd);

void
hnd_get_resource(coap_context_t  *ctx,
                 struct coap_resource_t *resource,
                 coap_session_t *session,
                 coap_pdu_t *request,
                 coap_binary_t *token,
                 coap_string_t *query,
                 coap_pdu_t *response);

void
hnd_put_resource(coap_context_t  *ctx,
                 struct coap_resource_t *resource,
                 coap_session_t *session,
                 coap_pdu_t *request,
                 coap_binary_t *token,
                 coap_string_t *query,
                 coap_pdu_t *response);
                 
void
hnd_delete_resource(coap_context_t  *ctx,
                    struct coap_resource_t *resource,
                    coap_session_t *session,
                    coap_pdu_t *request,
                    coap_binary_t *token,
                    coap_string_t *query,
                    coap_pdu_t *response);
                    
void
hnd_get_rd(coap_context_t  *ctx,
           struct coap_resource_t *resource,
           coap_session_t *session,
           coap_pdu_t *request,
           coap_binary_t *token,
           coap_string_t *query,
           coap_pdu_t *response);
           
int
parse_param(const uint8_t *search,
            size_t search_len,
            unsigned char *data,
            size_t data_len,
            coap_string_t *result);
            
void
add_source_address(struct coap_resource_t *resource,
                   coap_address_t *peer);
                   
rd_t *make_rd(coap_pdu_t *pdu);

void
hnd_post_rd(coap_context_t  *ctx,
            struct coap_resource_t *resource,
            coap_session_t *session,
            coap_pdu_t *request,
            coap_binary_t *token,
            coap_string_t *query,
            coap_pdu_t *response);
            
void init_rd_resources(coap_context_t *ctx);
#endif 
