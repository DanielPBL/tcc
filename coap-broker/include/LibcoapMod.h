#ifndef LIBCOAP_MOD_H
#define LIBCOAP_MOD_H

#include <coap2/coap.h>
#include "utlist.h"

void coapDeleteAttr(coap_attr_t *attr);
void coapFreeResource(coap_resource_t *resource);
	
#endif
