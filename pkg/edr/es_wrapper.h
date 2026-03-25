#ifndef ES_WRAPPER_H
#define ES_WRAPPER_H

#include <EndpointSecurity/EndpointSecurity.h>

// C function that internally creates the Objective-C block required by es_new_client
es_new_client_result_t create_es_client(es_client_t **client);

#endif
