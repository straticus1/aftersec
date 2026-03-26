#ifndef ES_WRAPPER_H
#define ES_WRAPPER_H

#include <EndpointSecurity/EndpointSecurity.h>

// C function that internally creates the Objective-C block required by es_new_client
es_new_client_result_t create_es_client(es_client_t **client);

pid_t get_pid(const es_message_t *msg);
pid_t get_ppid(const es_message_t *msg);
uint32_t get_uid(const es_message_t *msg);
const char* get_executable_path(const es_message_t *msg, int *out_len);
const char* get_mount_path(const es_message_t *msg, int *out_len);

// Responds to an AUTH event and releases the retained message
void respond_auth_and_release(es_client_t *client, const es_message_t *msg, bool allow, bool cache);

#endif
