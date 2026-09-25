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
const char* get_target_path(const es_message_t *msg, int *out_len);
const char* get_rename_path(const es_message_t *msg, int *out_len);
const char* get_rename_existing_dest(const es_message_t *msg, int *out_len);
const char* get_rename_new_dir(const es_message_t *msg, int *out_len);
const char* get_rename_new_name(const es_message_t *msg, int *out_len);
uint32_t notify_rename_event_code(void);
const char* get_open_target_path(const es_message_t *msg, int *out_len);
const char* get_unlink_path(const es_message_t *msg, int *out_len);
bool open_requests_write(const es_message_t *msg);
uint32_t auth_open_event_code(void);
uint32_t auth_exec_event_code(void);
uint32_t notify_exec_event_code(void);
uint32_t notify_exit_event_code(void);
uint32_t notify_mount_event_code(void);
uint32_t notify_unlink_event_code(void);
uint32_t notify_tcc_event_code(void);
int exec_arg_count(const es_message_t *msg);
const char* exec_arg(const es_message_t *msg, int index, int *out_len);
const char* get_exec_target_path(const es_message_t *msg, int *out_len);
int copy_tcc_revocation(const es_message_t *msg, char *service, int service_cap, char *identity, int identity_cap);

// Responds to an AUTH event and releases the retained message
void respond_auth_and_release(es_client_t *client, const es_message_t *msg, bool allow, bool cache);

// Retain message with availability check (macOS 11.0+)
void retain_message_safe(const es_message_t *msg);

#endif
