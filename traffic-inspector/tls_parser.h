#ifndef FireWall_FFA_TLS_PARSER_H
#define FireWall_FFA_TLS_PARSER_H

#include <stdint.h>
#include <stddef.h>

// Maximum lengths for various fields
#define MAX_SNI_LENGTH 256
#define MAX_CIPHER_SUITES 64

// Return codes
#define TLS_PARSE_OK 0
#define TLS_PARSE_ERROR -1
#define TLS_PARSE_UNINTERESTING -2

// TLS extension types
#define TLSEXT_TYPE_server_name 0
#define TLSEXT_TYPE_application_layer_protocol_negotiation 16

// TLS version macros
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

// Structure to hold extracted TLS information
typedef struct {
    uint16_t client_version;
    uint8_t random[32];
    uint16_t cipher_suites[MAX_CIPHER_SUITES];
    size_t cipher_suites_count;
    char sni[MAX_SNI_LENGTH];
} tls_info_t;

// Public API
int parse_tls(const uint8_t *data, size_t length, tls_info_t *info);

#endif // FireWall_FFA_TLS_PARSER_H
