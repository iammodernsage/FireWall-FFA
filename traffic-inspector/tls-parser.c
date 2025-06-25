#include "tls_parser.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#define TLS_HEADER_LENGTH 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

// Internal structure for TLS state
typedef struct {
    uint8_t *data;
    size_t length;
    size_t position;
} tls_buffer_t;

// Function prototypes
static int parse_tls_record(tls_buffer_t *buf, tls_info_t *info);
static int parse_client_hello(tls_buffer_t *buf, tls_info_t *info);
static int read_uint8(tls_buffer_t *buf, uint8_t *value);
static int read_uint16(tls_buffer_t *buf, uint16_t *value);
static int read_uint24(tls_buffer_t *buf, uint32_t *value);
static int read_bytes(tls_buffer_t *buf, uint8_t *dest, size_t length);
static int skip_bytes(tls_buffer_t *buf, size_t length);

// Main TLS parsing function
int parse_tls(const uint8_t *data, size_t length, tls_info_t *info) {
    if (!data || length < TLS_HEADER_LENGTH || !info) {
        return TLS_PARSE_ERROR;
    }

    memset(info, 0, sizeof(tls_info_t));

    tls_buffer_t buf = {
        .data = (uint8_t *)data,
        .length = length,
        .position = 0
    };

    return parse_tls_record(&buf, info);
}

// Parse a TLS record
static int parse_tls_record(tls_buffer_t *buf, tls_info_t *info) {
    uint8_t content_type;
    uint16_t version;
    uint16_t record_length;

    if (!read_uint8(buf, &content_type) ||
        !read_uint16(buf, &version) ||
        !read_uint16(buf, &record_length)) {
        return TLS_PARSE_ERROR;
    }

    // We only care about Handshake messages
    if (content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        return TLS_PARSE_UNINTERESTING;
    }

    // Check if we have enough data for the record
    if (buf->position + record_length > buf->length) {
        return TLS_PARSE_ERROR;
    }

    // Save the record boundary
    size_t record_end = buf->position + record_length;

    // Parse handshake message
    uint8_t handshake_type;
    if (!read_uint8(buf, &handshake_type)) {
        return TLS_PARSE_ERROR;
    }

    // We only care about Client Hello
    if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        return TLS_PARSE_UNINTERESTING;
    }

    // Skip handshake message length (3 bytes)
    if (!skip_bytes(buf, 3)) {
        return TLS_PARSE_ERROR;
    }

    // Parse client version
    if (!read_uint16(buf, &info->client_version)) {
        return TLS_PARSE_ERROR;
    }

    // Parse client random (32 bytes)
    if (!read_bytes(buf, info->random, 32)) {
        return TLS_PARSE_ERROR;
    }

    // Parse session ID
    uint8_t session_id_length;
    if (!read_uint8(buf, &session_id_length)) {
        return TLS_PARSE_ERROR;
    }
    if (!skip_bytes(buf, session_id_length)) {
        return TLS_PARSE_ERROR;
    }

    // Parse cipher suites
    uint16_t cipher_suites_length;
    if (!read_uint16(buf, &cipher_suites_length)) {
        return TLS_PARSE_ERROR;
    }
    info->cipher_suites_count = cipher_suites_length / 2;
    if (info->cipher_suites_count > MAX_CIPHER_SUITES) {
        info->cipher_suites_count = MAX_CIPHER_SUITES;
    }
    for (int i = 0; i < info->cipher_suites_count; i++) {
        if (!read_uint16(buf, &info->cipher_suites[i])) {
            return TLS_PARSE_ERROR;
        }
    }

    // Skip compression methods
    uint8_t compression_methods_length;
    if (!read_uint8(buf, &compression_methods_length)) {
        return TLS_PARSE_ERROR;
    }
    if (!skip_bytes(buf, compression_methods_length)) {
        return TLS_PARSE_ERROR;
    }

    // Parse extensions if present
    if (buf->position < record_end) {
        uint16_t extensions_length;
        if (!read_uint16(buf, &extensions_length)) {
            return TLS_PARSE_ERROR;
        }

        size_t extensions_end = buf->position + extensions_length;
        while (buf->position + 4 <= extensions_end) {
            uint16_t extension_type;
            uint16_t extension_length;
 
            if (!read_uint16(buf, &extension_type) ||
                !read_uint16(buf, &extension_length)) {
                return TLS_PARSE_ERROR;
            }

            // Handle specific extensions we care about
            switch (extension_type) {
                case TLSEXT_TYPE_server_name: {
                    uint16_t list_length;
                    uint8_t name_type;
                    uint16_t name_length;

                    if (!read_uint16(buf, &list_length) ||
                        !read_uint8(buf, &name_type) ||
                        !read_uint16(buf, &name_length)) {
                        return TLS_PARSE_ERROR;
                    }

                    if (name_type == 0) { // hostname
                        if (name_length > MAX_SNI_LENGTH - 1) {
                            name_length = MAX_SNI_LENGTH - 1;
                        }
                        if (!read_bytes(buf, (uint8_t *)info->sni, name_length)) {
                            return TLS_PARSE_ERROR;
                        }
                        info->sni[name_length] = '\0';
                        skip_bytes(buf, extension_length - 5 - name_length);
                    } else {
                        skip_bytes(buf, extension_length - 3);
                    }
                    break;
                }
                case TLSEXT_TYPE_application_layer_protocol_negotiation: {
                    uint16_t alpn_length;
                    if (!read_uint16(buf, &alpn_length)) {
                        return TLS_PARSE_ERROR;
                    }
                    skip_bytes(buf, extension_length - 2);
                    break;
                }
                default:
                    skip_bytes(buf, extension_length);
                    break;
            }
        }
    }

    return TLS_PARSE_OK;
}

// Helper function to read a uint8 from buffer
static int read_uint8(tls_buffer_t *buf, uint8_t *value) {
    if (buf->position + 1 > buf->length) {
        return 0;
    }
    *value = buf->data[buf->position++];
    return 1;
}

// Helper function to read a uint16 from buffer
static int read_uint16(tls_buffer_t *buf, uint16_t *value) {
    if (buf->position + 2 > buf->length) {
        return 0;
    }
    *value = (buf->data[buf->position] << 8) | buf->data[buf->position + 1];
    buf->position += 2;
    return 1;
}

// Helper function to read a uint24 from buffer
static int read_uint24(tls_buffer_t *buf, uint32_t *value) {
    if (buf->position + 3 > buf->length) {
        return 0;
    }
    *value = (buf->data[buf->position] << 16) | 
             (buf->data[buf->position + 1] << 8) | 
             buf->data[buf->position + 2];
    buf->position += 3;
    return 1;
}

// Helper function to read bytes from buffer
static int read_bytes(tls_buffer_t *buf, uint8_t *dest, size_t length) {
    if (buf->position + length > buf->length) {
        return 0;
    }
    memcpy(dest, buf->data + buf->position, length);
    buf->position += length;
    return 1;
}

// Helper function to skip bytes in buffer
static int skip_bytes(tls_buffer_t *buf, size_t length) {
    if (buf->position + length > buf->length) {
        return 0;
    }
    buf->position += length;
    return 1;
}
