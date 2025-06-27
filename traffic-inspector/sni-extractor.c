#include "sni_extractor.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

// TLS Constants
#define TLS_HEADER_LENGTH 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLSEXT_TYPE_SERVER_NAME 0x00
#define MAX_SNI_LENGTH 256

// Internal buffer structure
typedef struct {
    const uint8_t *data;
    size_t length;
    size_t position;
} sni_buffer_t;

// Helper functions
static int read_u8(sni_buffer_t *buf, uint8_t *val);
static int read_u16(sni_buffer_t *buf, uint16_t *val);
static int read_u24(sni_buffer_t *buf, uint32_t *val);
static int read_bytes(sni_buffer_t *buf, uint8_t *out, size_t len);
static int skip_bytes(sni_buffer_t *buf, size_t len);
static int parse_tls_handshake(sni_buffer_t *buf, char *sni);
static int parse_tls_extensions(sni_buffer_t *buf, char *sni);

// Main SNI extraction function
int extract_sni(const uint8_t *data, size_t len, char *sni) {
    if (!data || len < TLS_HEADER_LENGTH || !sni) {
        return SNI_EXTRACT_INVALID_INPUT;
    }

    sni_buffer_t buf = {
        .data = data,
        .length = len,
        .position = 0
    };

    uint8_t content_type;
    uint16_t version;
    uint16_t record_len;

    // Read TLS record header
    if (!read_u8(&buf, &content_type) || 
        !read_u16(&buf, &version) || 
        !read_u16(&buf, &record_len)) {
        return SNI_EXTRACT_INVALID_RECORD;
    }

    // We only care about Handshake messages
    if (content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        return SNI_EXTRACT_NOT_HANDSHAKE;
    }

    // Verify we have enough data for the record
    if (buf.position + record_len > buf.length) {
        return SNI_EXTRACT_TRUNCATED;
    }

    // Parse handshake message
    return parse_tls_handshake(&buf, sni);
}

// Parse TLS handshake message
static int parse_tls_handshake(sni_buffer_t *buf, char *sni) {
    uint8_t handshake_type;
    uint32_t handshake_len;

    if (!read_u8(buf, &handshake_type) || 
        !read_u24(buf, &handshake_len)) {
        return SNI_EXTRACT_INVALID_HANDSHAKE;
    }

    // We only care about Client Hello
    if (handshake_type != TLS_HANDSHAKE_CLIENT_HELLO) {
        return SNI_EXTRACT_NOT_CLIENT_HELLO;
    }

    // Skip client version (2), random (32), session_id (1+len)
    uint8_t session_id_len;
    if (!skip_bytes(buf, 34) || 
        !read_u8(buf, &session_id_len) || 
        !skip_bytes(buf, session_id_len)) {
        return SNI_EXTRACT_INVALID_CLIENT_HELLO;
    }

    // Skip cipher suites (2+len)
    uint16_t cipher_suites_len;
    if (!read_u16(buf, &cipher_suites_len) || 
        !skip_bytes(buf, cipher_suites_len)) {
        return SNI_EXTRACT_INVALID_CIPHER_SUITES;
    }

    // Skip compression methods (1+len)
    uint8_t compression_methods_len;
    if (!read_u8(buf, &compression_methods_len) || 
        !skip_bytes(buf, compression_methods_len)) {
        return SNI_EXTRACT_INVALID_COMPRESSION;
    }

    // Parse extensions if present
    if (buf->position < buf->length) {
        return parse_tls_extensions(buf, sni);
    }

    return SNI_EXTRACT_NO_EXTENSIONS;
}

// Parse TLS extensions to find SNI
static int parse_tls_extensions(sni_buffer_t *buf, char *sni) {
    uint16_t extensions_len;
    if (!read_u16(buf, &extensions_len)) {
        return SNI_EXTRACT_INVALID_EXTENSIONS;
    }

    size_t extensions_end = buf->position + extensions_len;
    int sni_found = 0;

    while (buf->position + 4 <= extensions_end) {
        uint16_t extension_type;
        uint16_t extension_len;

        if (!read_u16(buf, &extension_type) || 
            !read_u16(buf, &extension_len)) {
            return SNI_EXTRACT_INVALID_EXTENSION;
        }

        if (extension_type == TLSEXT_TYPE_SERVER_NAME) {
            uint16_t server_name_list_len;
            uint8_t name_type;
            uint16_t name_len;

            if (!read_u16(buf, &server_name_list_len) || 
                !read_u8(buf, &name_type) || 
                !read_u16(buf, &name_len)) {
                return SNI_EXTRACT_INVALID_SNI;
            }

            if (name_type == 0) {  // hostname type
                if (name_len > MAX_SNI_LENGTH - 1) {
                    name_len = MAX_SNI_LENGTH - 1;
                }

                if (!read_bytes(buf, (uint8_t *)sni, name_len)) {
                    return SNI_EXTRACT_INVALID_SNI;
                }
                sni[name_len] = '\0';
                sni_found = 1;
            }

            // Skip remaining extension data if any
            size_t bytes_read = 5 + name_len;
            if (bytes_read < extension_len) {
                if (!skip_bytes(buf, extension_len - bytes_read)) {
                    return SNI_EXTRACT_INVALID_SNI;
                }
            }
        } else {
            // Skip other extensions
            if (!skip_bytes(buf, extension_len)) {
                return SNI_EXTRACT_INVALID_EXTENSION;
            }
        }
    }

    return sni_found ? SNI_EXTRACT_SUCCESS : SNI_EXTRACT_NO_SNI;
}

// Helper function to read 1 byte
static int read_u8(sni_buffer_t *buf, uint8_t *val) {
    if (buf->position + 1 > buf->length) return 0;
    *val = buf->data[buf->position++];
    return 1;
}

// Helper function to read 2 bytes (network order)
static int read_u16(sni_buffer_t *buf, uint16_t *val) {
    if (buf->position + 2 > buf->length) return 0;
    *val = (buf->data[buf->position] << 8) | buf->data[buf->position + 1];
    buf->position += 2;
    return 1;
}

// Helper function to read 3 bytes (network order)
static int read_u24(sni_buffer_t *buf, uint32_t *val) {
    if (buf->position + 3 > buf->length) return 0;
    *val = (buf->data[buf->position] << 16) | 
           (buf->data[buf->position + 1] << 8) | 
           buf->data[buf->position + 2];
    buf->position += 3;
    return 1;
}

// Helper function to read bytes
static int read_bytes(sni_buffer_t *buf, uint8_t *out, size_t len) {
    if (buf->position + len > buf->length) return 0;
    memcpy(out, buf->data + buf->position, len);
    buf->position += len;
    return 1;
}

// Helper function to skip bytes
static int skip_bytes(sni_buffer_t *buf, size_t len) {
    if (buf->position + len > buf->length) return 0;
    buf->position += len;
    return 1;
}
