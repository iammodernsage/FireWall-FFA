#include "ja3_fingerprint.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TLS_HEADER_LENGTH 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define MAX_JA3_STRING 1024

typedef struct {
    const uint8_t *data;
    size_t length;
    size_t position;
} ja3_buffer_t;

// Function declarations
static int read_u8(ja3_buffer_t *buf, uint8_t *val);
static int read_u16(ja3_buffer_t *buf, uint16_t *val);
static int read_u24(ja3_buffer_t *buf, uint32_t *val);
static int read_bytes(ja3_buffer_t *buf, uint8_t *out, size_t len);
static int skip_bytes(ja3_buffer_t *buf, size_t len);
static int parse_tls_handshake(ja3_buffer_t *buf, ja3_data_t *ja3);
static int parse_tls_extensions(ja3_buffer_t *buf, ja3_data_t *ja3);
static void generate_ja3_string(ja3_data_t *ja3, char *output);
static void md5_hash(const char *input, char *output);

int generate_ja3_fingerprint(const uint8_t *data, size_t len, char *ja3_hash) {
    if (!data || len < TLS_HEADER_LENGTH || !ja3_hash) {
        return JA3_ERROR_INVALID_INPUT;
    }

    ja3_buffer_t buf = { data, len, 0 };
    ja3_data_t ja3_data = {0};
    char ja3_string[MAX_JA3_STRING] = {0};

    uint8_t content_type;
    uint16_t version;
    uint16_t record_len;

    if (!read_u8(&buf, &content_type) ||
        !read_u16(&buf, &version) ||
        !read_u16(&buf, &record_len)) {
        return JA3_ERROR_INVALID_RECORD;
    }

    if (content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        return JA3_ERROR_NOT_HANDSHAKE;
    }

    if (buf.position + record_len > buf.length) {
        return JA3_ERROR_TRUNCATED;
    }

    int result = parse_tls_handshake(&buf, &ja3_data);
    if (result != JA3_SUCCESS) {
        ja3_data_free(&ja3_data);
        return result;
    }

    generate_ja3_string(&ja3_data, ja3_string);
    md5_hash(ja3_string, ja3_hash);
    ja3_data_free(&ja3_data);

    return JA3_SUCCESS;
}

static int parse_tls_handshake(ja3_buffer_t *buf, ja3_data_t *ja3) {
    uint8_t handshake_type;
    uint32_t handshake_len;

    if (!read_u8(buf, &handshake_type) || !read_u24(buf, &handshake_len)) {
        return JA3_ERROR_INVALID_HANDSHAKE;
    }

    if (handshake_type != TLS_HANDSHAKE_CLIENT_HELLO) {
        return JA3_ERROR_NOT_CLIENT_HELLO;
    }

    if (!read_u16(buf, &ja3->tls_version)) return JA3_ERROR_INVALID_VERSION;
    if (!skip_bytes(buf, 32)) return JA3_ERROR_INVALID_RANDOM;

    uint8_t session_id_len;
    if (!read_u8(buf, &session_id_len) || !skip_bytes(buf, session_id_len)) {
        return JA3_ERROR_INVALID_SESSION_ID;
    }

    uint16_t cipher_suites_len;
    if (!read_u16(buf, &cipher_suites_len)) return JA3_ERROR_INVALID_CIPHER_SUITES;

    ja3->cipher_suites = malloc(cipher_suites_len);
    if (!ja3->cipher_suites) return JA3_ERROR_MEMORY;

    if (!read_bytes(buf, ja3->cipher_suites, cipher_suites_len)) {
        free(ja3->cipher_suites);
        return JA3_ERROR_INVALID_CIPHER_SUITES;
    }
    ja3->cipher_suites_len = cipher_suites_len;

    uint8_t compression_methods_len;
    if (!read_u8(buf, &compression_methods_len)) {
        free(ja3->cipher_suites);
        return JA3_ERROR_INVALID_COMPRESSION;
    }

    ja3->compression_methods = malloc(compression_methods_len);
    if (!ja3->compression_methods) {
        free(ja3->cipher_suites);
        return JA3_ERROR_MEMORY;
    }

    if (!read_bytes(buf, ja3->compression_methods, compression_methods_len)) {
        free(ja3->cipher_suites);
        free(ja3->compression_methods);
        return JA3_ERROR_INVALID_COMPRESSION;
    }
    ja3->compression_methods_len = compression_methods_len;

    if (buf->position < buf->length) {
        int ext_result = parse_tls_extensions(buf, ja3);
        if (ext_result != JA3_SUCCESS) {
            free(ja3->cipher_suites);
            free(ja3->compression_methods);
            return ext_result;
        }
    }

    return JA3_SUCCESS;
}

static int parse_tls_extensions(ja3_buffer_t *buf, ja3_data_t *ja3) {
    uint16_t extensions_len;
    if (!read_u16(buf, &extensions_len)) return JA3_ERROR_INVALID_EXTENSIONS;

    size_t extensions_end = buf->position + extensions_len;
    size_t count = 0;
    uint16_t *ext_types = NULL;

    while (buf->position + 4 <= extensions_end) {
        uint16_t ext_type, ext_len;

        if (!read_u16(buf, &ext_type) || !read_u16(buf, &ext_len)) {
            free(ext_types);
            return JA3_ERROR_INVALID_EXTENSION;
        }

        uint16_t *tmp = realloc(ext_types, (count + 1) * sizeof(uint16_t));
        if (!tmp) {
            free(ext_types);
            return JA3_ERROR_MEMORY;
        }
        ext_types = tmp;
        ext_types[count++] = ext_type;

        if (!skip_bytes(buf, ext_len)) {
            free(ext_types);
            return JA3_ERROR_INVALID_EXTENSION;
        }
    }

    ja3->extensions = ext_types;
    ja3->extensions_len = count;
    return JA3_SUCCESS;
}

static void generate_ja3_string(ja3_data_t *ja3, char *output) {
    size_t pos = 0;

    pos += snprintf(output + pos, MAX_JA3_STRING - pos, "%d,", ja3->tls_version);

    for (size_t i = 0; i + 1 < ja3->cipher_suites_len; i += 2) {
        if (i > 0) pos += snprintf(output + pos, MAX_JA3_STRING - pos, "-");
        uint16_t suite = (ja3->cipher_suites[i] << 8) | ja3->cipher_suites[i + 1];
        pos += snprintf(output + pos, MAX_JA3_STRING - pos, "%d", suite);
    }

    pos += snprintf(output + pos, MAX_JA3_STRING - pos, ",");

    for (size_t i = 0; i < ja3->extensions_len; i++) {
        if (i > 0) pos += snprintf(output + pos, MAX_JA3_STRING - pos, "-");
        pos += snprintf(output + pos, MAX_JA3_STRING - pos, "%d", ja3->extensions[i]);
    }

    pos += snprintf(output + pos, MAX_JA3_STRING - pos, ",,");

    // For now we skip optional EC data
}

static void md5_hash(const char *input, char *output) {
    unsigned char digest[JA3_HASH_LEN];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < JA3_HASH_LEN; i++) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }
    output[JA3_HASH_LEN * 2] = '\0';
}

void ja3_data_free(ja3_data_t *ja3) {
    if (!ja3) return;
    free(ja3->cipher_suites);
    free(ja3->compression_methods);
    free(ja3->extensions);
    free(ja3->elliptic_curves);
    free(ja3->ec_point_formats);
    memset(ja3, 0, sizeof(*ja3));
}

// Buffer reader helpers
static int read_u8(ja3_buffer_t *buf, uint8_t *val) {
    if (buf->position + 1 > buf->length) return 0;
    *val = buf->data[buf->position++];
    return 1;
}

static int read_u16(ja3_buffer_t *buf, uint16_t *val) {
    if (buf->position + 2 > buf->length) return 0;
    *val = (buf->data[buf->position] << 8) | buf->data[buf->position + 1];
    buf->position += 2;
    return 1;
}

static int read_u24(ja3_buffer_t *buf, uint32_t *val) {
    if (buf->position + 3 > buf->length) return 0;
    *val = (buf->data[buf->position] << 16) |
           (buf->data[buf->position + 1] << 8) |
           buf->data[buf->position + 2];
    buf->position += 3;
    return 1;
}

static int read_bytes(ja3_buffer_t *buf, uint8_t *out, size_t len) {
    if (buf->position + len > buf->length) return 0;
    memcpy(out, buf->data + buf->position, len);
    buf->position += len;
    return 1;
}

static int skip_bytes(ja3_buffer_t *buf, size_t len) {
    if (buf->position + len > buf->length) return 0;
    buf->position += len;
    return 1;
}
