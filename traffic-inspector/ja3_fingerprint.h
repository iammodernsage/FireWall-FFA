#ifndef FIREWALL_FFA_JA3_FINGERPRINT_H
#define FIREWALL_FFA_JA3_FINGERPRINT_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/md5.h>

// Return codes
#define JA3_SUCCESS 0
#define JA3_ERROR_INVALID_INPUT -1
#define JA3_ERROR_INVALID_RECORD -2
#define JA3_ERROR_NOT_HANDSHAKE -3
#define JA3_ERROR_TRUNCATED -4
#define JA3_ERROR_INVALID_HANDSHAKE -5
#define JA3_ERROR_NOT_CLIENT_HELLO -6
#define JA3_ERROR_INVALID_VERSION -7
#define JA3_ERROR_INVALID_RANDOM -8
#define JA3_ERROR_INVALID_SESSION_ID -9
#define JA3_ERROR_INVALID_CIPHER_SUITES -10
#define JA3_ERROR_INVALID_COMPRESSION -11
#define JA3_ERROR_INVALID_EXTENSIONS -12
#define JA3_ERROR_INVALID_EXTENSION -13
#define JA3_ERROR_MEMORY -14

// JA3 data structure
typedef struct {
    uint16_t tls_version;
    uint8_t *cipher_suites;
    size_t cipher_suites_len;
    uint8_t *compression_methods;
    size_t compression_methods_len;
    uint16_t *extensions;
    size_t extensions_len;
    uint8_t *elliptic_curves;
    size_t elliptic_curves_len;
    uint8_t *ec_point_formats;
    size_t ec_point_formats_len;
} ja3_data_t;

/**
 * Generates a JA3 fingerprint from TLS Client Hello data
 * 
 * @param data Pointer to the raw TLS data
 * @param len Length of the TLS data
 * @param ja3_hash Output buffer for the JA3 hash (must be at least 33 bytes)
 * @return JA3_SUCCESS if fingerprint was generated, error code otherwise
 */
int generate_ja3_fingerprint(const uint8_t *data, size_t len, char *ja3_hash);

/**
 * Frees memory allocated in a ja3_data_t structure
 * 
 * @param ja3 Pointer to the JA3 data structure to free
 */
void ja3_data_free(ja3_data_t *ja3);

#endif // FireWall_FFA_JA3_FINGERPRINT_H
