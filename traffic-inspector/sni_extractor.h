#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdio.h>

#define SNI_EXTRACT_SUCCESS                   0
#define SNI_EXTRACT_NO_SNI                   -1
#define SNI_EXTRACT_INVALID_INPUT            -2
#define SNI_EXTRACT_INVALID_RECORD           -3
#define SNI_EXTRACT_NOT_HANDSHAKE            -4
#define SNI_EXTRACT_TRUNCATED                -5
#define SNI_EXTRACT_INVALID_HANDSHAKE        -6
#define SNI_EXTRACT_NOT_CLIENT_HELLO         -7
#define SNI_EXTRACT_INVALID_CLIENT_HELLO     -8
#define SNI_EXTRACT_INVALID_CIPHER_SUITES    -9
#define SNI_EXTRACT_INVALID_COMPRESSION      -10
#define SNI_EXTRACT_NO_EXTENSIONS            -11
#define SNI_EXTRACT_INVALID_EXTENSIONS       -12
#define SNI_EXTRACT_INVALID_EXTENSION        -13
#define SNI_EXTRACT_INVALID_SNI              -14

int extract_sni(const uint8_t *data, size_t len, char *sni);

void process_packet(const uint8_t *data, size_t len) {
    char sni[256] = {0};
    int result = extract_sni(data, len, sni);

    switch (result) {
        case SNI_EXTRACT_SUCCESS:
            printf("Found SNI: %s\n", sni);
            break;
        case SNI_EXTRACT_NO_SNI:
            printf("No SNI extension present\n");
            break;
        default:
            printf("Error extracting SNI: %d\n", result);
            break;
    }
}

#endif
