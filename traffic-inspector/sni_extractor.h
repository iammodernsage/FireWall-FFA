#include "sni_extractor.h"

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
