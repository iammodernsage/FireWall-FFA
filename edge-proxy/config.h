#ifndef FireWall-FFA_CONFIG_H
#define FIREWALL_FFA_CONFIG_H

// Default ports
#define DEFAULT_HTTP_PORT  80
#define DEFAULT_HTTPS_PORT 443

// Timeouts (in seconds)
#define CLIENT_TIMEOUT     30
#define BACKEND_TIMEOUT    10

// Paths (adjust for your filesystem layout)
#define DEFAULT_CONFIG_PATH    "/etc/FireWall-FFA/config.yml"
#define DEFAULT_RULES_DIR      "/etc/FireWall-FFA/rules"
#define DEFAULT_CERT_DIR       "/etc/FireWall-FFA/certs"

// WAF settings
#define WAF_MAX_REQ_SIZE    (10 * 1024 * 1024)  // 10MB
#define WAF_MAX_DEPTH       20

// SSL/TLS settings
#define SSL_CIPHERS "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"

#endif
