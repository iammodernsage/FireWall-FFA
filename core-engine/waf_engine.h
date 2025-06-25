#ifndef FireWall-FFA_WAF_ENGINE_H
#define FIREWALL-FFA_WAF_ENGINE_H

#include <stdint.h>

typedef struct {
    void *rules;
    uint64_t req_count;
} waf_engine_t;

// WAF actions
typedef enum {
    WAF_ACTION_ALLOW = 0,
    WAF_ACTION_BLOCK,
    WAF_ACTION_CHALLENGE,
    WAF_ACTION_LOG
} waf_action_t;

// HTTP request structure for WAF inspection
typedef struct {
    const char *method;
    const char *uri;
    const char *headers;
    const char *body;
    size_t body_length;
    const char *remote_ip;
} waf_http_request_t;

// Public API
waf_engine_t *waf_init();
waf_action_t waf_process_request(waf_engine_t *waf, const waf_http_request_t *req);
void waf_cleanup(waf_engine_t *waf);

#endif
