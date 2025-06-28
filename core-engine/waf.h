/*Header File*/

#ifndef FIREWALL_FFA_WAF_H
#define FIREWALL_FFA_WAF_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// Return codes
#define WAF_OK 0
#define WAF_ERROR -1

// WAF actions
typedef enum {
    WAF_ACTION_ALLOW = 0,
    WAF_ACTION_LOG = 1,
    WAF_ACTION_CHALLENGE = 2,
    WAF_ACTION_BLOCK = 3
} waf_action_t;

// HTTP request structure
typedef struct {
    const char *method;
    const char *uri;
    const char *headers;
    const char *body;
    size_t body_length;
    const char *remote_ip;
    const char *hostname;
    const char *payload;
    size_t payload_len;
    int is_tls; //flag from proxy or traffic inspector
} waf_http_request_t;

// WAF rule definition
typedef struct {
    uint32_t id;
    waf_action_t action;
    const char *pattern;  // Regex pattern or other matching criteria
    const char *description;
} waf_rule_t;

// Rule match information
typedef struct {
    uint32_t rule_id;
    const char *matched_string;
    const char *match_location;  // "header", "body", "uri", etc.
    size_t match_offset;
} waf_match_t;

// WAF configuration
typedef struct {
    int load_default_rules;
    int log_matches;
    int performance_mode;  // Trade security for speed
    // Add more configuration options as needed
} waf_config_t;

// WAF statistics
typedef struct {
    time_t start_time;
    uint64_t total_requests_processed;
    uint64_t total_requests_blocked;
    uint64_t rules_matched[1024];  // Assuming rule IDs are < 1024
} waf_stats_t;

// Public API
int waf_init(const waf_config_t *config);
waf_action_t waf_process_request(const waf_http_request_t *request);
int waf_add_rule(const waf_rule_t *rule);
int waf_remove_rule(uint32_t rule_id);
int waf_load_default_rules();
void waf_cleanup();
waf_stats_t waf_get_stats();

// Rules engine API
int waf_rules_init();
int waf_add_compiled_rule(const waf_rule_t *rule);
int waf_match_rule(const waf_rule_t *rule, const waf_http_request_t *request, 
                  waf_match_t *match);
int waf_match_string(internal_rule_t *rule, const char *str, const char *location,
                   waf_match_t *match);
int waf_remove_compiled_rule(uint32_t rule_id);
void waf_rules_cleanup();
const waf_rule_t *waf_get_rule_by_id(uint32_t rule_id);
size_t waf_rule_count();
int waf_optimize_rules();

#endif // FireWall_FFA_WF_H
