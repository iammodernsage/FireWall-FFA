/*This is where the main file script is*/

#include "waf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "tls_parser.h"
#include "sni_extractor.h"
#include "ja3_fingerprint.h"

// Global configuration
waf_config_t global_config;

// Rule storage
waf_rule_t *rules = NULL;
size_t rules_count = 0;
pthread_rwlock_t rules_lock;

// Statistics
waf_stats_t waf_stats;
pthread_mutex_t stats_lock;

// Initialize the WAF engine
int waf_init(const waf_config_t *config) {
    if (config == NULL) {
        return WAF_ERROR;
    }

    // Copy configuration
    memcpy(&global_config, config, sizeof(waf_config_t));

    // Initialize locks
    if (pthread_rwlock_init(&rules_lock, NULL) != 0) {
        return WAF_ERROR;
    }

    if (pthread_mutex_init(&stats_lock, NULL) != 0) {
        pthread_rwlock_destroy(&rules_lock);
        return WAF_ERROR;
    }

    // Initialize statistics
    memset(&waf_stats, 0, sizeof(waf_stats_t));
    waf_stats.start_time = time(NULL);

    // Load default rules if configured
    if (global_config.load_default_rules) {
        if (waf_load_default_rules() != WAF_OK) {
            fprintf(stderr, "Warning: Failed to load default rules\n");
        }
    }

    return WAF_OK;
}

// Process an HTTP request
waf_action_t waf_process_request(const waf_http_request_t *request) {
    if (request == NULL) {
        return WAF_ACTION_ALLOW;
    }

    waf_action_t final_action = WAF_ACTION_ALLOW;
    waf_match_t match;

    // TLS Inspection Integration
    // If this is a TLS request (you may detect via port 443 or content-type)

    if (request->is_tls) {
        tls_info_t tls_info;
        memset(&tls_info, 0, sizeof(tls_info_t));

        if (parse_tls(&request->payload, &tls_info) == 0) {
            // Log or act based on SNI
            if (tls_info.sni) {
                printf("[*] Extracted SNI: %s\n", tls_info.sni);
                // You can apply SNI-based rules here as per your convenience
            }

            // JA3 fingerprinting
            char ja3_hash[36];  // enough for MD5
            if (generate_ja3_fingerprint(&tls_info, ja3_hash, sizeof(ja3_hash)) == 0) {
                printf("[*] JA3 Fingerprint: %s\n", ja3_hash);
                // Apply fingerprint-based rules or blacklist
            }
        } else {
            fprintf(stderr, "[!] Failed to parse TLS ClientHello\n");
        }
    }

    // Lock rules for reading
    pthread_rwlock_rdlock(&rules_lock);

    // Check each rule
    for (size_t i = 0; i < rules_count; i++) {
        if (waf_match_rule(&rules[i], request, &match)) {
            // Update statistics
            pthread_mutex_lock(&stats_lock);
            waf_stats.rules_matched[match.rule_id]++;
            waf_stats.total_requests_blocked++;
            pthread_mutex_unlock(&stats_lock);

            // Log the match if configured
            if (global_config.log_matches) {
                waf_log_match(&match, request);
            }

            // Take the most severe action
            if (rules[i].action > final_action) {
                final_action = rules[i].action;
            }

            // Break if we've reached the most severe action
            if (final_action == WAF_ACTION_BLOCK) {
                break;
            }
        }
    }

    pthread_rwlock_unlock(&rules_lock);

    // Update general statistics
    pthread_mutex_lock(&stats_lock);
    waf_stats.total_requests_processed++;
    if (final_action != WAF_ACTION_ALLOW) {
        waf_stats.total_requests_blocked++;
    }
    pthread_mutex_unlock(&stats_lock);

    return final_action;
}

// Add a new rule to the WAF
int waf_add_rule(const waf_rule_t *rule) {
    if (rule == NULL) {
        return WAF_ERROR;
    }

    // Lock rules for writing
    pthread_rwlock_wrlock(&rules_lock);

    // Reallocate rules array
    waf_rule_t *new_rules = realloc(rules, (rules_count + 1) * sizeof(waf_rule_t));
    if (new_rules == NULL) {
        pthread_rwlock_unlock(&rules_lock);
        return WAF_ERROR;
    }

    rules = new_rules;
    memcpy(&rules[rules_count], rule, sizeof(waf_rule_t));
    rules_count++;

    pthread_rwlock_unlock(&rules_lock);
    return WAF_OK;
}

// Remove a rule by ID
int waf_remove_rule(uint32_t rule_id) {
    int found = 0;

    pthread_rwlock_wrlock(&rules_lock);

    for (size_t i = 0; i < rules_count; i++) {
        if (rules[i].id == rule_id) {
            // Shift remaining rules
            memmove(&rules[i], &rules[i + 1], 
                   (rules_count - i - 1) * sizeof(waf_rule_t));
            rules_count--;
            found = 1;
            break;
        }
    }

    pthread_rwlock_unlock(&rules_lock);

    return found ? WAF_OK : WAF_ERROR;
}

// Load default rules
int waf_load_default_rules() {
    // This will load built-in rules for common attacks
    // Implementation should depend on your rule format

    // Placeholder for actual implementation
    waf_rule_t default_rules[] = {
        // SQL Injection patterns
        { .id = 1001, .action = WAF_ACTION_BLOCK, .pattern = "(?i)(\\bunion\\b.*\\bselect\\b)" },
        // XSS patterns
        { .id = 1002, .action = WAF_ACTION_BLOCK, .pattern = "(<script>|javascript:)" },
        // Path traversal
        { .id = 1003, .action = WAF_ACTION_BLOCK, .pattern = "(\\.\\./|\\.\\.\\\\)" }
    };

    for (size_t i = 0; i < sizeof(default_rules)/sizeof(default_rules[0]); i++) {
        if (waf_add_rule(&default_rules[i]) != WAF_OK) {
            return WAF_ERROR;
        }
    }

    return WAF_OK;
}

// Cleanup WAF resources
void waf_cleanup() {
    pthread_rwlock_wrlock(&rules_lock);
    free(rules);
    rules = NULL;
    rules_count = 0;
    pthread_rwlock_unlock(&rules_lock);

    pthread_rwlock_destroy(&rules_lock);
    pthread_mutex_destroy(&stats_lock);
}

// Get current statistics
waf_stats_t waf_get_stats() {
    waf_stats_t stats_copy;

    pthread_mutex_lock(&stats_lock);
    stats_copy = waf_stats;
    pthread_mutex_unlock(&stats_lock);

    return stats_copy;
}
