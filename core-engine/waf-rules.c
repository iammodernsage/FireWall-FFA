/*This where the rules are*/

#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0x10

#include "waf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <pcre.h>
#include <ctype.h>
#include "internal_rule.h"
#include <fnmatch.h>

// Internal rule storage structure

 typedef struct { // add this part when needed (already defined in waf_rule.h)
   waf_rule_t rule;
   regex_t regex;          // Compiled regex
   pcre *pcre_pattern;     // PCRE compiled pattern
   pcre_extra *pcre_extra; // PCRE study data
   int is_regex;           // Flag for regex patterns
 } internal_rule_t;

static internal_rule_t *internal_rules = NULL;
static size_t internal_rules_count = 0;

// Forward declarations
static int compile_rule_pattern(internal_rule_t *internal_rule);
static void free_rule_resources(internal_rule_t *rule);

// Initialize the rules engine
int waf_rules_init() {
    // Nothing needed for now, but keeping the function for future expansion as the project progresses
    return WAF_OK;
}

// Add and compile a rule
int waf_add_compiled_rule(const waf_rule_t *rule) {
    if (rule == NULL || rule->pattern == NULL) {
        return WAF_ERROR;
    }

    // Reallocate internal rules array
    internal_rule_t *new_rules = realloc(internal_rules,
                                       (internal_rules_count + 1) * sizeof(internal_rule_t));
    if (new_rules == NULL) {
        return WAF_ERROR;
    }

    internal_rules = new_rules;
    internal_rule_t *new_rule = &internal_rules[internal_rules_count];

    // Initialize the new rule
    memset(new_rule, 0, sizeof(internal_rule_t));
    memcpy(&new_rule->rule, rule, sizeof(waf_rule_t));

    // Try to compile as regex first
    new_rule->is_regex = 1;
    if (compile_rule_pattern(new_rule) != WAF_OK) {
        // Fall back to simple pattern matching if regex compilation fails
        new_rule->is_regex = 0;
    }

    internal_rules_count++;
    return WAF_OK;
}

// Compile a rule pattern (regex or simple)
static int compile_rule_pattern(internal_rule_t *internal_rule) {
    const char *error;
    int erroffset;

    // First try PCRE compilation (more powerful regex)
    internal_rule->pcre_pattern = pcre_compile(
        internal_rule->rule.pattern,
        PCRE_CASELESS | PCRE_MULTILINE,
        &error,
        &erroffset,
        NULL
    );

    if (internal_rule->pcre_pattern != NULL) {
        // Study the pattern for better performance
        internal_rule->pcre_extra = pcre_study(
            internal_rule->pcre_pattern,
            0,
            &error
        );
        return WAF_OK;
    }

    // Fall back to POSIX regex if PCRE fails
    if (regcomp(&internal_rule->regex, internal_rule->rule.pattern,
               REG_EXTENDED | REG_NOSUB | REG_ICASE) == 0) {
        return WAF_OK;
    }

    return WAF_ERROR;
}

// Match a rule against a request
int waf_match_rule(const waf_rule_t *rule, const waf_http_request_t *request,
                  waf_match_t *match) {
    if (rule == NULL || request == NULL || match == NULL) {
        return 0;
    }

    // Find the internal rule representation
    internal_rule_t *internal_rule = NULL;
    for (size_t i = 0; i < internal_rules_count; i++) {
        if (internal_rules[i].rule.id == rule->id) {
            internal_rule = &internal_rules[i];
            break;
        }
    }

    if (internal_rule == NULL) {
        return 0;
    }

    // Check URI
    if (request->uri && waf_match_string(internal_rule, request->uri, "uri", match)) {
        return 1;
    }

    // Check headers
    if (request->headers && waf_match_string(internal_rule, request->headers, "headers", match)) {
        return 1;
    }

    // Check body
    if (request->body && request->body_length > 0 && 
        waf_match_string(internal_rule, request->body, "body", match)) {
        return 1;
    }

    return 0;
}

// Match a rule against a specific string
int waf_match_string(internal_rule_t *rule, const char *str, const char *location, 
                   waf_match_t *match) {
    if (rule == NULL || str == NULL || match == NULL) {
        return 0;
    }

    int result = 0;
    const char *match_ptr = NULL;

    if (rule->is_regex) {
        if (rule->pcre_pattern != NULL) {
            // Use PCRE for matching
            int ovector[30]; // Room for 10 matches
            int rc = pcre_exec(
                rule->pcre_pattern,
                rule->pcre_extra,
                str,
                strlen(str),
                0,
                0,
                ovector,
                30
            );

            if (rc >= 0) {
                result = 1;
                match_ptr = str + ovector[0];
            }
        } else {
            // Fall back to POSIX regex
            result = regexec(&rule->regex, str, 0, NULL, 0) == 0;
            if (result) {
                match_ptr = str; // POSIX regex doesn't give us match position
            }
        }
    } else {
        // Simple pattern matching (case insensitive)
        result = (fnmatch(rule->rule.pattern, str, FNM_CASEFOLD) == 0);
        if (result) {
            match_ptr = str;
        }
    }

    if (result) {
        match->rule_id = rule->rule.id;
        match->match_location = location;
        match->matched_string = match_ptr;
        match->match_offset = match_ptr ? (size_t)(match_ptr - str) : 0;
    }

    return result;
}

// Remove a rule by ID
int waf_remove_compiled_rule(uint32_t rule_id) {
    int found = 0;

    for (size_t i = 0; i < internal_rules_count; i++) {
        if (internal_rules[i].rule.id == rule_id) {
            // Free resources
            free_rule_resources(&internal_rules[i]);

            // Shift remaining rules
            memmove(&internal_rules[i], &internal_rules[i + 1], 
                   (internal_rules_count - i - 1) * sizeof(internal_rule_t));
            
            internal_rules_count--;
            found = 1;
            break;
        }
    }

    return found ? WAF_OK : WAF_ERROR;
}

// Free resources associated with a rule
static void free_rule_resources(internal_rule_t *rule) {
    if (rule == NULL) return;

    if (rule->is_regex) {
        if (rule->pcre_pattern != NULL) {
            pcre_free(rule->pcre_pattern);
        }
        if (rule->pcre_extra != NULL) {
            pcre_free_study(rule->pcre_extra);
        }
    } else {
        regfree(&rule->regex);
    }
}

// Cleanup all rules
void waf_rules_cleanup() {
    for (size_t i = 0; i < internal_rules_count; i++) {
        free_rule_resources(&internal_rules[i]);
    }

    free(internal_rules);
    internal_rules = NULL;
    internal_rules_count = 0;
}

// Get rule by ID
const waf_rule_t *waf_get_rule_by_id(uint32_t rule_id) {
    for (size_t i = 0; i < internal_rules_count; i++) {
        if (internal_rules[i].rule.id == rule_id) {
            return &internal_rules[i].rule;
        }
    }
    return NULL;
}

// Count of loaded rules
size_t waf_rule_count() {
    return internal_rules_count;
}

// Rule optimization (recompile all rules for better performance - working more on this part)
int waf_optimize_rules() {
    for (size_t i = 0; i < internal_rules_count; i++) {
        free_rule_resources(&internal_rules[i]);
        if (compile_rule_pattern(&internal_rules[i]) != WAF_OK) {
            return WAF_ERROR;
        }
    }
    return WAF_OK;
}

#endif
