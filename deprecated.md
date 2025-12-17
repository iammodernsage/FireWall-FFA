## Codes & files that were deprecated or deleted

- From core-engine/internal_rule.h:

/* typedef struct internal_rule_t {
          int id;
          char *pattern;
          char *location;
          int action;
   } internal_rule_t; (commenting this because this is causing a hell lot of cofusions*/

-------------------------------

- From core-engine/waf-rules.c:

/*typedef struct { // add this part when needed (already defined in waf_rule.h)
   waf_rule_t rule;
   regex_t regex;          // Compiled regex
   pcre *pcre_pattern;     // PCRE compiled pattern
   pcre_extra *pcre_extra; // PCRE study data
   int is_regex;           // Flag for regex patterns
 } internal_rule_t;*/

----------------------------

- From tls-inspector/tls-parser.c

static int read_uint24(tls_buffer_t *buf, uint32_t *value);

----------------------------



