#ifndef INTERNAL_RULE_H
#define INTERNAL_RULE_H

#include <stdint.h>
#include <stddef.h>
#include <regex.h>
#include <pcre.h>

/* typedef struct internal_rule_t {
          int id;
          char *pattern;
          char *location;
          int action;
   } internal_rule_t; (commenting this because this is causing a hell lot of cofusions*/

typedef struct internal_rule_t {
   waf_rule_t rule;   // original rule

   regex_t regex;    //POSIX cmpiled regex
   pcre *pcre_pattern;   //PCRE compiled pattern
   pcre_extra *pcre_extra;  //PCRE study data

   int is_regex;
 } internal_rule_t;

#endif //internal_rule_h
