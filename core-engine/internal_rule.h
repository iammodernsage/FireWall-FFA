#ifndef INTERNAL_RULE_H
#define INTERNAL_RULE_H

#include <stdint.h>
#include <regex.h>
#include <pcre.h>

#include <waf.h>

typedef struct internal_rule {
   waf_rule_t rule;   // original rule

   regex_t regex;    //POSIX cmpiled regex
   pcre *pcre_pattern;   //PCRE compiled pattern
   pcre_extra *pcre_extra;  //PCRE study data

   int is_regex;
 } internal_rule_t;

#endif //internal_rule_h
