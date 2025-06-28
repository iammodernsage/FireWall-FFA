#ifndef INTERNAL_RULE_H
#define INTERNAL_RULE_H

#include <stdint.h>
#include <Stddef.h>

typedef struct internal_rule_t {
          int id;
          char *pattern;
          char *location;
          int action;
   } internal_rule_t;

#endif
