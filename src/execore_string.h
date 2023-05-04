#ifndef EXECORE_STRING_H
#define EXECORE_STRING_H

#include <nolibc.h>

static __attribute__((unused)) void *memchr(const void *s, int c, size_t n) {
  for (const char *p = s, *end = p + n; p != end; p++)
    if (*p == c)
      return (void *)p;
  return NULL;
}

#endif
