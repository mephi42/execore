#ifndef EXECORE_STRING_H
#define EXECORE_STRING_H

#include "execore.h"

static __attribute__((unused)) void *EXECORE_(memchr)(const void *s, int c,
                                                      size_t n) {
  for (const char *p = s, *end = p + n; p != end; p++)
    if (*p == c)
      return (void *)p;
  return NULL;
}

#define strdupa(s)                                                             \
  (__extension__({                                                             \
    const char *__old = (s);                                                   \
    size_t __len = strlen(__old) + 1;                                          \
    char *__new = (char *)__builtin_alloca(__len);                             \
    (char *)memcpy(__new, __old, __len);                                       \
  }))

#endif
