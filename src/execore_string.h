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

#define strcata(s1, s2)                                                        \
  (__extension__({                                                             \
    const char *__s1 = (s1);                                                   \
    const char *__s2 = (s2);                                                   \
    size_t __len1 = strlen(__s1);                                              \
    size_t __len2 = strlen(__s2);                                              \
    char *__buf = (char *)__builtin_alloca(__len1 + __len2 + 1);               \
    memcpy(__buf, __s1, __len1);                                               \
    memcpy(__buf + __len1, __s2, __len2 + 1);                                  \
    __buf;                                                                     \
  }))

#endif
