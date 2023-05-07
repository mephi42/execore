#include "execore_maps.h"
#include "execore_stdlib.h"
#include "execore_string.h"
#include <nolibc.h>

static ssize_t for_each_mapping_1(char *buf, char *end, const char *path,
                                  int lineno,
                                  int (*cb)(struct mapping *, void *),
                                  void *arg) {
  const char *nl = EXECORE_(memchr)(buf, '\n', end - buf);
  if (nl == NULL)
    return 0;
  char *p = buf;

#define EXPECT_CHAR(c)                                                         \
  if (*p != (c)) {                                                             \
    fprintf(stderr, "%s:%d:%ld: expected " #c "\n", path, lineno,              \
            p - buf + 1);                                                      \
    return -1;                                                                 \
  }                                                                            \
  p++;

#define EXPECT_EITHER_CHAR(c1, c2)                                             \
  ({                                                                           \
    if (*p != (c1) && *p != (c2)) {                                            \
      fprintf(stderr, "%s:%d:%ld: expected " #c1 " or " #c2 "\n", path,        \
              lineno, p - buf + 1);                                            \
      return -1;                                                               \
    }                                                                          \
    p++;                                                                       \
    p[-1] != c1;                                                               \
  })

  struct mapping m;
  m.start = EXECORE_(strtoul)(p, &p, 16);
  EXPECT_CHAR('-');
  m.end = EXECORE_(strtoul)(p, &p, 16);
  EXPECT_CHAR(' ');

  m.r = EXPECT_EITHER_CHAR('-', 'r');
  m.w = EXPECT_EITHER_CHAR('-', 'w');
  m.x = EXPECT_EITHER_CHAR('-', 'x');
  m.p = EXPECT_EITHER_CHAR('s', 'p');
  EXPECT_CHAR(' ');

  m.offset = EXECORE_(strtoul)(p, &p, 16);
  EXPECT_CHAR(' ');

  m.major = EXECORE_(strtoul)(p, &p, 16);
  EXPECT_CHAR(':');
  m.minor = EXECORE_(strtoul)(p, &p, 16);
  EXPECT_CHAR(' ');

  m.inode = EXECORE_(strtoul)(p, &p, 10);
  EXPECT_EITHER_CHAR(' ', '\n');

#undef EXPECT_CHAR
#undef EXPECT_EITHER_CHAR

  if (cb(&m, arg) == -1)
    return -1;

  return nl - buf + 1;
}

int for_each_mapping(const char *path, int (*cb)(struct mapping *, void *),
                     void *arg) {
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open(%s failed: errno=%d\n", path, errno);
    goto err;
  }

  char buf[128 + PATH_MAX];
  char *buf_end = buf + sizeof(buf);
  char *high = buf;
  int lineno = 1;
  while (1) {
    ssize_t n_read = read(fd, high, buf_end - high);
    if (n_read < 0) {
      fprintf(stderr, "read(%s) failed: errno=%d\n", path, errno);
      goto err_close;
    }
    if (n_read == 0) {
      if (high == buf)
        break;
      fprintf(stderr, "%s:%d: line too long or no newline\n", path, lineno);
      goto err_close;
    }
    high += n_read;
    char *low = buf;
    while (1) {
      ssize_t n_parsed = for_each_mapping_1(low, high, path, lineno, cb, arg);
      if (n_parsed < 0)
        goto err_close;
      if (n_parsed == 0)
        break;
      low += n_parsed;
      lineno++;
    }
    memmove(buf, low, high - low);
    high = buf + (high - low);
  }

  close(fd);
  return 0;

err_close:
  close(fd);
err:
  return -1;
}
