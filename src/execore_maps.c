#include "execore_maps.h"
#include "execore_stdlib.h"
#include "execore_string.h"
#include <nolibc.h>

#define PROC_SELF_MAPS "/proc/self/maps"

static ssize_t for_each_mapping_1(char *buf, char *end,
                                  int (*cb)(struct mapping *, void *),
                                  void *arg) {
  const char *nl = memchr(buf, '\n', end - buf);
  if (nl == NULL)
    return 0;
  char *p = buf;

#define EXPECT_CHAR(c)                                                         \
  if (*p != (c)) {                                                             \
    fprintf(stderr, PROC_SELF_MAPS ": expected " #c "\n");                     \
    return -1;                                                                 \
  }                                                                            \
  p++;

#define EXPECT_EITHER_CHAR(c1, c2)                                             \
  if (*p != (c1) && *p != (c2)) {                                              \
    fprintf(stderr, PROC_SELF_MAPS ": expected " #c1 " or " #c2 "\n");         \
    return -1;                                                                 \
  }                                                                            \
  p++;

  struct mapping m;
  m.start = strtoul(p, &p, 16);
  EXPECT_CHAR('-');
  m.end = strtoul(p, &p, 16);
  EXPECT_CHAR(' ');

  EXPECT_EITHER_CHAR('r', '-');
  EXPECT_EITHER_CHAR('w', '-');
  EXPECT_EITHER_CHAR('x', '-');
  EXPECT_CHAR('p');
  EXPECT_CHAR(' ');

  m.offset = strtoul(p, &p, 16);
  EXPECT_CHAR(' ');

  m.major = strtoul(p, &p, 16);
  EXPECT_CHAR(':');
  m.minor = strtoul(p, &p, 16);
  EXPECT_CHAR(' ');

  m.inode = strtoul(p, &p, 10);
  EXPECT_CHAR(' ');

#undef EXPECT_CHAR
#undef EXPECT_EITHER_CHAR

  if (cb(&m, arg) == -1)
    return -1;

  return nl - buf + 1;
}

int for_each_mapping(int (*cb)(struct mapping *, void *), void *arg) {
  int fd = open(PROC_SELF_MAPS, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open(" PROC_SELF_MAPS " failed: errno=%d\n", errno);
    goto err;
  }

  char buf[128 + PATH_MAX];
  char *buf_end = buf + sizeof(buf);
  char *high = buf;
  while (1) {
    ssize_t n_read = read(fd, high, buf_end - high);
    if (n_read < 0) {
      fprintf(stderr, "read(" PROC_SELF_MAPS ") failed: errno=%d\n", errno);
      goto err_close;
    }
    if (n_read == 0) {
      if (high == buf)
        break;
      fprintf(stderr, PROC_SELF_MAPS ": line too long or no newline\n");
      goto err_close;
    }
    high += n_read;
    char *low = buf;
    while (1) {
      ssize_t n_parsed = for_each_mapping_1(low, high, cb, arg);
      if (n_parsed < 0)
        goto err_close;
      if (n_parsed == 0)
        break;
      low += n_parsed;
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
