#ifndef EXECORE_UNISTD_H
#define EXECORE_UNISTD_H

#ifndef NOLIBC
#include <stddef.h>
#include <sys/types.h>
#endif

#include "execore.h"

int EXECORE_(execvpe)(const char *file, char *const argv[], char *const envp[]);

#ifdef NOLIBC
static __attribute__((unused)) ssize_t sys_pread(int fd, void *buf,
                                                 size_t count, off_t offset) {
  return my_syscall4(__NR_pread64, fd, buf, count, offset);
}

static __attribute__((unused)) ssize_t pread(int fd, void *buf, size_t count,
                                             off_t offset) {
  ssize_t ret = sys_pread(fd, buf, count, offset);

  if (ret < 0) {
    errno = -ret;
    ret = -1;
  }

  return ret;
}
#endif

int pread_exact(int fd, void **buf, size_t *count, off_t *offset);

#define PREAD_EXACT(path, fd, buf, count, offset, label)                       \
  do {                                                                         \
    void *__buf = (buf);                                                       \
    size_t __count = (count);                                                  \
    off_t __offset = (offset);                                                 \
    if (pread_exact(fd, &__buf, &__count, &__offset) < 0) {                    \
      fprintf(stderr, "Could not read from %s: errno=%d\n", path, errno);      \
      goto label;                                                              \
    }                                                                          \
  } while (0)

#endif
