/* clang-format off */
#include <nolibc.h>
/* clang-format on */
#include "execore_unistd.h"
#include "execore_string.h"
#include <alloca.h>

static const char *path_end(const char *p) {
  if (p == NULL)
    return NULL;
  while (*p != 0 && *p != ':')
    p++;
  return p;
}

#define FOR_EACH_PATH(paths, start, end)                                       \
  for (const char *start = (paths), *end = path_end(start); start != NULL;     \
       start = *end == ':' ? end + 1 : NULL, end = path_end(start))

static size_t get_max_path_len(const char *paths) {
  size_t max_len = 0;
  FOR_EACH_PATH(paths, start, end) {
    size_t len = end - start;
    if (len > max_len)
      max_len = len;
  }
  return max_len;
}

int EXECORE_(execvpe)(const char *file, char *const argv[],
                      char *const envp[]) {
  size_t len = strlen(file);
  if (EXECORE_(memchr)(file, '/', len) != NULL)
    return execve(file, argv, envp);
  const char *paths = getenv("PATH");
  if (paths == NULL)
    paths = "/bin:/usr/bin";
  char *path_buf = alloca(get_max_path_len(paths) + 1 + len + 1);
  int local_errno = 0;
  FOR_EACH_PATH(paths, start, end) {
    char *p = path_buf;
    memcpy(p, start, end - start);
    p += end - start;
    *(p++) = '/';
    memcpy(p, file, len + 1);
    if (execve(path_buf, argv, envp) == -1) {
      if (errno == EACCES)
        local_errno = EACCES;
      /* TODO: handle ENOEXEC as specified by man 3 execvpe */
    }
  }
  if (local_errno != 0)
    errno = local_errno;
  return -1;
}

ssize_t pread_exact(int fd, void *buf, size_t count, off_t offset) {
  size_t orig_count = count;
  while (count != 0) {
    ssize_t n_read = pread(fd, buf, count, offset);
    if (n_read < 0) {
      return -1;
    }
    if (n_read == 0) {
      errno = EIO;
      return -1;
    }
    buf += n_read;
    count -= n_read;
    offset += n_read;
  }
  return orig_count;
}
