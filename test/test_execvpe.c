#include "execore_unistd.h"
#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *get_paths() {
  const char *paths = getenv("PATH");
  if (paths == NULL)
    paths = "/bin:/usr/bin";
  return paths;
}

static const char *get_path() { return CMAKE_SOURCE_DIR "/test"; }

static char *concat_paths(const char *path1, const char *path2) {
  size_t len1 = strlen(path1);
  size_t len2 = strlen(path2);
  char *buf = (char *)malloc(len1 + 1 + len2 + 1);
  if (buf == NULL)
    return NULL;
  memcpy(buf, path1, len1);
  buf[len1] = ':';
  memcpy(buf + len1 + 1, path2, len2 + 1);
  return buf;
}

extern char **environ;

static void test(const char *new_paths) {
  pid_t pid = fork();
  if (pid == 0) {
    setenv("PATH", new_paths, 1);
    char path[] = "test_execvpe.sh";
    char arg[] = "abc";
    char *argv[] = {path, arg, NULL};
    EXECORE_(execvpe)(argv[0], argv, environ);
    exit(1);
  }
  ASSERT_GT(pid, 0);
  int wstatus;
  ASSERT_EQ(pid, waitpid(pid, &wstatus, 0));
  ASSERT_TRUE(WIFEXITED(wstatus));
  ASSERT_EQ(0, WEXITSTATUS(wstatus));
}

static void test_execvpe_first(void) {
  char *path_buf = concat_paths(get_path(), get_paths());
  ASSERT_TRUE(path_buf != NULL);
  test(path_buf);
  free(path_buf);
}

static void test_execvpe_last(void) {
  char *path_buf = concat_paths(get_paths(), get_path());
  ASSERT_TRUE(path_buf != NULL);
  test(path_buf);
  free(path_buf);
}

static void test_execvpe_only(void) { test(get_path()); }

void test_execvpe(void) {
  test_execvpe_first();
  test_execvpe_last();
  test_execvpe_only();
}
