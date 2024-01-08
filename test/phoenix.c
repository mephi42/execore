#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd != -1) {
    char buf[16];
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  raise(SIGABRT);
  puts("On the edge of death, my heart races. I am alive!");
  return EXIT_SUCCESS;
}
