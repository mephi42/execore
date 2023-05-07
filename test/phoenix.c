#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  raise(SIGABRT);
  puts("On the edge of death, my heart races. I am alive!");
  return EXIT_SUCCESS;
}
