#ifndef EXECORE_MMAN_H
#define EXECORE_MMAN_H

#include <nolibc.h>

static __attribute__((unused)) int sys_mprotect(void *addr, size_t len,
                                                int prot) {
  return my_syscall3(__NR_mprotect, addr, len, prot);
}

static __attribute__((unused)) int mprotect(void *addr, size_t len, int prot) {
  int ret = sys_mprotect(addr, len, prot);

  if (ret < 0) {
    errno = -ret;
    ret = -1;
  }
  return ret;
}

#endif
