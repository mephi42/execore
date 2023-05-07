#ifndef EXECORE_PTRACE
#define EXECORE_PTRACE

struct iovec {
  void *iov_base;
  size_t iov_len;
};

enum __ptrace_request {
  PTRACE_TRACEME = 0,
  PTRACE_DETACH = 17,
  PTRACE_SETREGSET = 0x4205,
};

static __attribute__((unused)) long
sys_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
  return my_syscall4(__NR_ptrace, request, pid, addr, data);
}

#endif
