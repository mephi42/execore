#ifndef EXECORE_PROCFS_H
#define EXECORE_PROCFS_H

#include "execore_user.h"
#include <nolibc.h>

#if defined(__x86_64__)

__extension__ typedef unsigned long long elf_greg_t;
#define ELF_NGREG (sizeof(struct user_regs_struct) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

struct elf_siginfo {
  int si_signo;
  int si_code;
  int si_errno;
};

struct elf_prstatus {
  struct elf_siginfo pr_info;
  short int pr_cursig;
  unsigned long int pr_sigpend;
  unsigned long int pr_sighold;
  pid_t pr_pid;
  pid_t pr_ppid;
  pid_t pr_pgrp;
  pid_t pr_sid;
  struct timeval pr_utime;
  struct timeval pr_stime;
  struct timeval pr_cutime;
  struct timeval pr_cstime;
  elf_gregset_t pr_reg;
  int pr_fpvalid;
};

#else
#error Unsupported architecture
#endif

#endif
