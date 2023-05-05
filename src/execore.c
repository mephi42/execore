#include "execore_maps.h"
#include "execore_procfs.h"
#include "execore_ptrace.h"
#include "execore_stdlib.h"
#include <alloca.h>
#include <elf.h>
#include <nolibc.h>

static char local_stack[8 * 1024 * 1024];

#if defined(__x86_64__)

#define ARCH_EM EM_X86_64

static void arch_switch_stack(void __attribute__((noreturn)) (*f)(void *),
                              void *arg, void *stack) {
  asm("mov %[stack],%%rsp\n"
      "mov %[arg],%%rdi\n"
      "jmp *%[f]\n"
      :
      : [f] "r"(f), [arg] "r"(arg), [stack] "r"(stack)
      : "rdi");
  __builtin_unreachable();
}

static int arch_is_mappable_addr(void *p) {
  /* [vsyscall] */
  return (unsigned long)p != 0xffffffffff600000;
}

static int arch_setregset(pid_t pid, const char *name, unsigned int type,
                          const void *desc, const void *desc_end,
                          const char *core_path) {
  if (strcmp(name, "CORE") == 0 && type == NT_PRSTATUS) {
    if (desc_end - desc != (ssize_t)sizeof(struct elf_prstatus)) {
      fprintf(stderr, "%s contains a bad NT_PRSTATUS\n", core_path);
      goto err;
    }
    struct elf_prstatus *prstatus = (struct elf_prstatus *)desc;
    struct iovec iov = {
        .iov_base = &prstatus->pr_reg,
        .iov_len = sizeof(prstatus->pr_reg),
    };
    long pt_err = sys_ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    if (pt_err < 0) {
      fprintf(stderr, "PTRACE_SETREGSET failed: errno=%d\n", (int)-pt_err);
      goto err;
    }
  }
  return 0;

err:
  return -1;
}

#else
#error Unsupported architecture
#endif

static int sys_fstat(int fd, struct sys_stat_struct *statbuf) {
  return my_syscall2(__NR_fstat, fd, statbuf);
}

static void *mmap_path(void *addr, const char *path, int *fd, size_t *length) {
  int local_fd = open(path, O_RDONLY);
  if (local_fd == -1) {
    fprintf(stderr, "open(%s) failed: errno=%d\n", path, errno);
    goto err;
  }
  struct sys_stat_struct statbuf;
  int err = sys_fstat(local_fd, &statbuf);
  if (err < 0) {
    fprintf(stderr, "fstat(%s) failed: errno=%d\n", path, -err);
    goto err_close;
  }
  void *p = mmap(addr, statbuf.st_size, PROT_READ, MAP_PRIVATE | MAP_FIXED,
                 local_fd, 0);
  if (p == MAP_FAILED) {
    fprintf(stderr, "mmap(%s) failed: errno=%d\n", path, errno);
    goto err_close;
  }
  *fd = local_fd;
  *length = statbuf.st_size;
  return p;

err_close:
  close(local_fd);
err:
  return NULL;
}

static int is_mappable_phdr(Elf64_Phdr *phdr) {
  if (phdr->p_type != PT_LOAD)
    return 0;
  return arch_is_mappable_addr((void *)phdr->p_vaddr);
}

static int get_prot(Elf64_Word p_flags) {
  int prot = 0;
  if (p_flags & PF_X)
    prot |= PROT_EXEC;
  if (p_flags & PF_W)
    prot |= PROT_WRITE;
  if (p_flags & PF_R)
    prot |= PROT_READ;
  return prot;
}

static int setregset(pid_t pid, const void *data, const void *data_end,
                     const char *core_path) {
  const void *p = data;
  while (p != data_end) {
    if (data_end - data < (ssize_t)(sizeof(unsigned int) * 3)) {
      fprintf(stderr, "%s contains an incomplete PT_NOTE\n", core_path);
      goto err;
    }
    const unsigned int *note = p;
    const char *name = (const char *)(note + 3);
    const void *desc = name + ((note[0] + 3) & -4);
    if (desc < (const void *)name || desc > data_end) {
      fprintf(stderr, "%s contains a bad namesz\n", core_path);
      goto err;
    }
    p = desc + ((note[1] + 3) & -4);
    if (p < desc || p > data_end) {
      fprintf(stderr, "%s contains a bad descsz\n", core_path);
      goto err;
    }
    if (arch_setregset(pid, name, note[2], desc, desc + note[1], core_path) ==
        -1)
      return -1;
  }
  return 0;

err:
  return -1;
}

static void execore_1(Elf64_Ehdr *ehdr, int fd, size_t length, char **gdb_argv,
                      const char *core_path) {
  void *end = (void *)ehdr + length;
  if ((void *)(ehdr + 1) > end || ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
      ehdr->e_ident[EI_MAG1] != ELFMAG1 || ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
      ehdr->e_ident[EI_MAG3] != ELFMAG3) {
    fprintf(stderr, "%s is not an ELF file\n", core_path);
    goto err;
  }
  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "%s is not a 64-bit ELF file\n", core_path);
    goto err;
  }
  if (ehdr->e_type != ET_CORE) {
    fprintf(stderr, "%s is not a core file\n", core_path);
    goto err;
  }
  if (ehdr->e_machine != ARCH_EM) {
    fprintf(stderr, "%s is for a different machine\n", core_path);
    goto err;
  }
  Elf64_Phdr *phdr = (void *)ehdr + ehdr->e_phoff;
  Elf64_Phdr *phdr_end = phdr + ehdr->e_phnum;
  if ((void *)phdr > end || phdr > phdr_end || (void *)phdr_end > end) {
    fprintf(stderr, "%s contains a bad e_phoff or e_phnum\n", core_path);
    goto err;
  }
  int phdr_i = 0;
  for (; phdr_i < ehdr->e_phnum; phdr_i++) {
    Elf64_Phdr *phdr_cur = &phdr[phdr_i];
    void *data = (void *)ehdr + phdr_cur->p_offset;
    void *data_end = data + phdr_cur->p_filesz;
    if (data > end || data > data_end || data_end > end) {
      fprintf(stderr, "%s contains a bad Phdr[%d]\n", core_path, phdr_i);
      goto err_munmap;
    }
    if (!is_mappable_phdr(phdr_cur))
      continue;
    void *p = mmap((void *)phdr_cur->p_vaddr, phdr_cur->p_memsz,
                   get_prot(phdr_cur->p_flags),
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
      fprintf(stderr,
              "mmap(%s Phdr[%d]=%p, 0x%lx, MAP_ANONYMOUS) failed: errno=%d\n",
              core_path, phdr_i, (void *)phdr_cur->p_vaddr,
              (long)phdr_cur->p_memsz, errno);
      goto err_munmap;
    }
    if (phdr_cur->p_filesz > 0) {
      p = mmap((void *)phdr_cur->p_vaddr, phdr_cur->p_filesz,
               get_prot(phdr_cur->p_flags), MAP_PRIVATE | MAP_FIXED, fd,
               phdr_cur->p_offset);
      if (p == MAP_FAILED) {
        fprintf(stderr, "mmap(%s Phdr[%d]=%p, 0x%lx) failed: errno=%d\n",
                core_path, phdr_i, (void *)phdr_cur->p_vaddr,
                (long)phdr_cur->p_filesz, errno);
        goto err_munmap;
      }
    }
  }

  pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "fork() failed: errno=%d\n", errno);
    goto err_munmap;
  }
  if (pid == 0) {
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    abort();
  }
  int wstatus;
  int err = waitpid(pid, &wstatus, 0);
  if (err == -1) {
    fprintf(stderr, "waitpid(%d) failed: errno=%d\n", (int)pid, errno);
    goto err_kill;
  }
  if (!WIFSTOPPED(wstatus)) {
    fprintf(stderr, "The child process did not stop itself\n");
    goto err_kill;
  }
  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf64_Phdr *phdr_cur = &phdr[i];
    void *data = (void *)ehdr + phdr_cur->p_offset;
    void *data_end = data + phdr_cur->p_filesz;
    if (phdr_cur->p_type == PT_NOTE &&
        setregset(pid, data, data_end, core_path) == -1)
      goto err_munmap;
  }
  long pt_err = sys_ptrace(PTRACE_DETACH, pid, 0, (void *)SIGSTOP);
  if (pt_err < 0) {
    fprintf(stderr, "PTRACE_DETACH failed: errno=%d\n", (int)-pt_err);
    goto err_kill;
  }
  char pid_str[32];
  itoa_r((long)pid, pid_str);
  gdb_argv[2] = pid_str;
  if (execve(gdb_argv[0], gdb_argv, environ) == -1) {
    fprintf(stderr, "execve() failed: errno=%d\n", errno);
    goto err_kill;
  }

err_kill:
  kill(pid, SIGKILL);
err_munmap:
  for (int j = 0; j < phdr_i; j++)
    if (is_mappable_phdr(&phdr[j]))
      munmap((void *)phdr[j].p_vaddr, phdr[j].p_memsz);
err:
}

extern char _end[];

static int unmap_1(struct mapping *m, void *arg) {
  struct stat *self = arg;
  int is_self =
      ((m->major << 8) | m->minor) == self->st_dev && m->inode == self->st_ino;
  int is_bss = m->start < (unsigned long)(local_stack + sizeof(local_stack)) &&
               m->end > (unsigned long)local_stack;
  if (!is_self && !is_bss && arch_is_mappable_addr((void *)m->start)) {
    if (munmap((void *)m->start, m->end - m->start) == -1) {
      fprintf(stderr, "munmap(%p) failed: errno=%d\n", (void *)m->start, errno);
      return -1;
    }
  }
  return 0;
}

static int unmap_all(void) {
  struct stat self;
  if (stat("/proc/self/exe", &self) == -1) {
    fprintf(stderr, "stat(/proc/self/exe) failed: errno=%d\n", errno);
    return -1;
  }
  return for_each_mapping(&unmap_1, &self);
}

struct argc_argv {
  int argc;
  char **argv;
};

static void __attribute__((noreturn)) execore(void *arg) {
  struct argc_argv *aa = arg;
  if (aa->argc < 2) {
    fprintf(stderr, "Usage: %s CORE [GDB_ARG [GDB_ARG ...]]\n", aa->argv[0]);
    goto err;
  }
  char *core_path = strdupa(aa->argv[1]);

  char **gdb_argv = alloca((aa->argc + 2) * sizeof(char *));
  gdb_argv[0] = "/usr/bin/gdb";
  gdb_argv[1] = "-p";
  for (int i = 2; i < aa->argc; i++)
    gdb_argv[i + 1] = strdupa(aa->argv[i]);
  gdb_argv[aa->argc + 1] = NULL;

  size_t environ_n;
  for (environ_n = 0; environ[environ_n]; environ_n++)
    environ[environ_n] = strdupa(environ[environ_n]);
  char **new_environ = alloca((environ_n + 1) * sizeof(char *));
  memcpy(new_environ, environ, (environ_n + 1) * sizeof(char *));
  environ = new_environ;

  if (unmap_all() == -1)
    goto err;

  int fd;
  size_t length;
  Elf64_Ehdr *core =
      mmap_path((void *)(((unsigned long)_end + 4095UL) & -4096UL), core_path,
                &fd, &length);
  if (core == NULL)
    goto err;
  execore_1(core, fd, length, gdb_argv, core_path);
  munmap(core, length);
  close(fd);
err:
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  struct argc_argv aa = {
      .argc = argc,
      .argv = argv,
  };
  arch_switch_stack(execore, &aa, local_stack + sizeof(local_stack));
}
