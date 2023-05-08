/* clang-format off */
#include <nolibc.h>
/* clang-format on */
#include "execore_elf.h"
#include "execore_maps.h"
#include "execore_mman.h"
#include "execore_procfs.h"
#include "execore_ptrace.h"
#include "execore_stdlib.h"
#include "execore_string.h"
#include "execore_unistd.h"
#include <alloca.h>
#include <elf.h>

static char local_stack[8 * 1024 * 1024];

#if defined(__x86_64__)

#define ARCH_EM EM_X86_64

static __attribute__((noreturn)) void
arch_switch_stack(void __attribute__((noreturn)) (*f)(void *), void *arg,
                  void *stack) {
  stack = (void *)((long)stack & -0x10L) - 8;
  asm("mov %[stack],%%rsp\n"
      "mov %[arg],%%rdi\n"
      "jmp *%[f]\n"
      :
      : [f] "r"(f), [arg] "r"(arg), [stack] "r"(stack)
      : "rdi", "memory");
  __builtin_unreachable();
}

static int arch_is_mappable_addr(void *p) {
  /* [vsyscall] */
  return (unsigned long)p != 0xffffffffff600000;
}

#elif defined(__s390x__)

#define ARCH_EM EM_S390

static __attribute__((noreturn)) void
arch_switch_stack(void __attribute__((noreturn)) (*f)(void *), void *arg,
                  void *stack) {
  asm("lgr %%r15,%[stack]\n"
      "lgr %%r2,%[arg]\n"
      "br %[f]\n"
      :
      : [f] "a"(f), [arg] "r"(arg), [stack] "r"(stack)
      : "r2", "memory");
  __builtin_unreachable();
}

static int arch_is_mappable_addr(void *p) {
  (void)p;
  return 1;
}

#else
#error Unsupported architecture
#endif

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

struct pid_path_fd {
  pid_t pid;
  const char *path;
  int fd;
};

static int setregset(struct note *n, void *arg) {
  struct pid_path_fd *ppf = arg;

  if (strcmp(n->name, "CORE") == 0 && n->type == NT_PRSTATUS) {
    if (n->desc_sz != (ssize_t)sizeof(struct elf_prstatus)) {
      fprintf(stderr, "%s contains a bad NT_PRSTATUS\n", ppf->path);
      goto err;
    }
    elf_gregset_t reg;
    PREAD_EXACT(ppf->path, ppf->fd, &reg, sizeof(reg),
                n->desc_off + offsetof(struct elf_prstatus, pr_reg), err);
    struct iovec iov = {
        .iov_base = &reg,
        .iov_len = sizeof(reg),
    };
    long pt_err =
        sys_ptrace(PTRACE_SETREGSET, ppf->pid, (void *)NT_PRSTATUS, &iov);
    if (pt_err < 0) {
      fprintf(stderr, "PTRACE_SETREGSET failed: errno=%d\n", (int)-pt_err);
      goto err;
    }
  }
  return 0;

err:
  return -1;
}

extern const char _execore_start[];
extern const char _execore_end[];

static int unmap_1(struct mapping *m, void *arg) {
  (void)arg;
  int is_self = m->start < (unsigned long)_execore_end &&
                (unsigned long)_execore_start < m->end;
  if (!is_self && arch_is_mappable_addr((void *)m->start)) {
    if (munmap((void *)m->start, m->end - m->start) == -1) {
      fprintf(stderr, "munmap(%p) failed: errno=%d\n", (void *)m->start, errno);
      return -1;
    }
  }
  return 0;
}

static int unmap_all(void) {
  return for_each_mapping("/proc/self/maps", &unmap_1, NULL);
}

static int map_nt_file(struct nt_file *f, void *arg) {
  (void)arg;
  int fd = open(f->filename, O_RDONLY);
  void *p;
  if (fd == -1) {
    p = mmap((void *)f->start, f->end - f->start,
             PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  } else {
    p = mmap((void *)f->start, f->end - f->start,
             PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd,
             f->offset);
  }
  if (p == MAP_FAILED) {
    fprintf(stderr, "mmap(%d %s) failed: errno=%d\n", fd, f->filename, errno);
  }
  if (fd != -1)
    close(fd);
  return p == MAP_FAILED ? -1 : 0;
}

struct path_fd {
  const char *path;
  int fd;
};

static int map_nt_files_from_note(struct note *n, void *arg) {
  struct path_fd *pf = arg;
  if (n->type == NT_FILE)
    return for_each_nt_file(pf->path, pf->fd, n, map_nt_file, arg);
  return 0;
}

static void map_nt_files(const char *path, int fd, Elf64_Ehdr *ehdr) {
  struct path_fd pf = {.path = path, .fd = fd};
  if (for_each_note(path, fd, ehdr, map_nt_files_from_note, &pf) == -1)
    exit(EXIT_FAILURE);
}

static void map_phdrs(const char *path, int fd, Elf64_Ehdr *ehdr) {
  int i = 0;
  for (; i < ehdr->e_phnum; i++) {
    Elf64_Phdr phdr;
    PREAD_EXACT(path, fd, &phdr, sizeof(phdr), ehdr->e_phoff + sizeof(phdr) * i,
                err);
    if (!is_mappable_phdr(&phdr))
      continue;
    void *p = mmap((void *)phdr.p_vaddr, phdr.p_memsz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
      fprintf(stderr, "mmap(%s Phdr[%d]=%p, 0x%lx) failed: errno=%d\n", path, i,
              (void *)phdr.p_vaddr, (long)phdr.p_memsz, errno);
      goto err;
    }
    PREAD_EXACT(path, fd, (void *)phdr.p_vaddr, phdr.p_filesz, phdr.p_offset,
                err);
    if (mprotect((void *)phdr.p_vaddr, phdr.p_memsz, get_prot(phdr.p_flags)) ==
        -1) {
      fprintf(stderr, "mprotect(%s Phdr[%d]=%p, 0x%lx) failed: errno=%d\n",
              path, i, (void *)phdr.p_vaddr, (long)phdr.p_memsz, errno);
      goto err;
    }
  }
  return;

err:
  exit(EXIT_FAILURE);
}

static void execore_1(int fd, char **gdb_argv, const char *core_path) {
  Elf64_Ehdr ehdr;
  PREAD_EXACT(core_path, fd, &ehdr, sizeof(ehdr), 0, err);
  if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
    fprintf(stderr, "%s is not an ELF file\n", core_path);
    goto err;
  }
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "%s is not a 64-bit ELF file\n", core_path);
    goto err;
  }
  if (ehdr.e_type != ET_CORE) {
    fprintf(stderr, "%s is not a core file\n", core_path);
    goto err;
  }
  if (ehdr.e_machine != ARCH_EM) {
    fprintf(stderr, "%s is for a different machine\n", core_path);
    goto err;
  }

  pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "fork() failed: errno=%d\n", errno);
    goto err;
  }
  if (pid == 0) {
    if (unmap_all() == -1)
      exit(EXIT_FAILURE);
    map_nt_files(core_path, fd, &ehdr);
    map_phdrs(core_path, fd, &ehdr);
    close(fd);
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    exit(EXIT_FAILURE);
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

  struct pid_path_fd ppf = {.pid = pid, .path = core_path, .fd = fd};
  if (for_each_note(core_path, fd, &ehdr, setregset, &ppf) == -1)
    goto err_kill;

  long pt_err = sys_ptrace(PTRACE_DETACH, pid, 0, (void *)SIGSTOP);
  if (pt_err < 0) {
    fprintf(stderr, "PTRACE_DETACH failed: errno=%d\n", (int)-pt_err);
    goto err_kill;
  }
  char pid_str[32];
  itoa_r((long)pid, pid_str);
  gdb_argv[2] = pid_str;
  if (EXECORE_(execvpe)(gdb_argv[0], gdb_argv, environ) == -1) {
    fprintf(stderr, "execvpe() failed: errno=%d\n", errno);
    goto err_kill;
  }

err_kill:
  kill(pid, SIGKILL);
err:
  return;
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

  char **gdb_argv = alloca((aa->argc + 4) * sizeof(char *));
  gdb_argv[0] = "gdb";
  gdb_argv[1] = "-p";
  /* https://github.com/mephi42/gdb-pounce/blob/v0.0.16/gdb-pounce#L411 */
  gdb_argv[3] = "-ex";
  gdb_argv[4] = "handle SIGSTOP nostop noprint nopass";
  for (int i = 2; i < aa->argc; i++)
    gdb_argv[i + 3] = strdupa(aa->argv[i]);
  gdb_argv[aa->argc + 3] = NULL;

  size_t environ_n;
  for (environ_n = 0; environ[environ_n]; environ_n++)
    environ[environ_n] = strdupa(environ[environ_n]);
  char **new_environ = alloca((environ_n + 1) * sizeof(char *));
  memcpy(new_environ, environ, (environ_n + 1) * sizeof(char *));
  environ = new_environ;

  int fd = open(core_path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open(%s) failed: errno=%d\n", core_path, errno);
    goto err;
  }

  execore_1(fd, gdb_argv, core_path);

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
