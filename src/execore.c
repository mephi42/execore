/* clang-format off */
#include <nolibc.h>
/* clang-format on */
#include "execore_elf.h"
#include "execore_maps.h"
#include "execore_mman.h"
#include "execore_page.h"
#include "execore_procfs.h"
#include "execore_ptrace.h"
#include "execore_stdlib.h"
#include "execore_string.h"
#include "execore_unistd.h"
#include <alloca.h>
#include <elf.h>

static char local_stack[8 * 1024 * 1024];

struct setregset_context {
  pid_t pid;
  const char *path;
  int fd;
  int tid;
  int current_tid;
};

static int setregset_1(struct setregset_context *ctx, void *buf, size_t len,
                       uintptr_t type) {
  struct iovec iov = {.iov_base = buf, .iov_len = len};
  long pt_err = sys_ptrace(PTRACE_SETREGSET, ctx->pid, (void *)type, &iov);
  if (pt_err < 0) {
    fprintf(stderr, "PTRACE_SETREGSET failed: errno=%d\n", (int)-pt_err);
    return -1;
  }
  return 0;
}

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

static int arch_fixup_prstatus(pid_t pid, elf_gregset_t *reg) {
  (void)pid;
  (void)reg;
  return 0;
}

static int arch_setregset(struct setregset_context *ctx, struct note *n) {
  if (strcmp(n->name, "LINUX") == 0 && n->type == NT_X86_XSTATE) {
    char reg[n->desc_sz];
    PREAD_EXACT(ctx->path, ctx->fd, reg, sizeof(reg), n->desc_off, err);
    return setregset_1(ctx, reg, sizeof(reg), n->type);
  }

  return 0;

err:
  return -1;
}

#elif defined(__s390x__)

#define ARCH_EM EM_S390

static __attribute__((noreturn)) void
arch_switch_stack(void __attribute__((noreturn)) (*f)(void *), void *arg,
                  void *stack) {
  stack = (void *)((long)stack & -0x8L);
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

#define PSW_MASK_CC 0x0000300000000000UL
#define PSW_MASK_PM 0x00000F0000000000UL
#define PSW_MASK_64 0x0000000100000000UL
#define PSW_MASK_32 0x0000000080000000UL

static int arch_fixup_prstatus(pid_t pid, elf_gregset_t *reg) {
  elf_gregset_t cur;
  struct iovec iov = {
      .iov_base = &cur,
      .iov_len = sizeof(cur),
  };
  long pt_err = sys_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
  if (pt_err < 0) {
    fprintf(stderr, "PTRACE_GETREGSET failed: errno=%d\n", (int)-pt_err);
    return -1;
  }
  unsigned long user_pswm_bits =
      PSW_MASK_CC | PSW_MASK_PM | PSW_MASK_64 | PSW_MASK_32;
  (*reg)[0] &= user_pswm_bits;
  (*reg)[0] |= (cur[0] & ~user_pswm_bits);
  return 0;
}

static int arch_setregset(struct setregset_context *ctx, struct note *n) {
  (void)ctx;
  (void)n;
  return 0;
}

#elif defined(__powerpc64__)

#define ARCH_EM EM_PPC64

static __attribute__((noreturn)) void
arch_switch_stack(void __attribute__((noreturn)) (*f)(void *), void *arg,
                  void *stack) {
  stack = (void *)((long)stack & -0x10L);
  asm("mr 1,%[stack]\n"
      "mr 3,%[arg]\n"
      "mtctr %[f]\n"
      "bctrl\n"
      :
      : [f] "r"(f), [arg] "r"(arg), [stack] "r"(stack)
      : "3", "ctr");
  __builtin_unreachable();
}

static int arch_is_mappable_addr(void *p) {
  (void)p;
  return 1;
}

static int arch_fixup_prstatus(pid_t pid, elf_gregset_t *reg) {
  (void)pid;
  (void)reg;
  return 0;
}

static int arch_setregset(struct setregset_context *ctx, struct note *n) {
  (void)ctx;
  (void)n;
  return 0;
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

static int setregset(struct note *n, void *arg) {
  struct setregset_context *ctx = arg;

  if (strcmp(n->name, "CORE") == 0 && n->type == NT_PRSTATUS) {
    if (n->desc_sz != (ssize_t)sizeof(struct elf_prstatus)) {
      fprintf(stderr, "%s contains a bad NT_PRSTATUS\n", ctx->path);
      goto err;
    }
    struct elf_prstatus prstatus;
    PREAD_EXACT(ctx->path, ctx->fd, &prstatus, sizeof(prstatus), n->desc_off,
                err);
    ctx->current_tid = prstatus.pr_pid;
    if (ctx->tid == -1)
      ctx->tid = ctx->current_tid;
    if (ctx->tid != ctx->current_tid)
      return 0;
    if (arch_fixup_prstatus(ctx->pid, &prstatus.pr_reg) == -1)
      goto err;
    return setregset_1(ctx, &prstatus.pr_reg, sizeof(prstatus.pr_reg), n->type);
  }

  if (ctx->tid != ctx->current_tid)
    return 0;

  if (strcmp(n->name, "CORE") == 0 && n->type == NT_FPREGSET) {
    if (n->desc_sz != (ssize_t)sizeof(elf_fpregset_t)) {
      fprintf(stderr, "%s contains a bad NT_FPREGSET\n", ctx->path);
      goto err;
    }
    elf_fpregset_t reg;
    PREAD_EXACT(ctx->path, ctx->fd, &reg, sizeof(reg), n->desc_off, err);
    return setregset_1(ctx, &reg, sizeof(reg), n->type);
  }

  return arch_setregset(ctx, n);

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

struct path_fd_sysroot {
  const char *path;
  int fd;
  const char *sysroot;
};

#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)

static int map_nt_file(struct nt_file *f, void *arg) {
  struct path_fd_sysroot *pfs = arg;
  const char *filename = f->filename;
  if (pfs->sysroot != NULL)
    filename = strcata(pfs->sysroot, filename);
  int fd = open(filename, O_RDONLY);
  void *p;
  if (fd == -1) {
    fprintf(stderr,
            "Warning: could not open %s (errno=%d), mapping zeros at %p\n",
            filename, errno, (void *)f->start);
    p = mmap((void *)f->start, f->end - f->start, PROT_RWX,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  } else {
    p = mmap((void *)f->start, f->end - f->start, PROT_RWX,
             MAP_PRIVATE | MAP_FIXED, fd, f->offset);
  }
  if (p == MAP_FAILED) {
    fprintf(stderr, "mmap(%d %s) failed: errno=%d\n", fd, filename, errno);
  }
  if (fd != -1)
    close(fd);
  return p == MAP_FAILED ? -1 : 0;
}

static int map_nt_files_from_note(struct note *n, void *arg) {
  struct path_fd_sysroot *pfs = arg;
  if (n->type == NT_FILE)
    return for_each_nt_file(pfs->path, pfs->fd, n, map_nt_file, arg);
  return 0;
}

static void map_nt_files(const char *path, int fd, const char *sysroot,
                         Elf64_Ehdr *ehdr) {
  struct path_fd_sysroot pfs = {.path = path, .fd = fd, .sysroot = sysroot};
  if (for_each_note(path, fd, ehdr, map_nt_files_from_note, &pfs) == -1)
    exit(EXIT_FAILURE);
}

static int for_each_mappable_phdr(const char *path, int fd, Elf64_Ehdr *ehdr,
                                  int (*cb)(Elf64_Phdr *, void *), void *arg) {
  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf64_Phdr phdr;
    PREAD_EXACT(path, fd, &phdr, sizeof(phdr), ehdr->e_phoff + sizeof(phdr) * i,
                err);
    if (!is_mappable_phdr(&phdr))
      continue;
    if (cb(&phdr, arg) == -1)
      goto err;
  }
  return 0;

err:
  return -1;
}

#define PHDR_PAGE_ADDR(phdr)                                                   \
  ((void *)((phdr)->p_vaddr & (unsigned long)(-PAGE_SIZE)))
#define PHDR_PAGE_SIZE(phdr)                                                   \
  ({                                                                           \
    Elf64_Phdr *__phdr = (phdr);                                               \
    ((__phdr->p_vaddr + __phdr->p_memsz + (unsigned long)(PAGE_SIZE - 1)) &    \
     (unsigned long)(-PAGE_SIZE)) -                                            \
        (__phdr->p_vaddr & (unsigned long)(-PAGE_SIZE));                       \
  })

static int map_phdr(Elf64_Phdr *phdr, void *arg) {
  const char *path = arg;
  void *p = mmap(PHDR_PAGE_ADDR(phdr), PHDR_PAGE_SIZE(phdr), PROT_RWX,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED) {
    fprintf(stderr, "mmap(%s %p, 0x%llx) failed: errno=%d\n", path,
            PHDR_PAGE_ADDR(phdr), PHDR_PAGE_SIZE(phdr), errno);
    return -1;
  }
  return 0;
}

static void map_phdrs(const char *path, int fd, Elf64_Ehdr *ehdr) {
  if (for_each_mappable_phdr(path, fd, ehdr, map_phdr, (void *)path) == -1)
    exit(EXIT_FAILURE);
}

struct path_fd {
  const char *path;
  int fd;
};

static int read_phdr(Elf64_Phdr *phdr, void *arg) {
  struct path_fd *pf = arg;
  PREAD_EXACT(pf->path, pf->fd, (void *)phdr->p_vaddr, phdr->p_filesz,
              phdr->p_offset, err);
  return 0;

err:
  return -1;
}

static void read_phdrs(const char *path, int fd, Elf64_Ehdr *ehdr) {
  struct path_fd pf = {.path = path, .fd = fd};
  if (for_each_mappable_phdr(path, fd, ehdr, read_phdr, &pf) == -1)
    exit(EXIT_FAILURE);
}

static int protect_phdr(Elf64_Phdr *phdr, void *arg) {
  const char *path = arg;
  if (mprotect(PHDR_PAGE_ADDR(phdr), PHDR_PAGE_SIZE(phdr),
               get_prot(phdr->p_flags)) == -1) {
    fprintf(stderr, "mprotect(%s %p, 0x%llx) failed: errno=%d\n", path,
            PHDR_PAGE_ADDR(phdr), PHDR_PAGE_SIZE(phdr), errno);
    return -1;
  }
  return 0;
}

static void protect_phdrs(const char *path, int fd, Elf64_Ehdr *ehdr) {
  if (for_each_mappable_phdr(path, fd, ehdr, protect_phdr, (void *)path) == -1)
    exit(EXIT_FAILURE);
}

#define AT_VECTOR_SIZE 128

struct auxv {
  unsigned long data[AT_VECTOR_SIZE];
  unsigned int size; /* in bytes */
};

struct get_auxv_context {
  const char *path;
  int fd;
  int found;
  struct auxv *auxv;
};

static int get_auxv_from_note(struct note *n, void *arg) {
  struct get_auxv_context *ctx = arg;
  if (n->type == NT_AUXV) {
    if (n->desc_sz > sizeof(ctx->auxv->data)) {
      fprintf(stderr, "Warning: NT_AUXV note in %s is too large\n", ctx->path);
      goto err;
    }
    PREAD_EXACT(ctx->path, ctx->fd, ctx->auxv->data, n->desc_sz, n->desc_off,
                err);
    ctx->auxv->size = n->desc_sz;
    ctx->found = 1;
  }
  return 0;

err:
  return -1;
}

static int get_auxv(const char *path, int fd, Elf64_Ehdr *ehdr,
                    struct auxv *auxv) {
  struct get_auxv_context ctx = {
      .path = path, .fd = fd, .found = 0, .auxv = auxv};
  if (for_each_note(path, fd, ehdr, get_auxv_from_note, &ctx) == -1)
    return -1;
  if (!ctx.found) {
    fprintf(stderr, "Warning: no NT_AUXV note in %s\n", path);
    return -1;
  }
  return 0;
}

static unsigned long get_execfn_addr(const struct auxv *auxv) {
  for (unsigned int i = 0; i < auxv->size / sizeof(unsigned long); i += 2)
    if (auxv->data[i] == AT_EXECFN)
      return auxv->data[i + 1];
  return -1;
}

static void get_proc_mem_path(char *buf, pid_t pid) {
  strcpy(buf, "/proc/");
  buf += strlen(buf);
  utoa_r(pid, buf);
  strcpy(buf + strlen(buf), "/mem");
}

static int ptrace_read_str(pid_t pid, unsigned long addr, char *buf, size_t n) {
  char proc_mem_path[64];
  get_proc_mem_path(proc_mem_path, pid);
  int fd = open(proc_mem_path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "open(%s) failed: errno=%d\n", proc_mem_path, errno);
    goto err;
  }
  size_t i;
  for (i = 0; i < n; i++) {
    PREAD_EXACT(proc_mem_path, fd, buf + i, 1, addr + i, err_close);
    if (buf[i] == 0)
      break;
  }
  close(fd);
  return i == n ? -1 : 0;

err_close:
  close(fd);
err:
  return -1;
}

static void set_auxv(struct auxv *auxv) {
  if (prctl(PR_SET_MM, PR_SET_MM_AUXV, (unsigned long)auxv->data, auxv->size,
            0) < 0)
    fprintf(stderr, "Warning: PR_SET_MM_AUXV failed: errno=%d\n", errno);
}

static void execore_1(const char *core_path, int fd, const char *sysroot,
                      char **gdb_argv, int tid) {
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

  struct auxv auxv;
  int have_auxv = get_auxv(core_path, fd, &ehdr, &auxv) == 0;

  pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "fork() failed: errno=%d\n", errno);
    goto err;
  }
  if (pid == 0) {
    if (unmap_all() == -1)
      exit(EXIT_FAILURE);
    map_phdrs(core_path, fd, &ehdr);
    map_nt_files(core_path, fd, sysroot, &ehdr);
    read_phdrs(core_path, fd, &ehdr);
    protect_phdrs(core_path, fd, &ehdr);
    if (have_auxv)
      set_auxv(&auxv);
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

  char execfn[PATH_MAX];
  if (have_auxv) {
    unsigned long execfn_addr = get_execfn_addr(&auxv);
    if (execfn_addr == (unsigned long)-1) {
      fprintf(stderr, "Warning: no AT_EXECFN auxval in %s\n", core_path);
    } else {
      if (ptrace_read_str(pid, execfn_addr, execfn, sizeof(execfn))) {
        fprintf(stderr, "Warning: could not read AT_EXECFN\n");
      } else {
        gdb_argv[1] = execfn;
        if (sysroot != NULL)
          gdb_argv[1] = strcata(sysroot, gdb_argv[1]);
      }
    }
  }

  struct setregset_context ctx = {
      .pid = pid, .path = core_path, .fd = fd, .tid = tid, .current_tid = -1};
  if (for_each_note(core_path, fd, &ehdr, setregset, &ctx) == -1)
    goto err_kill;

  long pt_err = sys_ptrace(PTRACE_DETACH, pid, 0, (void *)SIGSTOP);
  if (pt_err < 0) {
    fprintf(stderr, "PTRACE_DETACH failed: errno=%d\n", (int)-pt_err);
    goto err_kill;
  }
  char pid_str[32] = "--pid=";
  itoa_r((long)pid, pid_str + strlen(pid_str));
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
  char add_symbol_file[strlen(aa->argv[0]) + 128];
  char *core_path = NULL;
  char *sysroot = NULL;
  int argn = 1;
  int tid = -1;
  while (argn < aa->argc) {
    if (strncmp(aa->argv[argn], "--sysroot=", 10) == 0) {
      sysroot = strdupa(aa->argv[argn] + 10);
      argn++;
    } else if (strncmp(aa->argv[argn], "--tid=", 6) == 0) {
      tid = atoi(aa->argv[argn] + 6);
      argn++;
    } else if (core_path == NULL) {
      core_path = strdupa(aa->argv[argn]);
      argn++;
    } else {
      break;
    }
  }
  if (core_path == NULL) {
    fprintf(
        stderr,
        "Usage: %s [--sysroot=PATH] [--tid=TID] CORE [GDB_ARG [GDB_ARG ...]]\n",
        aa->argv[0]);
    goto err;
  }

  int gdb_argc = 6 + (aa->argc - argn);
  char **gdb_argv = alloca((gdb_argc + 1) * sizeof(char *));
  int gdb_argn = 0;
  gdb_argv[gdb_argn++] = "gdb";
  gdb_argv[gdb_argn++] =
      strdupa(aa->argv[0]); /* execfn, filled by execore_1() */
  gdb_argn++;               /* real pid, filled by execore_1() */
  gdb_argv[gdb_argn++] = "--eval-command=set confirm off";
  /* https://github.com/mephi42/gdb-pounce/blob/v0.0.16/gdb-pounce#L411 */
  gdb_argv[gdb_argn++] = "--eval-command=handle SIGSTOP nostop noprint nopass";
  strcpy(add_symbol_file, "--eval-command=add-symbol-file ");
  char *p = add_symbol_file + strlen(add_symbol_file);
  strcpy(p, aa->argv[0]);
  p += strlen(p);
  strcpy(p, " 0x");
  utoh_r((unsigned long)_execore_start, p + strlen(p));
  gdb_argv[gdb_argn++] = add_symbol_file;
  for (int i = argn; i < aa->argc; i++)
    gdb_argv[gdb_argn++] = strdupa(aa->argv[i]);
  if (gdb_argn != gdb_argc) {
    fprintf(stderr, "Assertion error: gdb_argn != gdb_argc\n");
    goto err;
  }
  gdb_argv[gdb_argn++] = NULL;

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

  execore_1(core_path, fd, sysroot, gdb_argv, tid);

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
