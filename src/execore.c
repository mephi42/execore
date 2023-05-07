#include "execore_maps.h"
#include "execore_mman.h"
#include "execore_procfs.h"
#include "execore_ptrace.h"
#include "execore_stdlib.h"
#include "execore_string.h"
#include "execore_unistd.h"
#include <alloca.h>
#include <elf.h>
#include <nolibc.h>

static char local_stack[8 * 1024 * 1024];

#if defined(__x86_64__)

#define ARCH_EM EM_X86_64

static __attribute__((noreturn)) void
arch_switch_stack(void __attribute__((noreturn)) (*f)(void *), void *arg,
                  void *stack) {
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

ssize_t sys_pread64(int fd, void *buf, size_t count, off_t offset) {
  return my_syscall4(__NR_pread64, fd, buf, count, offset);
}

static int pread64_exact(int fd, void *buf, size_t count, off_t offset) {
  while (count != 0) {
    ssize_t n_read = sys_pread64(fd, buf, count, offset);
    if (n_read < 0) {
      errno = -n_read;
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
  return 0;
}

#define PREAD64_EXACT(fd, buf, count, offset, label)                           \
  do {                                                                         \
    if (pread64_exact(fd, buf, count, offset) == -1) {                         \
      fprintf(stderr, "Could not read from %s: errno=%d\n", core_path, errno); \
      goto label;                                                              \
    }                                                                          \
  } while (0)

static int setregset_1(pid_t pid, int fd, unsigned int type, off_t name_off,
                       unsigned int name_sz, off_t desc_off,
                       unsigned int desc_sz, const char *core_path) {
  char *name = alloca(name_sz);
  PREAD64_EXACT(fd, name, name_sz, name_off, err);
  char *desc = alloca(desc_sz);
  PREAD64_EXACT(fd, desc, desc_sz, desc_off, err);
  return arch_setregset(pid, name, type, desc, desc + desc_sz, core_path);

err:
  return -1;
}

static int setregset(pid_t pid, int fd, Elf64_Phdr *phdr,
                     const char *core_path) {
  off_t off = phdr->p_offset;
  off_t end = off + phdr->p_filesz;
  if (off > end) {
    fprintf(stderr, "%s contains a bad p_offset or p_filesz\n", core_path);
    goto err;
  }
  while (off != end) {
    unsigned int note[3];
    PREAD64_EXACT(fd, note, sizeof(note), off, err);
    off_t name_off = off + sizeof(note);
    off_t desc_off = name_off + ((note[0] + 3) & -4);
    off_t next_off = desc_off + ((note[1] + 3) & -4);
    if (name_off <= off || desc_off < name_off || next_off < desc_off) {
      fprintf(stderr, "%s contains a bad namesz or descsz\n", core_path);
      goto err;
    }
    if (setregset_1(pid, fd, note[2], name_off, note[0], desc_off, note[1],
                    core_path) == -1)
      goto err;
    off = next_off;
  }
  return 0;

err:
  return -1;
}

static void unmap_phdrs(int fd, Elf64_Ehdr *ehdr, int n,
                        const char *core_path) {
  for (int i = 0; i < n; i++) {
    Elf64_Phdr phdr;
    PREAD64_EXACT(fd, &phdr, sizeof(phdr), ehdr->e_phoff + sizeof(phdr) * i,
                  err);
    if (is_mappable_phdr(&phdr))
      munmap((void *)phdr.p_vaddr, phdr.p_memsz);
  }
err:
  return;
}

static int map_phdrs(int fd, Elf64_Ehdr *ehdr, const char *core_path) {
  int i = 0;
  for (; i < ehdr->e_phnum; i++) {
    Elf64_Phdr phdr;
    PREAD64_EXACT(fd, &phdr, sizeof(phdr), ehdr->e_phoff + sizeof(phdr) * i,
                  err);
    if (!is_mappable_phdr(&phdr))
      continue;
    void *p = mmap((void *)phdr.p_vaddr, phdr.p_memsz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
      fprintf(stderr, "mmap(%s Phdr[%d]=%p, 0x%lx) failed: errno=%d\n",
              core_path, i, (void *)phdr.p_vaddr, (long)phdr.p_memsz, errno);
      goto err;
    }
    PREAD64_EXACT(fd, (void *)phdr.p_vaddr, phdr.p_filesz, phdr.p_offset, err);
    if (mprotect((void *)phdr.p_vaddr, phdr.p_memsz, get_prot(phdr.p_flags)) ==
        -1) {
      fprintf(stderr, "mprotect(%s Phdr[%d]=%p, 0x%lx) failed: errno=%d\n",
              core_path, i, (void *)phdr.p_vaddr, (long)phdr.p_memsz, errno);
      goto err;
    }
  }
  return 0;

err:
  unmap_phdrs(fd, ehdr, i, core_path);
  return -1;
}

static void execore_1(int fd, char **gdb_argv, const char *core_path) {
  Elf64_Ehdr ehdr;
  PREAD64_EXACT(fd, &ehdr, sizeof(ehdr), 0, err);
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
    if (map_phdrs(fd, &ehdr, core_path) == -1)
      abort();
    close(fd);
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
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr phdr;
    PREAD64_EXACT(fd, &phdr, sizeof(phdr), ehdr.e_phoff + sizeof(phdr) * i,
                  err_kill);
    if (phdr.p_type == PT_NOTE && setregset(pid, fd, &phdr, core_path) == -1)
      goto err_kill;
  }

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
  return for_each_mapping("/proc/self/maps", &unmap_1, &self);
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

  if (unmap_all() == -1)
    goto err;

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
