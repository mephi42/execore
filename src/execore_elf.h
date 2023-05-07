#ifndef EXECORE_ELF_H
#define EXECORE_ELF_H

#include <elf.h>

struct note {
  unsigned int type;
  const char *name;
  off_t desc_off;
  unsigned int desc_sz;
};

int for_each_note(const char *path, int fd, Elf64_Ehdr *ehdr,
                  int (*cb)(struct note *, void *), void *arg);

struct nt_file {
  unsigned long start;
  unsigned long end;
  unsigned long offset;
  const char *filename;
};

int for_each_nt_file(const char *path, int fd, struct note *n,
                     int (*cb)(struct nt_file *, void *), void *arg);

#endif
