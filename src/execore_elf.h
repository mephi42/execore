#ifndef EXECORE_ELF_H
#define EXECORE_ELF_H

#include <elf.h>

struct note {
  unsigned int type;
  const char *name;
  const char *desc;
  const char *desc_end;
};

int for_each_note(const char *path, int fd, Elf64_Ehdr *ehdr,
                  int (*cb)(struct note *, void *), void *arg);

#endif
