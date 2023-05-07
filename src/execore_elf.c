/* clang-format off */
#include <nolibc.h>
/* clang-format on */
#include "execore_elf.h"
#include "execore_unistd.h"
#include <alloca.h>

static off_t for_each_note_1(const char *path, int fd, off_t off,
                             int (*cb)(struct note *, void *), void *arg) {
  unsigned int note_hdr[3];
  PREAD_EXACT(path, fd, note_hdr, sizeof(note_hdr), off, err);
  off_t name_off = off + sizeof(note_hdr);
  unsigned long name_sz = note_hdr[0];
  off_t desc_off = name_off + ((name_sz + 3) & -4);
  unsigned long desc_sz = note_hdr[1];
  off_t next_off = desc_off + ((desc_sz + 3) & -4);
  if (name_off <= off || desc_off < name_off || next_off < desc_off) {
    fprintf(stderr, "%s contains a bad namesz or descsz\n", path);
    goto err;
  }

  char *name = alloca(name_sz);
  PREAD_EXACT(path, fd, name, name_sz, name_off, err);
  char *desc = alloca(desc_sz);
  PREAD_EXACT(path, fd, desc, desc_sz, desc_off, err);
  struct note note = {
      .type = note_hdr[2],
      .name = name,
      .desc = desc,
      .desc_end = desc + desc_sz,
  };
  return cb(&note, arg);

err:
  return -1;
}

int for_each_note(const char *path, int fd, Elf64_Ehdr *ehdr,
                  int (*cb)(struct note *, void *), void *arg) {
  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf64_Phdr phdr;
    PREAD_EXACT(path, fd, &phdr, sizeof(phdr), ehdr->e_phoff + sizeof(phdr) * i,
                err);
    if (phdr.p_type == PT_NOTE) {
      off_t off = phdr.p_offset;
      off_t end = off + phdr.p_filesz;
      if (off > end) {
        fprintf(stderr, "%s contains a bad p_offset or p_filesz\n", path);
        goto err;
      }
      while (off != end) {
        off = for_each_note_1(path, fd, off, cb, arg);
        if (off == -1)
          goto err;
      }
      return 0;
    }
  }

err:
  return -1;
}
