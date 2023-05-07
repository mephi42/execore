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
  struct note note = {
      .type = note_hdr[2],
      .name = name,
      .desc_off = desc_off,
      .desc_sz = desc_sz,
  };
  if (cb(&note, arg) == -1)
    goto err;
  return next_off;

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

int for_each_nt_file(const char *path, int fd, struct note *n,
                     int (*cb)(struct nt_file *, void *), void *arg) {
  unsigned long hdr[2];
  PREAD_EXACT(path, fd, hdr, sizeof(hdr), n->desc_off, err);
  unsigned long count = hdr[0];
  unsigned long page_size = hdr[1];
  off_t file_off = n->desc_off + sizeof(hdr);
  off_t filename_off = file_off + sizeof(unsigned long) * 3 * count;
  for (unsigned long i = 0; i < count; i++) {
    unsigned long file[3];
    PREAD_EXACT(path, fd, file, sizeof(file), file_off, err);
    char filename[PATH_MAX + 1];
    size_t pread_count = n->desc_sz - (filename_off - n->desc_off);
    if (pread_count > sizeof(filename))
      pread_count = sizeof(filename);
    PREAD_EXACT(path, fd, filename, pread_count, filename_off, err);
    size_t filename_len = strnlen(filename, pread_count - 1);
    if (filename[filename_len] != 0) {
      fprintf(stderr,
              "%s contains NT_FILE with a file name which is too long\n", path);
      goto err;
    }
    struct nt_file f = {
        .start = file[0],
        .end = file[1],
        .offset = file[2] * page_size,
        .filename = filename,
    };
    if (cb(&f, arg) == -1)
      goto err;
    file_off += sizeof(unsigned long) * 3;
    filename_off += filename_len + 1;
  }
  return 0;

err:
  return -1;
}
