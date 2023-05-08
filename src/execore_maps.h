#ifndef EXECORE_PROC_H
#define EXECORE_PROC_H

struct mapping {
  unsigned long start;
  unsigned long end;
  unsigned flags : 3;
  unsigned p : 1;
  unsigned long offset;
  unsigned long major;
  unsigned long minor;
  unsigned long inode;
};

int for_each_mapping(const char *path, int (*cb)(struct mapping *, void *),
                     void *arg);

#endif
