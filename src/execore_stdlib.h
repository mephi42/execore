#ifndef EXECORE_STDLIB_H
#define EXECORE_STDLIB_H

#include "execore.h"

#define __WIFSTOPPED(status) (((status)&0xff) == 0x7f)
#define WIFSTOPPED(status) __WIFSTOPPED(status)

unsigned long EXECORE_(strtoul)(const char *nptr, char **endptr, int base);

#endif
