#ifndef EXECORE_UNISTD_H
#define EXECORE_UNISTD_H

#include "execore.h"

int EXECORE_(execvpe)(const char *file, char *const argv[], char *const envp[]);

#endif
