#ifndef EXECORE_PAGE_H
#define EXECORE_PAGE_H

#if defined(__x86_64__) || defined (__s390x__)
#define PAGE_SIZE 0x1000
#elif defined(__powerpc64__)
#define PAGE_SIZE 0x10000
#else
#error Unsupported architecture
#endif

#endif
