#include "execore_stdlib.h"
#include <nolibc.h>

static unsigned int parse_hex_digit(char c) {
  switch (c) {
  case '0':
    return 0;
  case '1':
    return 1;
  case '2':
    return 2;
  case '3':
    return 3;
  case '4':
    return 4;
  case '5':
    return 5;
  case '6':
    return 6;
  case '7':
    return 7;
  case '8':
    return 8;
  case '9':
    return 9;
  case 'a':
  case 'A':
    return 0xa;
  case 'b':
  case 'B':
    return 0xb;
  case 'c':
  case 'C':
    return 0xc;
  case 'd':
  case 'D':
    return 0xd;
  case 'e':
  case 'E':
    return 0xe;
  case 'f':
  case 'F':
    return 0xf;
  default:
    return -1;
  }
}

unsigned long EXECORE_(strtoul)(const char *nptr, char **endptr, int base) {
  const char *p = nptr;
  unsigned long result = 0;
  while (1) {
    unsigned int digit = parse_hex_digit(*p);
    if (digit >= (unsigned int)base)
      break;
    result = (result * base) + digit;
    p++;
  }
  if (endptr != NULL)
    *endptr = (char *)p;
  return result;
}
