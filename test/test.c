#include "test.h"

int test_status = 0;

int main(void) {
  test_execvpe();
  test_maps();
  return test_status;
}
