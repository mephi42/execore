#ifndef TEST_H
#define TEST_H

#include <stdlib.h>

void test_execvpe(void);
void test_maps(void);

extern int test_status;

#define ASSERT_EQ(x, y)                                                        \
  if ((x) != (y))                                                              \
    exit(1);

#define ASSERT_GT(x, y)                                                        \
  if ((x) <= (y))                                                              \
    exit(1);

#define ASSERT_TRUE(x)                                                         \
  if (!(x))                                                                    \
    exit(1);

#define EXPECT_EQ(x, y)                                                        \
  if ((x) != (y))                                                              \
    test_status = 1;

#define EXPECT_FALSE(x)                                                        \
  if (x)                                                                       \
    test_status = 1;

#define EXPECT_TRUE(x)                                                         \
  if (!(x))                                                                    \
    test_status = 1;

#endif
