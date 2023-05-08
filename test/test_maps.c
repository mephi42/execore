#include "execore_maps.h"
#include "test.h"
#include <linux/mman.h>
#include <stddef.h>

static int push_back_mapping(struct mapping *m, void *arg) {
  size_t *n = (size_t *)arg;
  if (*n == 0) {
    EXPECT_EQ(0xfc000000, m->start);
    EXPECT_EQ(0xfcac0000, m->end);
    EXPECT_EQ(PROT_READ | PROT_WRITE, m->prot);
    EXPECT_TRUE(m->p);
    EXPECT_EQ(0, m->offset);
    EXPECT_EQ(0, m->major);
    EXPECT_EQ(0, m->minor);
    EXPECT_EQ(0, m->inode);
  } else if (*n == 15) {
    EXPECT_EQ(0x5619df78f000, m->start);
    EXPECT_EQ(0x5619df790000, m->end);
    EXPECT_EQ(PROT_READ, m->prot);
    EXPECT_TRUE(m->p);
    EXPECT_EQ(0x1000, m->offset);
    EXPECT_EQ(0, m->major);
    EXPECT_EQ(0x3d, m->minor);
    EXPECT_EQ(5472749, m->inode);
  } else if (*n == 59) {
    EXPECT_EQ(0x7f3640ee4000, m->start);
    EXPECT_EQ(0x7f36413d4000, m->end);
    EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, m->prot);
    EXPECT_TRUE(m->p);
    EXPECT_EQ(0, m->offset);
    EXPECT_EQ(0, m->major);
    EXPECT_EQ(0, m->minor);
    EXPECT_EQ(0, m->inode);
  } else if (*n == 65) {
    EXPECT_EQ(0x7f364fee4000, m->start);
    EXPECT_EQ(0x7f3658000000, m->end);
    EXPECT_EQ(PROT_READ, m->prot);
    EXPECT_FALSE(m->p);
    EXPECT_EQ(0, m->offset);
    EXPECT_EQ(0, m->major);
    EXPECT_EQ(0x3d, m->minor);
    EXPECT_EQ(6179083, m->inode);
  }
  (*n)++;
  return 0;
}

void test_maps(void) {
  size_t n = 0;
  ASSERT_EQ(0, for_each_mapping(CMAKE_SOURCE_DIR "/test/maps.txt",
                                &push_back_mapping, &n));
  ASSERT_EQ(204, n);
}
