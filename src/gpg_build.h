#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#define _aligned_malloc(size, align) memalign((align), (size))
#define _aligned_free(ptr) free(ptr)
