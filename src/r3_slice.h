#ifndef R3_SLICE_H_INCLUDED
#define R3_SLICE_H_INCLUDED
//#include <stdlib.h>
#if 1

#undef gsize
#undef gpointer

#ifndef __GLIBCONFIG_H__
#if (defined (__amd64) || defined(__sparcv9))
typedef unsigned long long gsize;
#else
typedef unsigned int gsize;
#endif
#endif
typedef void* gpointer;

#ifndef g_slice_new
#define g_slice_new(type)  ((type*) g_slice_alloc (sizeof (type)))
#define g_slice_free(type, mem)  g_slice_free1(sizeof (type), (mem))
#endif // g_slice_new

extern gpointer g_slice_alloc (gsize size);
extern gpointer g_slice_alloc0(gsize size);
extern void     g_slice_free1 (gsize size, gpointer data);

//#include <glib/gslice.h>
//#include <glib/gmem.h>
#else
/*! работа с динамической памятью, удобно использовать для списков и деревьев */
extern void  r3_slice_init();
//extern void  r3_slice_test();
extern void* r3_slice_alloc  (unsigned int size);
extern void* r3_slice_alloc0 (unsigned int size);
extern void  r3_slice_free   (unsigned int size, void* data);
void r3_slice_status();

#define r3_slice_new(type)  r3_slice_alloc(sizeof(type))
#define r3_slice_new0(type)  r3_slice_alloc0(sizeof(type))

#undef g_slice_new0
#undef g_slice_free
#define g_slice_new0(type)  \
    (type* ) r3_slice_alloc0(sizeof(type))

#define g_slice_new(type)  \
    (type* ) r3_slice_alloc(sizeof(type))

#define g_slice_alloc(size) r3_slice_alloc(size)
#define g_slice_free1(size, d)  r3_slice_free(size, d)

#define g_slice_free(type, d)  \
    r3_slice_free(sizeof(type), d)

#define g_malloc(s)  __builtin_malloc(s)
#define g_malloc0(s)  ({ void * ptr = __builtin_malloc(s); __builtin_memset(ptr,0,s); ptr; })
#define g_free(s)  __builtin_free(s)
#endif
#endif // R3_SLICE_H_INCLUDED
