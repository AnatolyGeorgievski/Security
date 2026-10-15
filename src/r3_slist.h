#if !defined (R3_SLIST_H_INCLUDED) && !defined(__G_SLIST_H__)
#define R3_SLIST_H_INCLUDED
#define __G_SLIST_H__
#include <stdlib.h> // NULL
#include "r3_slice.h"
typedef struct _GSList GSList;
struct _GSList {
    void* data;
    GSList* next;
};

void   g_slist_free  (GSList *list);
static inline void   g_slist_free_1(GSList *list) { g_slice_free(GSList, list); }
int    g_slist_length(GSList* list);
/*
GList* g_list_last  (GList* list);
GList* g_list_nth   (GList* list, unsigned int n);
GList* g_list_insert_before(GList * list, GList* sibling, void* data);
GList* g_list_insert_after (GList * list, GList* sibling, void* data);
GList* g_list_remove (GList* list, void* data);
*/
GSList* g_slist_append (GSList* list, void* data);
GSList* g_slist_prepend(GSList* list, void* data);
GSList* g_slist_copy   (const GSList *list);
#if 0
static inline GSList* g_slist_prepend(GSList* list, void* data)
{
    GSList * last = g_slice_new(GSList);
    last->data = data, last->next = list;
    return last;
}
#endif

/*
typedef void* gpointer;
typedef const void *gconstpointer;
typedef int            (*GCompareFunc)         (gconstpointer  a,
                                                 gconstpointer  b);

//typedef int   (*GCompareFunc)(const void* a, const void* b);
GList* g_list_insert_sorted (GList *list,void* data, GCompareFunc func);
*/
#endif // R3_LIST_H_INCLUDED
