//#include "r3stdlib.h"
#include "r3_slist.h"
/*! \defgroup _r3_slist Односвязные списки объектов

Представлена реализация списков односвязных совместимая со списками Glib.
В Glib списки двухсвязные.
    \{
*/
/*! \brief добавить элемент в конец списка
    \param list - список
    \param data - данные
    \return начало списка
*/
GSList* g_slist_append(GSList* list, void* data)
{
    GSList * last = g_slice_new(GSList);
    last->data = data, last->next = NULL;
    if (list == NULL) return last;
    GSList * first = list;
    while (list->next != NULL) list = list->next;
    list->next = last;
    return first;
}

/*! \brief удалить элемент из списка

    \param list - поиск производится вниз по списку
    \param data - исключается первое появление таких данных
    \return начало списка
*/
GSList* g_slist_remove(GSList* list, const void* data)
{
    if (!list) return list; // нет элементов в списке
    GSList * first = list;
    if (list->data == data) { // в первом элементе
        first = list->next;
        g_slice_free(GSList, list);
    } else {
        GSList* prev = list;
        while ((list = list->next) != NULL)
        {
            if (list->data == data){
                prev->next = list->next;
                g_slice_free(GSList, list);
                break;
            }
            prev = list;
        }
    }
    return first;
}
/*! \brief освободить место занятое списком

Элементы списка должны освобождаться отдельно
    \param list - список
*/
void   g_slist_free  (GSList *list)
{
    while(list){
        GSList* prev = list;
        list = list->next;
        g_slice_free(GSList, prev);
    }
}
/*! \brief добавить элемент в начало списка

    \param list - начало списка
    \param data - данные для нового элемента списка
    \return начало списка
*/
GSList* g_slist_prepend(GSList* list, void* data)
{
    GSList * last = g_slice_new(GSList);
    last->data = data, last->next = list;
    return last;
}
/*! \brief копирование списка без копирования данных
    \param list исходный список
    \return копия списка
 */
GSList* g_slist_copy (const GSList *list)
{
    if (list==NULL) return NULL;
    GSList* top= g_slice_new(GSList);;
    top->data = list->data;
    GSList * prev = top;
    list = list->next;
    while (list) {
        GSList * item = g_slice_new(GSList);
        item->data = list->data;
        prev->next = item;
        prev = item;
        list = list->next;
    }
    prev->next = NULL;
    return top;
}

/*! удалить один элемент списка */
/*void   g_slist_free_1(GSList *list)
{
    g_slice_free(GSList, list);
}*/
#if 0
/*! \brief добавить элемент в список перед указанным
    \param list - список
    \param sibling - элемент списка перед которым вставляется новый элемент
    \param data - данные
    \return начало списка
*/
GList* g_slist_insert_before(GList * list, GList* sibling, void* data)
{
//    if (!list) return list;
    GList* first = list;
    if (first == sibling || first==NULL){ // перед первым элементом
        first = g_slice_new(GList);
        first->data = data, first->next = sibling;
    } else {
        while (list->next)
        {
            if (list->next == sibling){
                break;
            }
            list = list->next;
        }
        // доехали до конца списка, не нашли, вставим в конец
        list->next = g_slice_new(GList);
        list = list->next;
        list->data = data, list->next = sibling;
    }
    return first;
}
GList* g_slist_insert_after (GList * list, GList* sibling, void* data)
{
    GList * elem = g_slice_new(GList);
    elem->data = data, elem->next= NULL;
    if (sibling == NULL) {
        list = elem;
    } else {
        elem->next = sibling->next;
        sibling->next = elem;
    }
    return list;
}

/*! \brief добавить элемент в список с сортировкой
    \param list - список
    \param data - данные
    \param func - функция сравнения, возвращает >0 если a после b
    \return начало списка
*/
GList* g_slist_insert_sorted (GList *list, void* data, GCompareFunc func)
{
    GList* first = list;
    if (first == NULL || func(list->data, data)>0) {// первым элементом списка
        first = g_slice_new(GList);
        first->data = data, first->next = list;
    } else {
        GList* prev = first;
        list = list->next;
        while (list){
            if (func(list->data, data)>0) break;
            prev = list;
            list = list->next;
        }
        prev->next = g_slice_new(GList);
        prev = prev->next;
        prev->data = data, prev->next = list;
    }
    return first;
}

#endif

/*! \brief последний элемент списка
    \param list - список
    \return последний элемент списка
*/
GSList* g_slist_last(GSList* list)
{
    if (list)// return list;
    while (list->next) list = list->next;
    return list;
}

/*! \brief N-й элемент списка
    \param list - список
    \return последний элемент списка
*/

GSList* g_slist_nth   (GSList* list, unsigned int n)
{
    while (list && n!=0){
        n--;
        list = list->next;
    }
    return list;
}

/*! \brief подсчет элементов в списке
    \param list - список
    \return количество элементов в списке
*/
int g_slist_length(GSList* list)
{
    int count = 0;
    while (list){
        count++;
        list = list->next;
    }
    return count;
}



//! \}
