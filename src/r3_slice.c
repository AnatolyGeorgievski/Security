/*!	\file r3_slice.c
	Copyright (C) 2011-2022 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>

    \defgroup _r3_slice Слайсы - механизм распределения памяти
	\ingroup _mem

    \brief реализация метода распределения памяти - слайсами - блоками фиксированного размера

    Механизм позволяет организовать эффективное хранение и сбор мусора для объектов
    одинакового размера, над которыми требуется частое выполнение операций выделения
    и освобождения памяти.
    Наиболее эффективно оказывается использовать механизм слайсов для динамического
    выделения памяти для хранения элементов очередей, списков и деревьев.

    Механизм эффективен для хранения множества объектов небольшого размера. Накладные расходы
    для работы механизма сбора мусора один бит на один слайс памяти.

    Каждый типоразмер слайсов выделяется из своего пула. Если пул заканчивается,
    автоматически выделяется дополнительная память для выделения новых слайсов.

    \date 3.03.2011 Совместимость с x86_64 размер пула увеличивается с 32 на 64 элемента
    для i386, ARM размер пула остается 32 элемента

    \date 8.04.2014 Для Windows выделяет слайсы размером больше чем SLICE_POOL_NUM
    с выравниванием на 16 (SLICE_BLOCK_ALIGN)

    \date 25.01.2015 Надо реализовать блокировку одновременного доступа для выделения
    и освобождения памяти.

    \date 26.01.2015 Реализовал три очереди: полные, неполные и пустые блоки.
    Очередь "неполные" (open) используется как наиболее вероятный список для поиска карты памяти
    при освобождении элемента (слайса). Стек "пустые" используется для ускорения выделения памяти,
    эту память можно высвобождать.

	\date 16.09.2022 Сборка под pthread. Для локального тестирования
    \{
*/
#ifndef __MSVCRT_VERSION__
#define __MSVCRT_VERSION__ 0x0700 // для выявления функций _aligned_malloc и _aligned_free
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
//#include <glib.h>
//#include "atomic.h"
#include "r3_slist.h"
#include "r3_slice.h"
#define SLICE_DEBUG 1
// хранить пустые блоки для последующего использования
#define SLICE_FREE 0

#ifndef G_LOCK
#define G_LOCK(x) 	pthread_mutex_lock(&(x))
#define G_UNLOCK(x) 	pthread_mutex_unlock(&(x))
#define G_LOCK_DEFINE(x) pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifdef _WIN32
#include <malloc.h>
static inline int mem_alloc_aligned(void **memptr, size_t alignment, size_t size)
{
    *memptr = (void*)_aligned_malloc(size, alignment);
    return 0;
}
static inline void mem_free_aligned(void *memptr)//, size_t alignment, size_t size)
{
    _aligned_free(memptr);
}
#endif

static inline
int bitn_mask_idx(unsigned int size)
{
#if ((__GNUC__ >= 4) || defined(__i386__) || defined(__arm__))
    return 8*sizeof(int)-__builtin_clz((size-1)>>2);
#else
    int bitn = 0;
    size = (size-1) >> 1;
    while (size>>=1) bitn++;
    return bitn;
#endif
}

/*! \brief поиск незанятого объекта в пуле 32/64 элемента

    Оперция оптимизирована для работы на ARM
    Возможна реализация для переносимости на базе функции ffs()
 */
static inline
int bitn_first_zero(unsigned long word)
{
#if ((__GNUC__ >= 4) || defined(__i386__) || defined(__arm__))
    return __builtin_ctzl(~word);
#else
    int bitn = 0;
    int shift = 4*sizeof(long);
    unsigned long mask = ~0UL; // для m64 long = 64 bits
    do{
        mask>>= shift;
        if((word & mask) == mask) {
            word >>= shift;
            bitn += shift;
        }
    } while (shift >>= 1);
    return bitn;
#endif
}

#define SLICE_POOL_NUM 8
// минимальное выравнивание на должно быть на sizeof(void*)
#define SLICE_BLOCK_ALIGN 16
#define SLICE_SIZE(idx)         (  1<<(idx+2))
#define SLICE_BLOCK_SIZE(idx)   ((sizeof(long)*32)<<idx)
#define SLICE_OFFSET(pool_idx, idx)       (idx<<(pool_idx+2))
typedef struct _SlicePool SlicePool;
struct _SlicePool {
    void* open_maps;//!< список неполных мапов
#if (SLICE_FREE!=0)
    void* free_maps;//!< список пустых карт
#endif
    void* maps;
//    void* last_map;//!< последняя карта на которой освобождалась память
};
typedef struct _SliceMap SliceMap;
struct _SliceMap {
//    SliceMap* prev;     // цепочка мапов
    SliceMap* next;     // цепочка мапов
    unsigned char* data;//[0] __attribute__((__aligned__(SLICE_BLOCK_ALIGN)));
    unsigned long bits;
};

static int loop_count =0;
static int obj_count =0;
//static int hit_last_count =0;
static int hit_open_count =0;
static int max_open_count =0;
static SlicePool slice_pools[SLICE_POOL_NUM] = {{NULL}};// =NULL;//
G_LOCK_DEFINE(slice_lock);

/*! \brief Выделение слайса памяти размером size
    \param [in] size - размер слайса в байтах. Размер округляется до
    ближайшего числа 2^n.
    \return ссылку на блок памяти
*/
gpointer g_slice_alloc(gsize size)
{
    // каким количеством бит описывается размер
    int pool_idx = bitn_mask_idx(size);
    if (pool_idx >=  SLICE_POOL_NUM) {
        void * ptr;
        mem_alloc_aligned(&ptr, SLICE_BLOCK_ALIGN,size);
        return ptr;
    }
    if(SLICE_DEBUG) obj_count++;
    // должно быть не менее 4 байт 2**2 и не более 512 2**9, с большими мы не работаем
    SlicePool* pool = &slice_pools[pool_idx];
G_LOCK(slice_lock);

    SliceMap * map = pool->open_maps;

    if (map == NULL) { // все заполнены, создать новую
#if (SLICE_FREE!=0)
        if (pool->free_maps) {
            map = pool->free_maps;
            pool->free_maps = map->next;
        } else
#endif
        {
            mem_alloc_aligned((void**)&map, __alignof__(void*), sizeof(SliceMap));
            mem_alloc_aligned((void**)&map->data, SLICE_BLOCK_ALIGN, SLICE_BLOCK_SIZE(pool_idx));
            if (map==NULL) {
                puts("fatal error: SLICE can't allocate memory block");
            }
        }
        //map->next_open = NULL;
        map->bits = 1; // все свободны, выделим первый блок

        map->next = pool->open_maps;
        pool->open_maps = map; // \todo атомарно добавить в список частично пустых
        G_UNLOCK(slice_lock);
        return &map->data[0];
    }
    int slice_idx = bitn_first_zero(map->bits);
    map->bits |= (1UL<<slice_idx);// атомарно установить бит, иначе повтор операции или возврат в начлао!

    if (map->bits == ~0UL) {// полностью заполнен
        //if (map->next) map->next->prev = NULL;
        pool->open_maps = map->next; // выталкиваем из стека открытых
        //map->prev = NULL;
        map->next = pool->maps;// перекладываем в стек полных
        //if(map->next) map->next->prev = map;
        pool->maps = map;

    }
    G_UNLOCK(slice_lock);
    return &map->data[SLICE_OFFSET(pool_idx, slice_idx)];

}
/*! \brief Выделение слайса памяти размером size
    \param [in] size - размер слайса в байтах. Размер округляется до
    ближайшего числа 2^n.
    \return ссылку на блок памяти. Блок памяти заполнятеся нулями.
*/
gpointer g_slice_alloc0 (gsize size)
{
    void* data = g_slice_alloc(size);
    if(data) __builtin_bzero(data, size);
    return data;
}
/*! \brief Освобождает блок памяти выделенный в качестве слайса
    \param [in] size - размер слайса в байтах. Размер используется для
    поиска пула, из которого выделен слайс.
    \param [in] data - ссылка на слайс.
*/
void g_slice_free1(gsize size, gpointer data)
{
    int pool_idx = bitn_mask_idx(size);
    if (pool_idx >= SLICE_POOL_NUM) {
        mem_free_aligned(data);
        return;
    }
//    int block_size = SLICE_BLOCK_SIZE(pool_idx);
    SlicePool* pool = &slice_pools[pool_idx];
G_LOCK(slice_lock);

    unsigned int block_size = SLICE_BLOCK_SIZE(pool_idx);
    SliceMap*  map = NULL; // неполные

if ((map = pool->open_maps)!=NULL){
    SliceMap* map_prev = NULL;
    while (map) {
        if (map->data<=(unsigned char*)data && (unsigned char*)data < map->data+block_size) break;
        map_prev = map;
        map = map->next;
        if(SLICE_DEBUG)loop_count++;
    }
    if (map!=NULL){
        if(SLICE_DEBUG)hit_open_count++;
        unsigned int slice_idx = ((unsigned char*)data - &map->data[0])>>(pool_idx+2);
        if (!(map->bits & (1UL<<slice_idx))) {// повторная очистка памяти
            printf("!!! try to free data !!!\n");
            _Exit(1);
        }
        map->bits &= ~(1UL<<slice_idx);
        if (map->bits == 0) { // переместить из открытых в пустые
            if(map_prev) map_prev->next = map->next;
            else pool->open_maps = map->next;
            //if(map->next) map->next->prev = map->prev;
#if (defined(SLICE_FREE) && SLICE_FREE!=0)
            //map->prev=NULL;
            map->next = pool->free_maps;
            pool->free_maps = map;
#else
            mem_free_aligned(map->data);
            mem_free_aligned(map);
#endif
        }
        G_UNLOCK(slice_lock);
        return;
    }
}
if (map == NULL)
{
    map = pool->maps; // полные
    SliceMap* map_prev = NULL;
    while (map){
        if (map->data<=(unsigned char*)data && (unsigned char*)data < map->data+block_size) break;
        map_prev = map;
        map = map->next;
        if (SLICE_DEBUG) loop_count++; //пустые не считаем
    }
    if (map == NULL) {
        printf("!!! no free map for slice allocation data !!!\n");//, data);
        _Exit(1);
    } else
    {// нашли нужную карту памяти
        if (map->bits == ~0UL)
        {// переместить из полных, в неполные
            if (map_prev) map_prev->next = map->next;
            else pool->maps = map->next;
            //if (map->next) map->next->prev = map->prev;
            //map->prev = NULL;
            map->next = pool->open_maps;
            //if (map->next) map->next->prev = map;
            pool->open_maps = map;
        }
    }
    unsigned int slice_idx = ((unsigned char*)data - &map->data[0])>>(pool_idx+2);
    if (!(map->bits & (1UL<<slice_idx))) {// повторная очистка памяти
        printf("!!! try to free data !!!\n");
        _Exit(1);
    }
    map->bits &= ~(1UL<<slice_idx);
}
    G_UNLOCK(slice_lock);
}
#if 0
/*! \brief функция-конструктор выполняется до входа в main()
 */
static void __attribute__((constructor)) g_slice_init()
{
    const gsize size = sizeof(SlicePool)*SLICE_POOL_NUM;
    slice_pools = malloc(size);
    memset(slice_pools, 0, size);
}
#endif
//! \}

//static
int g_slice_test(unsigned char * buffer, int*length)
{
    int i;
    printf("slice test [%d / %d]:\nhits: open %d, max %d\n",loop_count, obj_count, hit_open_count, max_open_count);
    for (i=0; i<SLICE_POOL_NUM; i++)
    {
        SlicePool* pool = &slice_pools[i];
        if (pool->maps!=NULL || pool->open_maps!=NULL)
        {
            int count = 0, bits=0;
            SliceMap* map = pool->maps;
            printf( "%02d:\t", i);
            while (map){
                #ifdef DEBUG_SLICE
                printf("%0*lX ", (int)sizeof(long),map->bits);
                #endif // DEBUG_SLICE
                bits += __builtin_popcountl(map->bits);
                count++;
                map = map->next;
            }
            map = pool->open_maps;
            while (map){
                bits += __builtin_popcountl(map->bits);
                count++;
                map = map->next;
            }
#if (SLICE_FREE!=0)
            map = pool->free_maps;
            while (map){
                bits += __builtin_popcountl(map->bits);
                count++;
                map = map->next;
            }
#endif
            printf("blocks=%d (%d)\r\n", count, bits);
        }
    }
    return 0;
}

void __attribute__((destructor)) g_slice_status() {
    g_slice_test(NULL, NULL);
}
/*
#include "r3v2protocol.h"
R3CMD(R3_SNMP_SLICE_TEST, r3_slice_test);
*/

