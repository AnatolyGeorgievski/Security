#ifndef SEGMENT_H_INCLUDED
#define SEGMENT_H_INCLUDED
/*! механизм статического формирования регистрационных таблиц

    под каждую регистрационную таблицу создается свой сегмент памяти,
    в который на этапе компиляции программы добавляются записи из разных исходных файлов
    помеченные соответсвующим атрибутом.
    При компляции сегменты создаются автоматически, создание или модификация скрипта сборки не требуется.

пример декларации сегмента и ссылок на начало и конец таблицы
    #define R3_ATTR_MODULE  SEGMENT_ATTR(r3_module_table)
    extern R3Module __start__r3_module_table[];
    extern R3Module __stop__r3_module_table[];


*/

#if defined(WIN32) || defined(__linux__)
#define SEGMENT_ATTR(segment)  __attribute__ ((used, aligned(4), section ("_"#segment)))
#else
#define SEGMENT_ATTR(segment)  __attribute__ ((used, section (#segment)))
#endif


#ifndef SEGMENT_START
#ifdef WIN32
#ifdef __x86_64__
# define SEGMENT_START(addr) (void*)(((unsigned long long)(__start__##addr)+0xFFFULL) & ~0xFFFULL)
# define SEGMENT_STOP(addr) (void*)(__stop__##addr)
#else
# define SEGMENT_START(addr) (void*)(((unsigned long)(__start__##addr)+0xFFFULL) & ~0xFFFULL)
# define SEGMENT_STOP(addr) (void*)(__stop__##addr)
#endif
#else
# define SEGMENT_START(addr) (void*)(__start_##addr)
# define SEGMENT_STOP(addr) (void*)(__stop_##addr)
#endif
#endif


#endif // SEGMENT_H_INCLUDED
