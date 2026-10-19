#ifndef TTL_FILTER_H
#define TTL_FILTER_H
#include <stdatomic.h>
#include <stdint.h>

enum { TTL_CAP = 256 };
enum { TTL_MISS = 0, TTL_HIT = 1, TTL_NEW = 2, TTL_FULL = 3 };
enum { TTL_PASS = 1, TTL_HOLD = 0 };

typedef struct {
	_Atomic uint32_t lo;
	_Atomic uint32_t hi;
	_Atomic uint32_t hits;
	_Atomic int64_t expire;
	int32_t next;
} TtlNode;

typedef struct {
	TtlNode node[TTL_CAP];
	_Atomic uint64_t head;
	_Atomic uint64_t free_top;
} TtlFilter;

void ttl_filter_init(TtlFilter *f);
/* Сигнал отказа. Первый раз — бан, запись на стек. Повтор того же диапазона —
   бан-бан: срок растёт, запись переносится на вершину. Сбой CAS при переносе
   стек не рвёт: срок уже записан, звенья остаются. */
int  ttl_signal(TtlFilter *f, uint32_t lo, uint32_t hi, int64_t now, int64_t base, int64_t step);
/* Пакет уходит, если ни одна живая запись его не покрывает. Иначе порт молчит.
   Чтение не пишет звенья. Битый индекс обрывает проход. */
int  ttl_pass(const TtlFilter *f, uint32_t addr, int64_t now);
void ttl_sort(TtlFilter *f, int64_t now);
int  ttl_order(const TtlFilter *f, uint32_t *lo, int cap);
int  ttl_active(const TtlFilter *f);
#endif
