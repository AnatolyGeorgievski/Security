#include "ttl_filter.h"
#include <string.h>

enum { TTL_NIL = -1 };

static int stk_idx(uint64_t h)
{
	uint32_t u = (uint32_t)h;
	return u == 0xFFFFFFFFu ? TTL_NIL : (int)u;
}

static uint32_t stk_gen(uint64_t h)
{
	return (uint32_t)(h >> 32);
}

static uint64_t stk_make(uint32_t gen, int idx)
{
	uint32_t u = idx < 0 ? 0xFFFFFFFFu : (uint32_t)idx;
	return ((uint64_t)gen << 32) | u;
}

static int stk_pop(_Atomic uint64_t *top, TtlNode *node)
{
	uint64_t h;
	do {
		h = atomic_load_explicit(top, memory_order_acquire);
		int i = stk_idx(h);
		if (i < 0 || i >= TTL_CAP)
			return TTL_NIL;
		int nxt = node[i].next;
		if (atomic_compare_exchange_weak_explicit(
			top, &h, stk_make(stk_gen(h) + 1, nxt),
			memory_order_acq_rel, memory_order_acquire))
			return i;
	} while (1);
}

static void stk_push(_Atomic uint64_t *top, TtlNode *node, int i)
{
	uint64_t h;
	do {
		h = atomic_load_explicit(top, memory_order_acquire);
		node[i].next = stk_idx(h);
	} while (!atomic_compare_exchange_weak_explicit(
		top, &h, stk_make(stk_gen(h) + 1, i),
		memory_order_acq_rel, memory_order_acquire));
}

static int link_ok(int i)
{
	return i == TTL_NIL || (i >= 0 && i < TTL_CAP);
}

void ttl_filter_init(TtlFilter *f)
{
	memset(f, 0, sizeof *f);
	for (int i = 0; i < TTL_CAP; i++) {
		f->node[i].next = i + 1;
		atomic_store(&f->node[i].lo, 0);
		atomic_store(&f->node[i].hi, 0);
		atomic_store(&f->node[i].hits, 0);
		atomic_store(&f->node[i].expire, 0);
	}
	f->node[TTL_CAP - 1].next = TTL_NIL;
	atomic_store(&f->free_top, stk_make(1, 0));
	atomic_store(&f->head, stk_make(1, TTL_NIL));
}

static int64_t ttl_term(int64_t now, int64_t base, int64_t step, uint32_t hits)
{
	return now + base + (int64_t)hits * step;
}

int ttl_pass(const TtlFilter *f, uint32_t addr, int64_t now)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	for (int n = 0; n < TTL_CAP; n++) {
		if (!link_ok(i) || i < 0)
			break;
		uint32_t lo = atomic_load(&f->node[i].lo);
		uint32_t hi = atomic_load(&f->node[i].hi);
		int64_t exp = atomic_load(&f->node[i].expire);
		if (exp > now && addr >= lo && addr <= hi)
			return TTL_HOLD;
		int nxt = f->node[i].next;
		if (!link_ok(nxt))
			break;
		i = nxt;
	}
	return TTL_PASS;
}

static int find_key(const TtlFilter *f, uint32_t lo, uint32_t hi)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	for (int n = 0; n < TTL_CAP; n++) {
		if (!link_ok(i) || i < 0)
			return TTL_NIL;
		if (atomic_load(&f->node[i].lo) == lo && atomic_load(&f->node[i].hi) == hi)
			return i;
		int nxt = f->node[i].next;
		if (!link_ok(nxt))
			return TTL_NIL;
		i = nxt;
	}
	return TTL_NIL;
}

/* Одна попытка забрать цепочку. Неудачный CAS ничего не пишет. */
static int try_detach(TtlFilter *f, int *chain)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	if (i < 0) {
		*chain = TTL_NIL;
		return 1;
	}
	if (!link_ok(i))
		return 0;
	if (!atomic_compare_exchange_strong_explicit(
		&f->head, &h, stk_make(stk_gen(h) + 1, TTL_NIL),
		memory_order_acq_rel, memory_order_acquire))
		return 0;
	*chain = i;
	return 1;
}

static void move_head(TtlFilter *f, int hot)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	if (stk_idx(h) == hot)
		return;
	int chain;
	if (!try_detach(f, &chain))
		return;
	int idx[TTL_CAP];
	int n = 0;
	int seen = 0;
	while (link_ok(chain) && chain >= 0 && n < TTL_CAP) {
		int nxt = f->node[chain].next;
		if (chain == hot)
			seen = 1;
		else
			idx[n++] = chain;
		if (!link_ok(nxt))
			break;
		chain = nxt;
	}
	for (int k = n - 1; k >= 0; k--)
		stk_push(&f->head, f->node, idx[k]);
	if (seen)
		stk_push(&f->head, f->node, hot);
}

int ttl_signal(TtlFilter *f, uint32_t lo, uint32_t hi, int64_t now, int64_t base, int64_t step)
{
	if (lo > hi) {
		uint32_t t = lo;
		lo = hi;
		hi = t;
	}
	int i = find_key(f, lo, hi);
	if (i >= 0) {
		uint32_t hits = atomic_fetch_add(&f->node[i].hits, 1) + 1;
		atomic_store(&f->node[i].expire, ttl_term(now, base, step, hits));
		move_head(f, i);
		return TTL_HIT;
	}
	i = stk_pop(&f->free_top, f->node);
	if (i < 0) {
		ttl_sort(f, now);
		i = stk_pop(&f->free_top, f->node);
		if (i < 0)
			return TTL_FULL;
	}
	atomic_store(&f->node[i].lo, lo);
	atomic_store(&f->node[i].hi, hi);
	atomic_store(&f->node[i].hits, 1);
	atomic_store(&f->node[i].expire, ttl_term(now, base, step, 1));
	stk_push(&f->head, f->node, i);
	return TTL_NEW;
}

void ttl_sort(TtlFilter *f, int64_t now)
{
	int chain;
	if (!try_detach(f, &chain))
		return;
	int idx[TTL_CAP];
	int n = 0;
	while (link_ok(chain) && chain >= 0 && n < TTL_CAP) {
		int nxt = f->node[chain].next;
		int64_t exp = atomic_load(&f->node[chain].expire);
		if (exp <= now) {
			atomic_store(&f->node[chain].lo, 0);
			atomic_store(&f->node[chain].hi, 0);
			stk_push(&f->free_top, f->node, chain);
		} else {
			int p = n;
			while (p > 0 && atomic_load(&f->node[idx[p - 1]].expire) < exp) {
				idx[p] = idx[p - 1];
				p--;
			}
			idx[p] = chain;
			n++;
		}
		if (!link_ok(nxt))
			break;
		chain = nxt;
	}
	for (int k = n - 1; k >= 0; k--)
		stk_push(&f->head, f->node, idx[k]);
}

int ttl_order(const TtlFilter *f, uint32_t *lo, int cap)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	int n = 0;
	while (link_ok(i) && i >= 0 && n < cap) {
		lo[n++] = atomic_load(&f->node[i].lo);
		int nxt = f->node[i].next;
		if (!link_ok(nxt))
			break;
		i = nxt;
	}
	return n;
}

int ttl_active(const TtlFilter *f)
{
	uint32_t tmp[TTL_CAP];
	return ttl_order(f, tmp, TTL_CAP);
}

#ifdef TTL_FILTER_MAIN
#include <pthread.h>
#include <stdio.h>

static TtlFilter g;

static void *flood(void *arg)
{
	unsigned base = (unsigned)(uintptr_t)arg;
	for (unsigned k = 0; k < 80; k++) {
		uint32_t a = (base << 16) | k;
		ttl_signal(&g, a, a, 0, 100, 1);
	}
	return NULL;
}

int main(void)
{
	TtlFilter f;
	uint32_t ord[8];
	int n;
	int head;

	ttl_filter_init(&f);
	if (ttl_pass(&f, 5, 0) != TTL_PASS) return 1;
	if (ttl_signal(&f, 5, 5, 0, 10, 1) != TTL_NEW) return 2;
	if (ttl_pass(&f, 5, 0) != TTL_HOLD) return 3;
	if (ttl_pass(&f, 6, 0) != TTL_PASS) return 4;
	if (ttl_signal(&f, 5, 5, 1, 10, 1) != TTL_HIT) return 5;
	n = ttl_order(&f, ord, 8);
	if (n != 1 || ord[0] != 5) return 6;
	if (atomic_load(&f.node[stk_idx(atomic_load(&f.head))].hits) != 2) return 7;

	if (ttl_signal(&f, 10, 12, 0, 10, 1) != TTL_NEW) return 8;
	if (ttl_pass(&f, 11, 0) != TTL_HOLD) return 9;
	if (ttl_pass(&f, 9, 0) != TTL_PASS) return 10;
	if (ttl_pass(&f, 13, 0) != TTL_PASS) return 11;
	if (ttl_order(&f, ord, 8) < 1 || ord[0] != 10) return 12;

	head = stk_idx(atomic_load(&f.head));
	f.node[head].next = 999;
	if (ttl_pass(&f, 11, 0) != TTL_HOLD) return 13;
	if (f.node[head].next != 999) return 14;

	ttl_filter_init(&f);
	ttl_signal(&f, 1, 1, 0, 10, 1);
	ttl_signal(&f, 2, 2, 0, 10, 1);
	ttl_signal(&f, 1, 1, 1, 10, 1);
	ttl_sort(&f, 12);
	n = ttl_order(&f, ord, 8);
	if (n != 1 || ord[0] != 1) return 15;

	ttl_filter_init(&g);
	pthread_t th[4];
	for (int i = 0; i < 4; i++)
		pthread_create(&th[i], NULL, flood, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	if (ttl_active(&g) != TTL_CAP) return 16;
	if (ttl_signal(&g, 7, 7, 0, 100, 1) != TTL_FULL) return 17;
	ttl_sort(&g, 1000);
	if (ttl_active(&g) != 0) return 18;
	if (ttl_pass(&g, 7, 1000) != TTL_PASS) return 19;

	puts("ttl_filter ok");
	return 0;
}
#endif
