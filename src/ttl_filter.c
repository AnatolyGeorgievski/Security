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

static int n_pass, n_fail;

static const char *client_word(int c)
{
	if (c == TTL_PASS) return "pass";
	if (c == TTL_HOLD) return "hold";
	return "?";
}

static const char *service_word(int c)
{
	if (c == TTL_NEW) return "new";
	if (c == TTL_HIT) return "hit";
	if (c == TTL_FULL) return "full";
	if (c == -1) return "none";
	return "?";
}

static int head_lo(const TtlFilter *f)
{
	int i = stk_idx(atomic_load(&f->head));
	if (i < 0)
		return -1;
	return (int)atomic_load(&f->node[i].lo);
}

static int head_hits(const TtlFilter *f)
{
	int i = stk_idx(atomic_load(&f->head));
	if (i < 0)
		return -1;
	return (int)atomic_load(&f->node[i].hits);
}

/* Прогон одного модуля: клиент ttl_pass, сервис ttl_signal, вершина стека. */
static int step(const char *name, int client, int want_c, int service, int want_s,
		int head, int want_head, int hits, int want_hits)
{
	int bad = client != want_c || service != want_s || head != want_head || hits != want_hits;
	printf("%s %s client=%s service=%s head=%d hits=%d\n",
		bad ? "fail" : "pass", name, client_word(client), service_word(service), head, hits);
	if (bad) {
		n_fail++;
		return 1;
	}
	n_pass++;
	return 0;
}

static int v_empty(TtlFilter *f)
{
	return step("пустой приём", ttl_pass(f, 5, 0), TTL_PASS, -1, -1, head_lo(f), -1, ttl_active(f), 0);
}

static int v_ban(TtlFilter *f)
{
	int svc = ttl_signal(f, 5, 5, 0, 10, 1);
	int client = ttl_pass(f, 5, 0);
	if (ttl_pass(f, 6, 0) != TTL_PASS)
		client = -2;
	return step("бан", client, TTL_HOLD, svc, TTL_NEW, head_lo(f), 5, head_hits(f), 1);
}

static int v_banban(TtlFilter *f)
{
	int svc = ttl_signal(f, 5, 5, 1, 10, 1);
	return step("бан-бан", ttl_pass(f, 5, 1), TTL_HOLD, svc, TTL_HIT, head_lo(f), 5, head_hits(f), 2);
}

static int v_range(TtlFilter *f)
{
	int svc = ttl_signal(f, 10, 12, 0, 10, 1);
	if (ttl_pass(f, 9, 0) != TTL_PASS || ttl_pass(f, 13, 0) != TTL_PASS)
		return step("диапазон", TTL_PASS, TTL_HOLD, svc, TTL_NEW, head_lo(f), 10, head_hits(f), 1);
	return step("диапазон", ttl_pass(f, 11, 0), TTL_HOLD, svc, TTL_NEW, head_lo(f), 10, head_hits(f), 1);
}

static int v_read(TtlFilter *f)
{
	int i = stk_idx(atomic_load(&f->head));
	int saved, rc;
	if (i < 0)
		return step("чтение стека", TTL_HOLD, TTL_PASS, -1, -1, -1, 10, 0, 1);
	saved = f->node[i].next;
	f->node[i].next = 999;
	rc = ttl_pass(f, 11, 0);
	if (f->node[i].next != 999)
		rc = TTL_PASS;
	f->node[i].next = saved;
	return step("чтение стека", rc, TTL_HOLD, -1, -1, head_lo(f), 10, head_hits(f), 1);
}

static int v_expire(TtlFilter *f)
{
	ttl_sort(f, 12);
	if (ttl_pass(f, 11, 12) != TTL_PASS || ttl_active(f) != 1)
		return step("срок", TTL_PASS, TTL_HOLD, -1, -1, head_lo(f), 5, head_hits(f), 2);
	return step("срок", ttl_pass(f, 5, 12), TTL_HOLD, -1, -1, head_lo(f), 5, head_hits(f), 2);
}

static int v_full(TtlFilter *f)
{
	int svc = TTL_NEW;
	for (uint32_t a = 1000; a < 1000 + 255; a++) {
		svc = ttl_signal(f, a, a, 0, 10, 1);
		if (svc != TTL_NEW)
			break;
	}
	if (svc == TTL_NEW)
		svc = ttl_signal(f, 200000, 200000, 0, 10, 1);
	if (ttl_active(f) != TTL_CAP)
		return step("таблица полна", TTL_PASS, TTL_HOLD, svc, TTL_FULL, head_lo(f), 5, head_hits(f), 2);
	return step("таблица полна", ttl_pass(f, 5, 0), TTL_HOLD, svc, TTL_FULL, head_lo(f), 5, head_hits(f), 2);
}

static TtlFilter *flood_f;

static void *flood(void *arg)
{
	unsigned base = (unsigned)(uintptr_t)arg;
	for (unsigned k = 0; k < 80; k++) {
		uint32_t a = (base << 16) | k;
		ttl_signal(flood_f, a, a, 0, 100, 1);
	}
	return NULL;
}

static int v_flood(TtlFilter *f)
{
	TtlFilter g;
	pthread_t th[4];
	uint32_t a = 1u << 16;
	int active, held, svc;
	(void)f;
	ttl_filter_init(&g);
	flood_f = &g;
	for (int i = 0; i < 4; i++)
		pthread_create(&th[i], NULL, flood, (void *)(uintptr_t)(i + 1));
	for (int i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	active = ttl_active(&g);
	held = ttl_pass(&g, a, 0);
	svc = ttl_signal(&g, 7, 7, 0, 100, 1);
	ttl_sort(&g, 1000);
	if (active != TTL_CAP || held != TTL_HOLD || ttl_active(&g) != 0 || ttl_pass(&g, a, 1000) != TTL_PASS)
		return step("потоки", held, TTL_HOLD, svc, TTL_FULL, 0, -1, active, TTL_CAP);
	return step("потоки", held, TTL_HOLD, svc, TTL_FULL, -1, -1, active, TTL_CAP);
}

static int v_after(TtlFilter *f)
{
	ttl_sort(f, 12);
	if (ttl_pass(f, 1000, 12) != TTL_PASS || ttl_active(f) != 1)
		return step("после срока", TTL_HOLD, TTL_PASS, -1, -1, head_lo(f), 5, head_hits(f), 2);
	return step("после срока", ttl_pass(f, 5, 12), TTL_HOLD, -1, -1, head_lo(f), 5, head_hits(f), 2);
}

int main(void)
{
	TtlFilter f;
	struct { const char *name; int (*run)(TtlFilter *); } v[] = {
		{ "пустой приём", v_empty },
		{ "бан", v_ban },
		{ "бан-бан", v_banban },
		{ "диапазон", v_range },
		{ "чтение стека", v_read },
		{ "срок", v_expire },
		{ "таблица полна", v_full },
		{ "после срока", v_after },
		{ "потоки", v_flood },
	};
	(void)v[0].name;
	ttl_filter_init(&f);
	for (unsigned i = 0; i < sizeof v / sizeof v[0]; i++) {
		if (v[i].run(&f))
			break;
	}
	printf("skip 0 fail %d pass %d\n", n_fail, n_pass);
	return n_fail ? 1 : 0;
}
#endif
