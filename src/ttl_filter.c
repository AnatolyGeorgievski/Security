/* Реализация контракта из ttl_filter.h. */
#include "ttl_filter.h"

enum { TTL_NIL = -1 };

_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0), "ttl record");

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

static int stk_pop(_Atomic uint64_t *top, int16_t *link)
{
	uint64_t h;
	do {
		h = atomic_load_explicit(top, memory_order_acquire);
		int i = stk_idx(h);
		if (i < 0 || i >= TTL_CAP)
			return TTL_NIL;
		int next = link[i];
		if (atomic_compare_exchange_weak_explicit(
			top, &h, stk_make(stk_gen(h) + 1, next),
			memory_order_acq_rel, memory_order_acquire))
			return i;
	} while (1);
}

static void stk_push(_Atomic uint64_t *top, int16_t *link, int i)
{
	uint64_t h;
	do {
		h = atomic_load_explicit(top, memory_order_acquire);
		link[i] = (int16_t)stk_idx(h);
	} while (!atomic_compare_exchange_weak_explicit(
		top, &h, stk_make(stk_gen(h) + 1, i),
		memory_order_acq_rel, memory_order_acquire));
}

static int link_ok(int i)
{
	return i == TTL_NIL || (i >= 0 && i < TTL_CAP);
}

static uint64_t rec_make(uint32_t lo, uint16_t width, uint16_t expire)
{
	return (uint64_t)lo | ((uint64_t)width << 32) | ((uint64_t)expire << 48);
}

static uint32_t rec_lo(uint64_t r)
{
	return (uint32_t)r;
}

static uint16_t rec_width(uint64_t r)
{
	return (uint16_t)(r >> 32);
}

static uint16_t rec_expire(uint64_t r)
{
	return (uint16_t)(r >> 48);
}

static void rec_store(TtlFilter *f, int i, uint32_t lo, uint16_t width, uint16_t expire)
{
	atomic_store_explicit(&f->node[i], rec_make(lo, width, expire), memory_order_release);
}

static uint64_t rec_load(const TtlFilter *f, int i)
{
	return atomic_load_explicit(&f->node[i], memory_order_acquire);
}

void ttl_filter_init(TtlFilter *f)
{
	for (int i = 0; i < TTL_CAP; i++) {
		atomic_store_explicit(&f->node[i], 0, memory_order_relaxed);
		f->hits[i] = 0;
		f->link[i] = (int16_t)(i + 1);
	}
	f->link[TTL_CAP - 1] = TTL_NIL;
	atomic_store(&f->free_top, stk_make(1, 0));
	atomic_store(&f->head, stk_make(1, TTL_NIL));
}

static uint16_t sat_width(uint32_t lo, uint32_t hi)
{
	uint32_t span = hi - lo;
	if (span > 65535u)
		return 65535u;
	return (uint16_t)span;
}

static uint16_t sat_hits(uint16_t hits)
{
	if (hits == 65535u)
		return hits;
	return (uint16_t)(hits + 1);
}

static uint16_t ttl_term(int64_t now, int64_t base, int64_t step, unsigned hits)
{
	int64_t term = now + base + (int64_t)hits * step;
	if (term <= 0)
		return 0;
	if (term > 65535)
		return 65535;
	return (uint16_t)term;
}

int ttl_pass(const TtlFilter *f, uint32_t addr, int64_t now)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	for (int n = 0; n < TTL_CAP; n++) {
		uint64_t r;
		uint32_t lo;
		if (!link_ok(i) || i < 0)
			break;
		r = rec_load(f, i);
		lo = rec_lo(r);
		if ((int64_t)rec_expire(r) > now && addr >= lo && addr <= lo + rec_width(r))
			return TTL_HOLD;
		int next = f->link[i];
		if (!link_ok(next))
			break;
		i = next;
	}
	return TTL_PASS;
}

static int find_key(const TtlFilter *f, uint32_t lo, uint32_t hi)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	uint16_t width = sat_width(lo, hi);
	int i = stk_idx(h);
	for (int n = 0; n < TTL_CAP; n++) {
		uint64_t r;
		if (!link_ok(i) || i < 0)
			return TTL_NIL;
		r = rec_load(f, i);
		if (rec_lo(r) == lo && rec_width(r) == width)
			return i;
		int next = f->link[i];
		if (!link_ok(next))
			return TTL_NIL;
		i = next;
	}
	return TTL_NIL;
}

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
		int next = f->link[chain];
		if (chain == hot)
			seen = 1;
		else
			idx[n++] = chain;
		if (!link_ok(next))
			break;
		chain = next;
	}
	for (int k = n - 1; k >= 0; k--)
		stk_push(&f->head, f->link, idx[k]);
	if (seen)
		stk_push(&f->head, f->link, hot);
}

static void sort_held(TtlFilter *f, int64_t now);
static int signal_held(TtlFilter *f, uint32_t lo, uint32_t hi, int64_t now, int64_t base, int64_t step)
{
	int i = find_key(f, lo, hi);
	if (i >= 0) {
		uint64_t r = rec_load(f, i);
		unsigned hits = sat_hits(f->hits[i]);
		f->hits[i] = (uint16_t)hits;
		rec_store(f, i, rec_lo(r), rec_width(r), ttl_term(now, base, step, hits));
		move_head(f, i);
		return TTL_HIT;
	}
	i = stk_pop(&f->free_top, f->link);
	if (i < 0) {
		sort_held(f, now);
		i = stk_pop(&f->free_top, f->link);
		if (i < 0)
			return TTL_FULL;
	}
	f->hits[i] = 1;
	rec_store(f, i, lo, sat_width(lo, hi), ttl_term(now, base, step, 1));
	stk_push(&f->head, f->link, i);
	return TTL_NEW;
}

int ttl_signal(TtlFilter *f, uint32_t lo, uint32_t hi, int64_t now, int64_t base, int64_t step)
{
	if (lo > hi) {
		uint32_t t = lo;
		lo = hi;
		hi = t;
	}
	return signal_held(f, lo, hi, now, base, step);
}

static void sort_held(TtlFilter *f, int64_t now)
{
	int chain;
	if (!try_detach(f, &chain))
		return;
	int idx[TTL_CAP];
	int n = 0;
	while (link_ok(chain) && chain >= 0 && n < TTL_CAP) {
		int next = f->link[chain];
		uint64_t r = rec_load(f, chain);
		if ((int64_t)rec_expire(r) <= now) {
			atomic_store_explicit(&f->node[chain], 0, memory_order_relaxed);
			f->hits[chain] = 0;
			stk_push(&f->free_top, f->link, chain);
		} else {
			int p = n;
			while (p > 0 && rec_expire(rec_load(f, idx[p - 1])) < rec_expire(r)) {
				idx[p] = idx[p - 1];
				p--;
			}
			idx[p] = chain;
			n++;
		}
		if (!link_ok(next))
			break;
		chain = next;
	}
	for (int k = n - 1; k >= 0; k--)
		stk_push(&f->head, f->link, idx[k]);
}

void ttl_sort(TtlFilter *f, int64_t now)
{
	sort_held(f, now);
}

int ttl_order(const TtlFilter *f, uint32_t *lo, int cap)
{
	uint64_t h = atomic_load_explicit(&f->head, memory_order_acquire);
	int i = stk_idx(h);
	int n = 0;
	while (link_ok(i) && i >= 0 && n < cap) {
		lo[n++] = rec_lo(rec_load(f, i));
		int next = f->link[i];
		if (!link_ok(next))
			break;
		i = next;
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
	return (int)rec_lo(rec_load(f, i));
}

static int head_hits(const TtlFilter *f)
{
	int i = stk_idx(atomic_load(&f->head));
	if (i < 0)
		return -1;
	return (int)f->hits[i];
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
	saved = f->link[i];
	f->link[i] = 999;
	rc = ttl_pass(f, 11, 0);
	if (f->link[i] != 999)
		rc = TTL_PASS;
	f->link[i] = (int16_t)saved;
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
	for (uint32_t a = 1000; a < 1000 + (TTL_CAP - 1); a++) {
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

enum { FLOOD_N = 250 };
static const uint32_t net_lo = 0x64400000u;
static const uint32_t net_hi = 0x644000FFu;
static TtlFilter *flood_f;
static _Atomic int flood_new;

static void *flood(void *arg)
{
	(void)arg;
	if (ttl_signal(flood_f, net_lo, net_hi, 0, 100, 1) == TTL_NEW)
		atomic_fetch_add(&flood_new, 1);
	return NULL;
}

static int hold_span(const TtlFilter *f)
{
	uint32_t a = net_lo;
	uint32_t b = net_hi;
	for (uint32_t x = net_lo; x <= net_hi; x++)
		if (ttl_pass(f, x, 0) != TTL_HOLD)
			return 0;
	for (uint32_t x = net_hi; x > net_lo; x--)
		if (ttl_pass(f, x, 0) != TTL_HOLD)
			return 0;
	if (ttl_pass(f, net_lo, 0) != TTL_HOLD)
		return 0;
	while (a < b) {
		if (ttl_pass(f, a, 0) != TTL_HOLD || ttl_pass(f, b, 0) != TTL_HOLD)
			return 0;
		a++;
		b--;
	}
	if (a == b && ttl_pass(f, a, 0) != TTL_HOLD)
		return 0;
	return 1;
}

static int v_flood(TtlFilter *f)
{
	TtlFilter g;
	pthread_t th[FLOOD_N];
	pthread_attr_t at;
	int held;
	int before;
	int slot;
	int expect_hits;
	int svc;
	int made;
	(void)f;
	ttl_filter_init(&g);
	flood_f = &g;
	atomic_store(&flood_new, 0);
	pthread_attr_init(&at);
	pthread_attr_setstacksize(&at, 65536);
	for (int i = 0; i < FLOOD_N; i++) {
		if (pthread_create(&th[i], &at, flood, (void *)(uintptr_t)i) != 0)
			return step("потоки", TTL_PASS, TTL_HOLD, TTL_NEW, TTL_HIT, i, FLOOD_N, 0, 1 + FLOOD_N);
	}
	pthread_attr_destroy(&at);
	for (int i = 0; i < FLOOD_N; i++)
		pthread_join(th[i], NULL);
	made = atomic_load(&flood_new);
	before = ttl_active(&g);
	slot = find_key(&g, net_lo, net_hi);
	if (made < 1 || made > FLOOD_N || before < 1 || before > FLOOD_N || slot < 0)
		return step("потоки", TTL_PASS, TTL_HOLD, TTL_NEW, TTL_HIT, head_lo(&g), (int)net_lo, head_hits(&g), made);
	expect_hits = g.hits[slot] == 65535 ? 65535 : g.hits[slot] + 1;
	svc = ttl_signal(&g, net_lo, net_hi, 0, 100, 1);
	held = ttl_pass(&g, net_lo + 250, 0);
	if (svc != TTL_HIT || ttl_active(&g) != before || !hold_span(&g) || ttl_pass(&g, net_hi + 1, 0) != TTL_PASS)
		return step("потоки", held, TTL_HOLD, svc, TTL_HIT, head_lo(&g), (int)net_lo, head_hits(&g), expect_hits);
	return step("потоки", held, TTL_HOLD, svc, TTL_HIT, head_lo(&g), (int)net_lo, head_hits(&g), expect_hits);
}

static int v_sat(TtlFilter *f)
{
	TtlFilter g;
	int slot;
	int svc;
	(void)f;
	ttl_filter_init(&g);
	svc = ttl_signal(&g, 0, 70000, 0, 1, 1);
	if (svc != TTL_NEW || ttl_pass(&g, 65535, 0) != TTL_HOLD || ttl_pass(&g, 65536, 0) != TTL_PASS)
		return step("насыщение", TTL_PASS, TTL_HOLD, svc, TTL_NEW, head_lo(&g), 0, head_hits(&g), 1);
	slot = stk_idx(atomic_load(&g.head));
	g.hits[slot] = 65535;
	svc = ttl_signal(&g, 0, 70000, 0, 1, 1);
	if (head_hits(&g) != 65535 || ttl_pass(&g, 0, 65535) != TTL_PASS)
		return step("насыщение", TTL_PASS, TTL_HOLD, svc, TTL_HIT, head_lo(&g), 0, head_hits(&g), 65535);
	return step("насыщение", ttl_pass(&g, 0, 65534), TTL_HOLD, svc, TTL_HIT, head_lo(&g), 0, head_hits(&g), 65535);
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
		{ "насыщение", v_sat },
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
