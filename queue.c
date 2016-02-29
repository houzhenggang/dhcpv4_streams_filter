/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

/*
 * Packet presentation queueing mechanism
 */

#include "dhcp_module.h"

int process_expired_queued_cpkts (obj_t *obj)
{
	cached_pkt *t;
	hrtime_t curr = 0;
	uint64_t count = 0;

	if (obj == NULL)
		return (0);

	curr = gethrtime ();
	while (obj -> queued_cpkts) {
		if (obj -> queued_cpkts -> enqueue + default_storage_time_period_in_ticks > curr)
			break;
		t = obj -> queued_cpkts;
		if (t -> hash_name != NULL) {
			hash_remove_item (obj -> pkt_rates_table, t -> hash_name);
			t -> hash_name = NULL;
		}
		
		obj -> queued_cpkts = obj -> queued_cpkts -> next;
		if (obj -> queued_cpkts == NULL)
			obj -> queued_cpkts_end = NULL;

		if (t -> flag & ON_RATES_QUEUE)
			t -> flag &= ~ON_RATES_QUEUE;

		/* Link the packet on the unqueued list */
		t -> next = obj -> unqueued_cpkts;
		obj -> unqueued_cpkts = t;

		count++;
	}

	if (count > 0) {
		obj -> main_stat -> cache_expired = obj -> main_stat -> cache_expired + count;
		if (obj -> pkt_rates_table) {
		        obj -> main_stat -> cache_records = obj -> pkt_rates_table -> values;
		}
	}

	obj -> last = curr;
	if (obj -> start + default_1sec_in_ticks < obj -> last) {
		obj -> start = obj -> last;
		obj -> main_stat -> last_total_pkts = obj -> main_stat -> total_pkts;
		obj -> main_stat -> last_passed_pkts = obj -> main_stat -> passed_pkts;
		obj -> main_stat -> last_dropped_pkts = obj -> main_stat -> dropped_pkts;
	}

	return count;
}

int queue_lookup_cpkt (void *what)
{
	cached_pkt *w;

	if (what == NULL)
		return 0;

	w = what;

	if (w -> flag & ON_RATES_QUEUE)
		return 1;

	return 0;
}

void queue_remove_cpkt (obj_t *obj, void *what)
{
	cached_pkt *t, *q, *w;

	if (what == NULL)
		return;

	w = what;

	/* See if this packet was already queued, and unqueue it */
	t = (cached_pkt *)0;
	q = (cached_pkt *)0;
	if (w -> flag & ON_RATES_QUEUE) {
		for (q = obj -> queued_cpkts; q; q = q -> next) {
			if (q == what) {
				if (q -> hash_name != NULL) {
					hash_remove_item (obj -> pkt_rates_table, q -> hash_name);
					q -> hash_name = NULL;
				}

				if (t)
					t -> next = q -> next;
				else
					obj -> queued_cpkts = q -> next;
				if (q -> next == NULL)
					obj -> queued_cpkts_end = t;
				break;
			}
			t = q;
		}
	}

	/* Link the packet on the unqueued list */
	if (q) {
		if (q -> flag & ON_RATES_QUEUE)
			q -> flag &= ~ON_RATES_QUEUE;

		q -> next = obj -> unqueued_cpkts;
		obj -> unqueued_cpkts = q;
	}
}

void queue_add_cpkt (obj_t *obj, void *what, hrtime_t delta)
{
	cached_pkt *t, *q, *w;

	if (what == NULL)
		return;

	w = what;

	/* See if this packet was already queued */
	q = (cached_pkt *)0;
	if (w -> flag & ON_RATES_QUEUE) {
		for (q = obj -> queued_cpkts; q; q = q -> next) {
			if (q == what) {
				return;
			}
		}
	}

	q = what;

	q -> enqueue = gethrtime () + delta;

	if (!(q -> flag & ON_RATES_QUEUE))
		q -> flag |= ON_RATES_QUEUE;

	/* Link the packet on the start of queued list */
	if ((obj -> queued_cpkts == NULL) ||
	    (obj -> queued_cpkts -> enqueue > q -> enqueue)) {
		q -> next = obj -> queued_cpkts;
		if (obj -> queued_cpkts == NULL)
			obj -> queued_cpkts_end = q;
		obj -> queued_cpkts = q;
		return;
	}

	if (delta > 0) {
		/* We can avoid this cycle if it is known that packet expire won't be in the future */
		for (t = obj -> queued_cpkts; t -> next; t = t -> next) {
			if (t -> next -> enqueue > q -> enqueue) {
				q -> next = t -> next;
				t -> next = q;
				return;
			}
		}

		t -> next = q;
	} else {
		if (obj -> queued_cpkts_end)
			obj -> queued_cpkts_end -> next = q;
	}
	obj -> queued_cpkts_end = q;
	q -> next = (cached_pkt *)0;
}

void queue_remove_cpkts (obj_t *obj)
{
	cached_pkt *t, *n;
	for (t = obj -> queued_cpkts; t; t = n) {
		n = t -> next;

		if (t -> hash_name != NULL) {
			hash_remove_item (obj -> pkt_rates_table, t -> hash_name);
			t -> hash_name = NULL;
		}

		if (t -> flag & ON_RATES_QUEUE)
			t -> flag &= ~ON_RATES_QUEUE;

		/* Link the packet on the unqueued list */
		t -> next = obj -> unqueued_cpkts;
		obj -> unqueued_cpkts = t;
	}
	obj -> queued_cpkts = NULL;
	obj -> queued_cpkts_end = NULL;

	if (obj -> pkt_rates_table) {
	        obj -> main_stat -> cache_records = obj -> pkt_rates_table -> values;
	}
}

void queue_free_cpkts (obj_t *obj)
{
	cached_pkt *t, *n;
	for (t = obj -> unqueued_cpkts; t; t = n) {
		n = t -> next;
		kmem_free (t, t -> allocated);
		t = NULL;
	}
	obj -> unqueued_cpkts = NULL;
}
