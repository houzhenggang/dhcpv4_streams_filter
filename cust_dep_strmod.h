/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */
  
#ifndef CUST_DEPEND_HDR
#define CUST_DEPEND_HDR

#include "dhcp_module.h"

typedef struct obj_stat_named	obj_stat_named_t;

typedef struct obj_kstat_named	obj_kstat_named_t;

struct obj_kstat_named {
 	kstat_named_t state;
 	kstat_named_t total_pkts;
 	kstat_named_t total_pkts_per_sec;
	kstat_named_t passed_pkts;
	kstat_named_t passed_pkts_per_sec;
	kstat_named_t dropped_pkts;
	kstat_named_t dropped_pkts_per_sec;
	kstat_named_t rate_dropped_pkts;
	kstat_named_t failed_pkts;
	kstat_named_t total_malformed_pkts;
	kstat_named_t invalid_ip_pkts;
	kstat_named_t invalid_udp_pkts;
	kstat_named_t invalid_bootp_pkts;
	kstat_named_t fragmented_ip_pkts;
	kstat_named_t underrun_pkts;
	kstat_named_t overrun_pkts;
	kstat_named_t nondef_dport_pkts;
	kstat_named_t nondef_sport_pkts;
	kstat_named_t nondef_cookie_pkts;
	kstat_named_t nondef_bootp_msg_pkts;
	kstat_named_t nonsupp_bootp_hw_pkts;
	kstat_named_t nonsupp_dhcp_msg_pkts;
	kstat_named_t no_option82_pkts;
	kstat_named_t nomem_errors;
	kstat_named_t buffer_errors;
	kstat_named_t cache_hits;
	kstat_named_t cache_misses;
	kstat_named_t cache_errors;
	kstat_named_t cache_expired;
	kstat_named_t cache_allocated;
	kstat_named_t cache_records;
};

typedef struct obj_s {
	queue_t *rq;
	kmutex_t lock;
	timeout_id_t expire_queue;
	int instance_id;
	int state;
	/* general preamble */
	int default_allowed_packets_per_min;
	int default_allowed_no_ra_packets_per_min;
	int default_drop_policy_if_no_ra;
	int default_drop_policy_all_if_no_ra;
	int default_drop_policy_by_ppm;
	hash_table *pkt_rates_table;
	cached_pkt *last_cpkt;
	cached_pkt *queued_cpkts;
	cached_pkt *queued_cpkts_end;
	cached_pkt *unqueued_cpkts;
	char *largest_pkt_hash_string;
	uint16_t largest_pkt_hash_allocated;
	uchar_t *largest_pkt_option_string;
	uint16_t largest_pkt_option_allocated;
	uchar_t *largest_pkt_option_buffer;
	uint16_t largest_pkt_option_buffer_allocated;
	hrtime_t start;
	hrtime_t last;
	kstat_t	*main_ksp; /* kstat pointer */
	obj_stat_named_t *main_stat; /* per-obj kstat */
	int allocated;
} obj_t;

struct obj_stat_named {
	obj_t *obj;
	uint64_t last_total_pkts;
	uint64_t last_passed_pkts;
	uint64_t last_dropped_pkts;
	/* general preamble - statistical values */
	uint64_t total_pkts;
	uint64_t passed_pkts;
	uint64_t dropped_pkts;
	uint64_t rate_dropped_pkts;
	uint64_t failed_pkts;
	uint64_t total_malformed_pkts;
	uint64_t invalid_ip_pkts;
	uint64_t invalid_udp_pkts;
	uint64_t invalid_bootp_pkts;
	uint64_t fragmented_ip_pkts;
	uint64_t underrun_pkts;
	uint64_t overrun_pkts;
	uint64_t nondef_dport_pkts;
	uint64_t nondef_sport_pkts;
	uint64_t nondef_cookie_pkts;
	uint64_t nondef_bootp_msg_pkts;
	uint64_t nonsupp_bootp_hw_pkts;
	uint64_t nonsupp_dhcp_msg_pkts;
	uint64_t no_option82_pkts;
	uint64_t nomem_errors;
	uint64_t buffer_errors;
	uint64_t cache_hits;
	uint64_t cache_misses;
	uint64_t cache_errors;
	uint64_t cache_expired;
	uint64_t cache_allocated;
	uint64_t cache_records;
	int allocated;
};

#endif
