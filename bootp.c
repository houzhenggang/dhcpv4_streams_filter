/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

/* 
 * BOOTP parsing routines
 */

#include "dhcp_module.h"

static uint32_t cust_crc32_table[] = { CRC32_TABLE };

uint16_t default_allowed_packets_per_min = 30;
uint16_t default_allowed_no_ra_packets_per_min = 2;
uint16_t default_time_period_in_secs = 60;
hrtime_t default_1sec_in_ticks = 0;
hrtime_t default_time_period_in_ticks = 0;
hrtime_t default_storage_time_period_in_ticks = 0;
hrtime_t default_expire_queue_time_period_in_ticks = 0;

int process_pkt_rate (obj_t *obj, uint8_t dhcp_msg_type, uint32_t dhcp_ra_crc32, char *pkt_hash_string, uint16_t pkt_hash_len) {
	hash_entry *he;
	cached_pkt *cpkt;
	hrtime_t curr;
	uint16_t allowed_packets_per_min;
	int allocated;
	int i;

	curr = gethrtime ();

	he = hash_lookup (obj -> pkt_rates_table, pkt_hash_string, pkt_hash_len);
	if (he != NULL) {
		    cpkt = (cached_pkt *) he -> val;
		    if (cpkt == NULL) {
			    obj -> main_stat -> cache_errors++;
			    obj -> main_stat -> failed_pkts++;
			    return (1);
		    }
		    if ((dhcp_ra_crc32 == 0) && obj -> default_drop_policy_if_no_ra)
			    allowed_packets_per_min = obj -> default_allowed_no_ra_packets_per_min;
		    else
			    allowed_packets_per_min = obj -> default_allowed_packets_per_min;

		    obj -> main_stat -> cache_hits++;
		    cpkt -> last = curr;

		    if (cpkt -> start + default_time_period_in_ticks < cpkt -> last) {
			    if ((cpkt -> start + 2 * default_time_period_in_ticks >= cpkt -> last) &&
				(cpkt -> pkt_count[dhcp_msg_type - 1] >= allowed_packets_per_min)) {
				    cpkt -> pkt_count[dhcp_msg_type - 1] = 
					    ((allowed_packets_per_min > 1)
					    ? allowed_packets_per_min - 1 : 1);
			    } else {
				    cpkt -> pkt_count[dhcp_msg_type - 1] = 0;
			    }
			    cpkt -> start = curr;
		    }

		    cpkt -> pkt_count[dhcp_msg_type - 1]++;

		    if ((dhcp_ra_crc32 == 0) && obj -> default_drop_policy_all_if_no_ra &&
			obj -> default_drop_policy_by_ppm) {
			    cpkt -> pkt_count_dropped[dhcp_msg_type - 1]++;
			    return (0);
		    }

		    if ((cpkt -> pkt_count[dhcp_msg_type - 1] > allowed_packets_per_min) &&
			obj -> default_drop_policy_by_ppm) {
			    cpkt -> pkt_count_dropped[dhcp_msg_type - 1]++;
			    obj -> main_stat -> rate_dropped_pkts++;
			    return (0);
		    }
		    cpkt -> pkt_count_passed[dhcp_msg_type - 1]++;
	} else {
		    obj -> main_stat -> cache_misses++;
		    if (obj -> last_cpkt == NULL) {
			    if (obj -> unqueued_cpkts) {
				    cpkt = obj -> unqueued_cpkts;
				    obj -> unqueued_cpkts = cpkt -> next;
			    } else {
				    allocated = 1 * sizeof (cached_pkt);
				    cpkt = (cached_pkt *) kmem_alloc (allocated, KM_NOSLEEP);
				    if (cpkt != NULL) {
					    bzero (cpkt, allocated);
					    cpkt -> allocated = allocated;
				    }
			    }
		    } else {
			    cpkt = obj -> last_cpkt;
			    obj -> last_cpkt = NULL;
		    }
		    if (cpkt == NULL) {
			    obj -> main_stat -> nomem_errors++;
			    obj -> main_stat -> failed_pkts++;
			    return (1);
		    }

		    cpkt -> hash_name = NULL;
		    cpkt -> next = NULL;
		    cpkt -> enqueue = cpkt -> start = cpkt -> last = 0;
		    cpkt -> flag = 0;
		    for (i = 0; i < DHCP_MSG_TYPES; i++) {
			    cpkt -> pkt_count[i] = 0;
			    cpkt -> pkt_count_passed[i] = 0;
			    cpkt -> pkt_count_dropped[i] = 0;
		    }

		    if (!hash_add_item (&obj -> pkt_rates_table, pkt_hash_string, pkt_hash_len, cpkt, KM_NOSLEEP)) {
			    if (obj -> last_cpkt == NULL) {
				    obj -> last_cpkt = cpkt;
			    } else {
				    cpkt -> next = obj -> unqueued_cpkts;
				    obj -> unqueued_cpkts = cpkt;
			    }

			    obj -> main_stat -> nomem_errors++;
			    obj -> main_stat -> failed_pkts++;
			    return (1);
		    }
		    he = hash_lookup (obj -> pkt_rates_table, pkt_hash_string, pkt_hash_len);
		    if ((he == NULL) ||
			(he -> name == NULL)) {
			    hash_remove_item (obj -> pkt_rates_table, pkt_hash_string);

			    if (obj -> last_cpkt == NULL) {
				    obj -> last_cpkt = cpkt;
			    } else {
				    cpkt -> next = obj -> unqueued_cpkts;
				    obj -> unqueued_cpkts = cpkt;
			    }

			    obj -> main_stat -> cache_errors++;
			    obj -> main_stat -> failed_pkts++;
			    return (1);
		    }
		    if (obj -> pkt_rates_table) {
			    obj -> main_stat -> cache_allocated = obj -> pkt_rates_table -> buckets;
			    obj -> main_stat -> cache_records = obj -> pkt_rates_table -> values;
		    }
		    cpkt -> hash_name = he -> name;
		    cpkt -> start = curr;
		    cpkt -> last = curr;
		    cpkt -> pkt_count[dhcp_msg_type - 1] = 1;

		    queue_add_cpkt (obj, cpkt, 0);

		    if ((dhcp_ra_crc32 == 0) && obj -> default_drop_policy_all_if_no_ra &&
			obj -> default_drop_policy_by_ppm) {
			    cpkt -> pkt_count_dropped[dhcp_msg_type - 1] = 1;
			    return (0);
		    }
		    cpkt -> pkt_count_passed[dhcp_msg_type - 1] = 1;
	}

	return (2);
}

int bootp_init (void) {
	default_expire_queue_time_period_in_ticks = drv_usectohz(500000);

	default_1sec_in_ticks = 1000000 * 10 * drv_usectohz(1000000) * ((hrtime_t)1);
	default_time_period_in_ticks = 1000000 * 10 * drv_usectohz(1000000) * ((hrtime_t)default_time_period_in_secs);
	default_storage_time_period_in_ticks = 10 * default_time_period_in_ticks;

	return (1);
}

int bootp_start (obj_t *obj, int instance_id) {
	mutex_enter (&obj -> lock);

	obj -> default_allowed_packets_per_min = default_allowed_packets_per_min;
	obj -> default_allowed_no_ra_packets_per_min = default_allowed_no_ra_packets_per_min;
	obj -> default_drop_policy_if_no_ra = 0;
	obj -> default_drop_policy_all_if_no_ra = 0;
	obj -> default_drop_policy_by_ppm = 255;

	obj -> largest_pkt_hash_string = NULL;
	obj -> largest_pkt_hash_allocated = 0;

	obj -> largest_pkt_option_string = NULL;
	obj -> largest_pkt_option_allocated = 0;

	obj -> largest_pkt_option_buffer = NULL;
	obj -> largest_pkt_option_buffer_allocated = 0;

	obj -> last_cpkt = NULL;

	obj -> queued_cpkts = NULL;
	obj -> queued_cpkts_end = NULL;
	obj -> unqueued_cpkts = NULL;
	obj -> pkt_rates_table = NULL;

	obj -> start = obj -> last = gethrtime ();

	mutex_exit (&obj -> lock);

	obj_kstat_init (obj, instance_id);

	obj_kstat_update (obj -> main_ksp, KSTAT_WRITE);

	return (1);
}

int bootp_finish (obj_t *obj) {
	unsigned long hash_values = 0, last_hash_values = 0, last_cache_allocated = 0;

	mutex_enter (&obj -> lock);

	if (obj -> largest_pkt_hash_string != NULL) {
		    kmem_free (obj -> largest_pkt_hash_string, obj -> largest_pkt_hash_allocated);
		    obj -> largest_pkt_hash_string = NULL;
		    obj -> largest_pkt_hash_allocated = 0;
	}

	if (obj -> largest_pkt_option_string != NULL) {
		    kmem_free (obj -> largest_pkt_option_string, obj -> largest_pkt_option_allocated);
		    obj -> largest_pkt_option_string = NULL;
		    obj -> largest_pkt_option_allocated = 0;
	}

	if (obj -> largest_pkt_option_buffer != NULL) {
		    kmem_free (obj -> largest_pkt_option_buffer, obj -> largest_pkt_option_buffer_allocated);
		    obj -> largest_pkt_option_buffer = NULL;
		    obj -> largest_pkt_option_buffer_allocated = 0;
	}

	if (obj -> last_cpkt != NULL) {
		    kmem_free (obj -> last_cpkt, obj -> last_cpkt -> allocated);
		    obj -> last_cpkt = NULL;
	}

	queue_remove_cpkts (obj);
	queue_free_cpkts (obj);

	if (obj -> pkt_rates_table != NULL) {
		    hash_values = obj -> pkt_rates_table -> values;

		    hash_free_table (&obj -> pkt_rates_table, &last_cache_allocated, &last_hash_values);
		    obj -> pkt_rates_table = NULL;

		    if (hash_values > 0)
			    cmn_err (CE_WARN,
				    "instance ID %d: Freeing %lu HASH entries", obj -> instance_id, hash_values);
	}

	obj -> main_stat -> cache_allocated = last_cache_allocated;
	obj -> main_stat -> cache_records = last_hash_values;
	obj -> main_stat -> last_passed_pkts = obj -> main_stat -> passed_pkts;
	obj -> main_stat -> last_dropped_pkts = obj -> main_stat -> dropped_pkts;
	obj -> main_stat -> last_total_pkts = obj -> main_stat -> total_pkts;

	mutex_exit (&obj -> lock);

	obj_kstat_update (obj -> main_ksp, KSTAT_READ);

	obj_kstat_fini (obj);

	return (1);
}

int calc_crc32_for_buffer (uint32_t *crc_res, obj_t *obj, uchar_t *pkt_option_start, uint16_t pkt_option_len, int wait) {
	uchar_t *pkt_option_string = NULL;
	uint32_t crc_sum = 0;
	int allocated;

	if ((pkt_option_start == NULL) ||
	    (pkt_option_len == 0))
		return (0);

	if (pkt_option_len + 1 > obj -> largest_pkt_option_allocated) {
		if (obj -> largest_pkt_option_string != NULL) {
			kmem_free (obj -> largest_pkt_option_string, obj -> largest_pkt_option_allocated);
			obj -> largest_pkt_option_string = NULL;
			obj -> largest_pkt_option_allocated = 0;
		}
		retry:
		allocated = pkt_option_len + 1;
		pkt_option_string = (uchar_t *) kmem_alloc (allocated, wait);
		if (pkt_option_string == NULL) {
			obj -> main_stat -> nomem_errors++;
			obj -> main_stat -> failed_pkts++;
			return (0);
		}
		bzero (pkt_option_string, allocated);
		obj -> largest_pkt_option_allocated = allocated;
		obj -> largest_pkt_option_string = pkt_option_string;
	} else {
		if (obj -> largest_pkt_option_string == NULL)
			goto retry;
		pkt_option_string = obj -> largest_pkt_option_string;
	}
	bcopy (pkt_option_start, pkt_option_string, pkt_option_len);
	CRC32 (crc_sum, pkt_option_string, pkt_option_len, -1U, cust_crc32_table);
	*crc_res = crc_sum;

	return (1);
}

char *fill_pkt_hash_string (uint16_t *pkt_len, obj_t *obj, uint32_t n1, uint32_t n2, uint32_t n3, int wait) {
	char *pkt_hash_string = NULL;
	unsigned int pkt_hash_len;
	unsigned int put_hash_len;
	int allocated;

	pkt_hash_len = 3 * MAX_ULONG_STRING_LEN;

/*	if ((pkt_hash_len == 0) ||
	    (pkt_hash_len > 3 * MAX_ULONG_STRING_LEN)) {
		*pkt_len = 0;
		return (NULL);
	}*/
	pkt_hash_len += 2;

	if (pkt_hash_len + 1 > obj -> largest_pkt_hash_allocated) {
		if (obj -> largest_pkt_hash_string != NULL) {
			kmem_free (obj -> largest_pkt_hash_string, obj -> largest_pkt_hash_allocated);
			obj -> largest_pkt_hash_string = NULL;
			obj -> largest_pkt_hash_allocated = 0;
		}
		retry:
		allocated = pkt_hash_len + 1;
		pkt_hash_string = (char *) kmem_alloc (allocated, wait);
		if (pkt_hash_string == NULL) {
			*pkt_len = 0;
			obj -> main_stat -> nomem_errors++;
			obj -> main_stat -> failed_pkts++;
			return (NULL);
		}
		bzero (pkt_hash_string, allocated);
		obj -> largest_pkt_hash_allocated = allocated;
		obj -> largest_pkt_hash_string = pkt_hash_string;
	} else {
		if (obj -> largest_pkt_hash_string == NULL)
			goto retry;
		pkt_hash_string = obj -> largest_pkt_hash_string;
	}

	snprintf (pkt_hash_string, obj -> largest_pkt_hash_allocated - 1, 
		 "%u_%u_%u", n1, n2, n3);
	put_hash_len = strlen (pkt_hash_string);
	if (put_hash_len == 0) {
			*pkt_len = 0;
			obj -> main_stat -> buffer_errors++;
			obj -> main_stat -> failed_pkts++;
			return (NULL);
	}

	*pkt_len = (uint16_t)put_hash_len;

	return (pkt_hash_string);
}

int parse_bootp_option (uint8_t option_code, uchar_t *pkt_option_data, int pkt_option_len, obj_t *obj, uchar_t **option_start, uint8_t *option_len, int wait) {
	uchar_t *pkt_option_buffer = NULL;
	int option_found = 0, option_overload_opened = 0;
	int i = 0;
	int allocated;
	uint8_t curr_option_len = 0;
	uint8_t curr_code = 0;

	if ((pkt_option_data == NULL) ||
	    (pkt_option_len < DHCP_OPTION_MSG_TYPE_LEN + DHCP_OPTIONS_END_LEN) ||
	    (pkt_option_len > DHCP_OPTIONS_MAX_PKTLEN))
		return (0);

	if (pkt_option_len + 1 > obj -> largest_pkt_option_buffer_allocated) {
		if (obj -> largest_pkt_option_buffer != NULL) {
			kmem_free (obj -> largest_pkt_option_buffer, obj -> largest_pkt_option_buffer_allocated);
			obj -> largest_pkt_option_buffer = NULL;
			obj -> largest_pkt_option_buffer_allocated = 0;
		}
		retry:
		allocated = pkt_option_len + 1;
		pkt_option_buffer = (uchar_t *) kmem_alloc (allocated, wait);
		if (pkt_option_buffer == NULL) {
			obj -> main_stat -> nomem_errors++;
			obj -> main_stat -> failed_pkts++;
			return (0);
		}
		bzero (pkt_option_buffer, allocated);
		obj -> largest_pkt_option_buffer_allocated = allocated;
		obj -> largest_pkt_option_buffer = pkt_option_buffer;
	} else {
		if (obj -> largest_pkt_option_buffer == NULL)
			goto retry;
		pkt_option_buffer = obj -> largest_pkt_option_buffer;
	}
	bcopy (pkt_option_data, pkt_option_buffer, pkt_option_len);

	for (i = 0; (i < pkt_option_len) && (pkt_option_buffer[i] < BOOTP_OPTIONS_END); ) {

		curr_code = pkt_option_buffer[i];
		if ((i == 1) && (curr_code != DHCP_OPTION_MSG_TYPE))
			break;
		if (curr_code == BOOTP_OPTIONS_PAD) {
			i++;
			continue;
		}
		if (curr_code == DHCP_OPTION_OVERLOAD) {
			option_overload_opened = 1;
			break;
		}

		if (i + 2 >= pkt_option_len)
			break;
		i++;

		curr_option_len = pkt_option_buffer[i];
		if ((curr_code == DHCP_OPTION_MSG_TYPE) && (curr_option_len != 1))
			break;
		if ((curr_option_len == 0) || (curr_option_len > 128))
			break;

		if (i + curr_option_len >= pkt_option_len)
			break;

		if (curr_option_len > 0) {
			i++;
		}

		if (curr_code == option_code) {
			option_found = 1;

			if ((option_start != NULL) && (curr_option_len > 0))
				*option_start = &pkt_option_buffer[i];
			if (option_len != NULL)
				*option_len = curr_option_len;
			break;
		}

		i += curr_option_len;
	}

	return (option_found);
}

int process_bootpv4 (obj_t *obj, mblk_t *pkt_mb) {
	uchar_t *vp;
	uint32_t src_ip_i, dst_ip_i;
	ushort_t src_port;
	ushort_t dst_port;

	int pkt_len, ip_data_len, data_len, options_data_len;

	uint8_t ip_flags;
	uint8_t ip_frag_offset;
	uint8_t bootp_msg_type;
	uint8_t bootp_hw_type;
	uint8_t bootp_hw_len;
	uint32_t bootp_cookie;

	uchar_t *dhcp_option_start;
	uint8_t dhcp_option_len;

	uint8_t dhcp_msg_type;
	uint32_t dhcp_src_ipaddr_crc32;
	uint32_t dhcp_relay_agent_crc32;
	uint32_t dhcp_chaddr_crc32;

	char *pkt_hash_string;
	uint16_t pkt_hash_len;

	if ((obj == NULL) || (pkt_mb == NULL))
		return (0);

	obj -> main_stat -> total_pkts++;

	pkt_len = (int)MBLKL (pkt_mb);
	if (pkt_len <= IPV4_HDR_LEN + UDPV4_HDR_LEN) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}
	if (pkt_len > UDPV4_DGRAM_MAX_LEN) {
		obj -> main_stat -> invalid_udp_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN;
	if ((uintptr_t)vp % sizeof (ushort_t)) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_DATA_LEN_OFFSET;
	if ((uintptr_t)vp % sizeof (ushort_t)) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	ip_data_len = ntohs (*(ushort_t *)vp);
	if (ip_data_len != pkt_len) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_FLAGS_OFFSET;
	ip_flags = ntohs(*vp);
	if ((ip_flags != 0) && (ip_flags & ~IP_DF)) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> fragmented_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_FRAG_OFFSET_OFFSET;
	ip_frag_offset = *vp;
	if (ip_frag_offset != 0) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> fragmented_ip_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + UDPV4_DSTPORT_OFFSET;
	if ((uintptr_t)vp % sizeof (ushort_t)) {
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	dst_port = ntohs (*(ushort_t *)vp);
	if (dst_port != BOOTP_DEFAULT_SERVER_PORT)
		goto alien_pkt;

	if ((pkt_len < DHCP_MIN_PKTLEN) ||
	    (pkt_len > DHCP_MAX_PKTLEN)) {
		if (pkt_len < DHCP_MIN_PKTLEN)
		    obj -> main_stat -> underrun_pkts++;
		else
		    obj -> main_stat -> overrun_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_DSTADDR_OFFSET;
	if ((uintptr_t)vp % sizeof (uint32_t)) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	dst_ip_i = ntohl (*(uint32_t *)vp);

	vp = pkt_mb -> b_rptr + IPV4_SRCADDR_OFFSET;
	if ((uintptr_t)vp % sizeof (uint32_t)) {
		obj -> main_stat -> invalid_ip_pkts++;
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	src_ip_i = ntohl (*(uint32_t *)vp);

	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + UDPV4_DATA_LEN_OFFSET;
	if ((uintptr_t)vp % sizeof (ushort_t)) {
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	data_len = ntohs (*(ushort_t *)vp);
	if (data_len + IPV4_HDR_LEN != pkt_len) {
		obj -> main_stat -> invalid_udp_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	if ((data_len < DHCP_NONUDP_PKTLEN) ||
	    (data_len > DHCP_MAX_PKTLEN - IPV4_HDR_LEN - UDPV4_HDR_LEN)) { /* first condition of RFC1542 */
		obj -> main_stat -> invalid_bootp_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}
	options_data_len = data_len - BOOTP_OPTIONS_OFFSET;
	if ((options_data_len < DHCP_OPTION_MSG_TYPE_LEN + DHCP_OPTIONS_END_LEN) ||
	    (options_data_len > DHCP_OPTIONS_MAX_PKTLEN)) {
		obj -> main_stat -> invalid_bootp_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	bootp_msg_type = *(pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_MSG_OFFSET);
	if ((bootp_msg_type != BOOTP_REQUEST) && (bootp_msg_type != BOOTP_REPLY)) { /* second condition of RFC1542 */
		obj -> main_stat -> nondef_bootp_msg_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_COOKIE_OFFSET;
	if ((uintptr_t)vp % sizeof (uint32_t)) {
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	bootp_cookie = ntohl (*(uint32_t *)vp);
	if (bootp_cookie != BOOTP_COOKIE_VALUE) {
		obj -> main_stat -> nondef_cookie_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + UDPV4_SRCPORT_OFFSET;
	if ((uintptr_t)vp % sizeof (ushort_t)) {
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}
	src_port = ntohs (*(ushort_t *)vp);
	if ((src_port != BOOTP_DEFAULT_SERVER_PORT) &&
	    (src_port != BOOTP_DEFAULT_CLIENT_PORT)) {
		obj -> main_stat -> nondef_sport_pkts++;
		obj -> main_stat -> failed_pkts++;
		goto drop_pkt;
	}

	bootp_hw_type = *(pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_HWTYPE_OFFSET);
	if (bootp_hw_type != BOOTP_HW_ETHER) {
		obj -> main_stat -> nonsupp_bootp_hw_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	bootp_hw_len = *(pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_HWLEN_OFFSET);
	if (bootp_hw_len != BOOTP_HW_ETHER_LEN) {
		obj -> main_stat -> nonsupp_bootp_hw_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	dhcp_msg_type = 0;

	dhcp_option_start = NULL;
	dhcp_option_len = 0;
	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_OPTIONS_OFFSET;
	if (*vp == DHCP_OPTION_MSG_TYPE) {
		dhcp_option_len = *(vp + 1);
		if (dhcp_option_len == 1) {
			dhcp_msg_type = *(vp + 2);
			if ((dhcp_msg_type > 0) && (dhcp_msg_type <= DHCP_MSG_TYPES)) {
				;
			} else {
				dhcp_msg_type = 0;
			}
		}
	}
	 /* malformed BOOTP packet */
	if (dhcp_msg_type == 0) {
		obj -> main_stat -> nonsupp_dhcp_msg_pkts++;
		obj -> main_stat -> total_malformed_pkts++;
		goto drop_pkt;
	}

	/* CUSTOM: don't stop DHCPINFORM traffic in directly connected VLAN
	 * You probably should comment this.
	 */
	if ((dhcp_msg_type == DHCP_INFORM) &&
	    (*(pkt_mb -> b_rptr + IPV4_SRCADDR_OFFSET) == *(pkt_mb -> b_rptr + IPV4_DSTADDR_OFFSET)) &&
	    (*(pkt_mb -> b_rptr + IPV4_SRCADDR_OFFSET + 1) == *(pkt_mb -> b_rptr + IPV4_DSTADDR_OFFSET + 1)) &&
	    (*(pkt_mb -> b_rptr + IPV4_SRCADDR_OFFSET + 2) == *(pkt_mb -> b_rptr + IPV4_DSTADDR_OFFSET + 2)))
		goto pass_pkt;

	dhcp_src_ipaddr_crc32 = 0;
	vp = pkt_mb -> b_rptr + IPV4_SRCADDR_OFFSET;
	if (!calc_crc32_for_buffer (&dhcp_src_ipaddr_crc32, obj, vp, 4, KM_NOSLEEP))
		goto skip_pkt;

	dhcp_relay_agent_crc32 = 0;

	dhcp_option_start = NULL;
	dhcp_option_len = 0;
	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_OPTIONS_OFFSET;
	if (parse_bootp_option (DHCP_OPTION_RELAY_AGENT,
				vp, options_data_len, obj,
				&dhcp_option_start, &dhcp_option_len, KM_NOSLEEP) && (dhcp_option_len > 0)) {
		if (!calc_crc32_for_buffer (&dhcp_relay_agent_crc32, obj, dhcp_option_start, dhcp_option_len, KM_NOSLEEP))
			goto skip_pkt;
	} else {
		obj -> main_stat -> no_option82_pkts++;
	}

	dhcp_chaddr_crc32 = 0;
	vp = pkt_mb -> b_rptr + IPV4_HDR_LEN + BOOTP_CHADDR_OFFSET;
	if (!calc_crc32_for_buffer (&dhcp_chaddr_crc32, obj, vp, BOOTP_HW_ETHER_LEN, KM_NOSLEEP))
		goto skip_pkt;

	pkt_hash_len = 0;
	pkt_hash_string = (char *) fill_pkt_hash_string (&pkt_hash_len, obj, dhcp_src_ipaddr_crc32, dhcp_relay_agent_crc32, dhcp_chaddr_crc32, KM_NOSLEEP);
	if ((pkt_hash_string == NULL) || (pkt_hash_len == 0))
		goto skip_pkt;

	switch (process_pkt_rate (obj, dhcp_msg_type, dhcp_relay_agent_crc32, pkt_hash_string, pkt_hash_len)) {
		case 0:
			goto drop_pkt;
		case 1:
			goto skip_pkt;
		case 2:
			break;
		default:
			goto skip_pkt;
	}

    pass_pkt:
	obj -> main_stat -> passed_pkts++;
	return (2);
    skip_pkt:
	obj -> main_stat -> passed_pkts++;
	return (1);
    alien_pkt:
	return (1);
    drop_pkt:
	obj -> main_stat -> dropped_pkts++;
	return (0);
}
