/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

/*
 * Kstat routines
 */

#include "dhcp_module.h"

int obj_kstat_update (kstat_t *ksp, int flag)
{
	obj_t *obj;
	obj_stat_named_t *sp;
        obj_kstat_named_t	*skp;
	    
	if (ksp == NULL)
		return EIO;
	
	sp = (obj_stat_named_t *)(uintptr_t)ksp -> ks_private;
	if (sp == NULL)
		return EIO;

	obj = sp -> obj;
	if (obj == NULL)
		return EIO;
	mutex_enter (&obj -> lock);

	skp = (obj_kstat_named_t *)(uintptr_t)ksp -> ks_data;
	if (skp == NULL) {
		mutex_exit (&obj -> lock);
		return EIO;
	}

	if (flag == KSTAT_WRITE) {
		sp -> total_pkts = skp -> total_pkts.value.ui64;
		sp -> last_total_pkts = skp -> total_pkts.value.ui64;
		sp -> passed_pkts = skp -> passed_pkts.value.ui64;
		sp -> last_passed_pkts = skp -> passed_pkts.value.ui64;
		sp -> dropped_pkts = skp -> dropped_pkts.value.ui64;
		sp -> last_dropped_pkts = skp -> dropped_pkts.value.ui64;
		sp -> rate_dropped_pkts = skp -> rate_dropped_pkts.value.ui64;
		sp -> failed_pkts = skp -> failed_pkts.value.ui64;
		sp -> total_malformed_pkts = skp -> total_malformed_pkts.value.ui64;
		sp -> invalid_ip_pkts = skp -> invalid_ip_pkts.value.ui64;
		sp -> invalid_udp_pkts = skp -> invalid_udp_pkts.value.ui64;
		sp -> invalid_bootp_pkts = skp -> invalid_bootp_pkts.value.ui64;
		sp -> fragmented_ip_pkts = skp -> fragmented_ip_pkts.value.ui64;
		sp -> underrun_pkts = skp -> underrun_pkts.value.ui64;
		sp -> overrun_pkts = skp -> overrun_pkts.value.ui64;
		sp -> nondef_dport_pkts = skp -> nondef_dport_pkts.value.ui64;
		sp -> nondef_sport_pkts = skp -> nondef_sport_pkts.value.ui64;
		sp -> nondef_cookie_pkts = skp -> nondef_cookie_pkts.value.ui64;
		sp -> nondef_bootp_msg_pkts = skp -> nondef_bootp_msg_pkts.value.ui64;
		sp -> nonsupp_bootp_hw_pkts = skp -> nonsupp_bootp_hw_pkts.value.ui64;
		sp -> nonsupp_dhcp_msg_pkts = skp -> nonsupp_dhcp_msg_pkts.value.ui64;
		sp -> no_option82_pkts = skp -> no_option82_pkts.value.ui64;
		sp -> nomem_errors = skp -> nomem_errors.value.ui64;
		sp -> buffer_errors = skp -> buffer_errors.value.ui64;
		sp -> cache_hits = skp -> cache_hits.value.ui64;
		sp -> cache_misses = skp -> cache_misses.value.ui64;
		sp -> cache_errors = skp -> cache_errors.value.ui64;
		sp -> cache_expired = skp -> cache_expired.value.ui64;
		sp -> cache_allocated = 0;
		sp -> cache_records = 0;

		mutex_exit (&obj -> lock);
		return 0;
	}

	if (flag == KSTAT_READ) {
		switch (obj -> state) {
			case MODULE_INSTANCE_STATE_RUNNING:
				skp -> state.value.ui32 = MODULE_INSTANCE_STATE_RUNNING;
				break;
			case MODULE_INSTANCE_STATE_STOPPED:
				skp -> state.value.ui32 = MODULE_INSTANCE_STATE_STOPPED;
				break;
			case MODULE_INSTANCE_STATE_FAILED_TO_START:
				skp -> state.value.ui32 = MODULE_INSTANCE_STATE_FAILED_TO_START;
				break;
			case MODULE_INSTANCE_STATE_INITIALIZED:
			default:
				skp -> state.value.ui32 = MODULE_INSTANCE_STATE_INITIALIZED;
				break;
		}
		skp -> total_pkts.value.ui64 = sp -> total_pkts;
		skp -> total_pkts_per_sec.value.ui64 = (sp -> total_pkts > sp -> last_total_pkts) ?
		     sp -> total_pkts - sp -> last_total_pkts : 0;
		skp -> passed_pkts.value.ui64 = sp -> passed_pkts;
		skp -> passed_pkts_per_sec.value.ui64 = (sp -> passed_pkts > sp -> last_passed_pkts) ?
		     sp -> passed_pkts - sp -> last_passed_pkts : 0;
		skp -> dropped_pkts.value.ui64 = sp -> dropped_pkts;
		skp -> dropped_pkts_per_sec.value.ui64 = (sp -> dropped_pkts > sp -> last_dropped_pkts) ?
		     sp -> dropped_pkts - sp -> last_dropped_pkts : 0;
		skp -> rate_dropped_pkts.value.ui64 = sp -> rate_dropped_pkts;
		skp -> failed_pkts.value.ui64 = sp -> failed_pkts;
		skp -> total_malformed_pkts.value.ui64 = sp -> total_malformed_pkts;
		skp -> invalid_ip_pkts.value.ui64 = sp -> invalid_ip_pkts;
		skp -> invalid_udp_pkts.value.ui64 = sp -> invalid_udp_pkts;
		skp -> invalid_bootp_pkts.value.ui64 = sp -> invalid_bootp_pkts;
		skp -> fragmented_ip_pkts.value.ui64 = sp -> fragmented_ip_pkts;
		skp -> underrun_pkts.value.ui64 = sp -> underrun_pkts;
		skp -> overrun_pkts.value.ui64 = sp -> overrun_pkts;
		skp -> nondef_dport_pkts.value.ui64 = sp -> nondef_dport_pkts;
		skp -> nondef_sport_pkts.value.ui64 = sp -> nondef_sport_pkts;
		skp -> nondef_cookie_pkts.value.ui64 = sp -> nondef_cookie_pkts;
		skp -> nondef_bootp_msg_pkts.value.ui64 = sp -> nondef_bootp_msg_pkts;
		skp -> nonsupp_bootp_hw_pkts.value.ui64 = sp -> nonsupp_bootp_hw_pkts;
		skp -> nonsupp_dhcp_msg_pkts.value.ui64 = sp -> nonsupp_dhcp_msg_pkts;
		skp -> no_option82_pkts.value.ui64 = sp -> no_option82_pkts;
		skp -> nomem_errors.value.ui64 = sp -> nomem_errors;
		skp -> buffer_errors.value.ui64 = sp -> buffer_errors;
		skp -> cache_hits.value.ui64 = sp -> cache_hits;
		skp -> cache_misses.value.ui64 = sp -> cache_misses;
		skp -> cache_errors.value.ui64 = sp -> cache_errors;
		skp -> cache_expired.value.ui64 = sp -> cache_expired;
		skp -> cache_allocated.value.ui64 = sp -> cache_allocated;
		skp -> cache_records.value.ui64 = sp -> cache_records;

		mutex_exit (&obj -> lock);
		return (0);
	}

	mutex_exit (&obj -> lock);
	return 0;
}

void obj_kstat_init (obj_t *obj, int instance_id)
{
	kstat_t		*ksp;
	obj_kstat_named_t	*skp;
	int kstat_create_attempts = 0;
	int allocated;

	if (obj == NULL)
		return;

    retry_ks_creation:
	mutex_enter (&obj -> lock);

	if (obj -> main_stat == NULL) {
		allocated = sizeof (obj_stat_named_t);
		obj -> main_stat = (obj_stat_named_t *) kmem_alloc (allocated, KM_SLEEP);
		if (obj -> main_stat == NULL) {
			mutex_exit (&obj -> lock);
			return;
		}
		bzero (obj -> main_stat, allocated);
		obj -> main_stat -> allocated = allocated;
		obj -> main_stat -> obj = obj;
	}

	if (obj -> main_ksp != NULL) {
		mutex_exit (&obj -> lock);
		return;
	}

	ksp = kstat_create (MODULE_NAME, instance_id,
			    "inbound", "net", KSTAT_TYPE_NAMED,
			    sizeof (obj_kstat_named_t) / sizeof (kstat_named_t),
				    KSTAT_FLAG_PERSISTENT);
	kstat_create_attempts++;
	if (ksp == NULL) {
		mutex_exit (&obj -> lock);
#if defined kstat_delete_persistent
		ksp = kstat_hold_byname (MODULE_NAME, instance_id, "inbound", ALL_ZONES);
		if (ksp != NULL) {
			kstat_rele (ksp);
			kstat_delete_persistent (ksp);
			ksp = NULL;
		}
#else
		kstat_delete_byname (MODULE_NAME, instance_id, "inbound");
#endif
		if (kstat_create_attempts == 1)
			goto retry_ks_creation;
		cmn_err (CE_WARN, "instance ID %d: KSTAT structures will be available after reboot", instance_id);
		return;
	}
	
	if (ksp -> ks_data == NULL) {
		mutex_exit (&obj -> lock);
		kstat_delete (ksp);
		return;
	}
	skp = (obj_kstat_named_t *)(uintptr_t)(ksp -> ks_data);

        kstat_named_init (&skp -> state, "state",
		     KSTAT_DATA_UINT32);
        kstat_named_init (&skp -> total_pkts, "input packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> total_pkts_per_sec, "input packets per sec",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> passed_pkts, "passed packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> passed_pkts_per_sec, "passed packets per sec",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> dropped_pkts, "discarded packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> dropped_pkts_per_sec, "discarded packets per sec",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> rate_dropped_pkts, "discarded rate limit packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> failed_pkts, "failure packets",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> total_malformed_pkts, "malformed packets",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> invalid_ip_pkts, "invalid IP packets",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> invalid_udp_pkts, "invalid UDP packets",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> invalid_bootp_pkts, "invalid BOOTP packets",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> fragmented_ip_pkts, "fragmented IP packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> underrun_pkts, "underrun packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> overrun_pkts, "overrun packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nondef_dport_pkts, "non-def dest port packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nondef_sport_pkts, "non-def src port packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nondef_cookie_pkts, "non-def BOOTP cookie packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nondef_bootp_msg_pkts, "non-def BOOTP type packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nonsupp_bootp_hw_pkts, "non-support media type packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nonsupp_dhcp_msg_pkts, "non-support msg type packets",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> no_option82_pkts, "packets without DHCP Option 82",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> nomem_errors, "no memory errors",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> buffer_errors, "buffer errors",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> cache_hits, "cache hits",
		     KSTAT_DATA_UINT64);
	kstat_named_init (&skp -> cache_misses, "cache misses",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> cache_errors, "cache errors",
		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> cache_expired, "cache expired",
    		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> cache_allocated, "cache buckets",
    		     KSTAT_DATA_UINT64);
        kstat_named_init (&skp -> cache_records, "cache records",
    		     KSTAT_DATA_UINT64);

        ksp -> ks_update = obj_kstat_update;
        ksp -> ks_private = (void *)(uintptr_t)obj -> main_stat;

	/* Be aware of deadlocks: kstat_install() calls ks_update */
	mutex_exit (&obj -> lock);
        kstat_install (ksp);
	mutex_enter (&obj -> lock);

	obj -> main_ksp = ksp;
	mutex_exit (&obj -> lock);

        return;
}

void obj_kstat_fini (obj_t *obj)
{
	if (obj == NULL)
		return;

	mutex_enter (&obj -> lock);
	if (obj -> main_ksp != NULL) {
		mutex_exit (&obj -> lock);
		kstat_delete (obj -> main_ksp);
		mutex_enter (&obj -> lock);
		obj -> main_ksp = NULL;
	}

	if (obj -> main_stat != NULL) {
		kmem_free (obj -> main_stat, obj -> main_stat -> allocated);
		obj -> main_stat = NULL;
	}
	mutex_exit (&obj -> lock);
}

