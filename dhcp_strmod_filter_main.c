/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

/*
 * DHCPMOD module
 */

#include "dhcp_module.h"

static struct module_info rminfo = {
	0x322,		   /* mi_idnum */
	MODULE_SHORT_NAME, /* mi_idname */
	0, 		   /* mi_minpsz */
	INFPSZ, 	   /* mi_maxpsz */
	0, 		   /* mi_hiwat */
	0 		   /* mi_lowat */
};

static int mstrmod_open(queue_t *q, dev_t *devp, int oflag, int sflag, 
	cred_t *credp);
static int mstrmod_wput(queue_t *q, mblk_t *mp);
static int mstrmod_rput(queue_t *q, mblk_t *mp);
static int mstrmod_close(queue_t *q, int flag, cred_t *credp);

static struct qinit mstrmod_rinit = {
 	(int (*)())mstrmod_rput,/* qi_putp */
 	NULL,			/* qi_srvp */
 	mstrmod_open,		/* qi_qopen */
 	mstrmod_close,		/* qi_qclose */
 	NULL,			/* qi_qadmin */
 	&rminfo,		/* qi_minfo */
 	NULL			/* qi_mstat */
};

static struct qinit mstrmod_winit = {
 	(int (*)())mstrmod_wput,/* qi_putp */
 	NULL,			/* qi_srvp */
 	NULL,			/* qi_qopen */
 	NULL,			/* qi_qclose */
 	NULL,			/* qi_qadmin */
 	&rminfo,		/* qi_minfo */
 	NULL			/* qi_mstat */
};

struct streamtab mstrmod_info = {
	&mstrmod_rinit,
	&mstrmod_winit,
	NULL,
	NULL, 
};

static struct fmodsw mstrmod_fsw = {
        MODULE_SHORT_NAME,
        &mstrmod_info,
//        D_NEW | D_MP | D_MTPERMOD
        D_MTQPAIR | D_MP
};

extern struct mod_ops mod_strmodops;

static struct modlstrmod mmodldrv = {
        &mod_strmodops,
	MODULE_VERSION_TEXT,
	&mstrmod_fsw
};


static struct modlinkage mmodlinkage = {
	MODREV_1,
	{&mmodldrv, NULL}            /* ml_linkage */
	
};

static void *statep;
static int sim_queues_count;
kmutex_t mmod_lock;

/*
 * Module initialization/deinitialization routines.
 */

int
_init (void)
{
	int error;

	error = ddi_soft_state_init (&statep, sizeof (obj_t), 0);
	if (error != DDI_SUCCESS) {
		return error;
	}
 
	mutex_init (&mmod_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter (&mmod_lock);
	sim_queues_count = 0;
	bootp_init ();
	mutex_exit (&mmod_lock);

	error = mod_install (&mmodlinkage);
	if (error != DDI_SUCCESS) {
		mutex_destroy (&mmod_lock);
		ddi_soft_state_fini (&statep);
	}
	return error;
}

int
_info (struct modinfo *modinfop)
{
	return mod_info (&mmodlinkage, modinfop);
}

int
_fini (void)
{
	int error;

	error = mod_remove (&mmodlinkage);
	if (error == DDI_SUCCESS) {
		mutex_destroy (&mmod_lock);
		ddi_soft_state_fini (&statep);
	}
	return error;
}

static int mstrmod_ioctl (queue_t *q, obj_t *obj, mblk_t *mp)
{
     	struct iocblk *iocp;
	uint_t chunk;
	int ioc_error = EINVAL;

 	iocp = (struct iocblk *) mp -> b_rptr;

	mutex_enter (&obj -> lock);
 	switch (iocp -> ioc_cmd) {
		case DHCPIOCSDROPANYPPM:
		case DHCPIOCSDROPPOLIFNORA:
		case DHCPIOCSDROPNORAPPM:
		case DHCPIOCSDROPPOLALLNORA:
		case DHCPIOCSDROPPOLBYPPM:
			if ((mp -> b_cont == NULL) ||
			    (mp -> b_rptr == NULL) ||
			    (mp -> b_wptr == NULL) ||
			    (miocpullup (mp, sizeof (uint_t)) != 0))
				goto ioc_nak;
			chunk = *(uint_t *)mp -> b_cont -> b_rptr;
			if (iocp -> ioc_cmd == DHCPIOCSDROPANYPPM) {
				if ((chunk < 2) || (chunk > 100)) {
					ioc_error = ERANGE;
					goto ioc_nak;
				}
				obj -> default_allowed_packets_per_min = chunk;
			} else if (iocp -> ioc_cmd == DHCPIOCSDROPNORAPPM) {
				if ((chunk < 2) || (chunk > 100)) {
					ioc_error = ERANGE;
					goto ioc_nak;
				}
				obj -> default_allowed_no_ra_packets_per_min = chunk;
			} else if (iocp -> ioc_cmd == DHCPIOCSDROPPOLIFNORA) {
				if ((chunk != 0) && (chunk != 1)) {
					ioc_error = ERANGE;
					goto ioc_nak;
				}
				obj -> default_drop_policy_if_no_ra = chunk;
			} else if (iocp -> ioc_cmd == DHCPIOCSDROPPOLALLNORA) {
				if ((chunk != 0) && (chunk != 1)) {
					ioc_error = ERANGE;
					goto ioc_nak;
				}
				obj -> default_drop_policy_all_if_no_ra = chunk;
			} else if (iocp -> ioc_cmd == DHCPIOCSDROPPOLBYPPM) {
				if ((chunk != 0) && (chunk != 1)) {
					ioc_error = ERANGE;
					goto ioc_nak;
				}
				if (chunk == 0)
					obj -> default_drop_policy_by_ppm = 0;
				else
					obj -> default_drop_policy_by_ppm = 255;
			}
						
			mutex_exit (&obj -> lock);
			miocack (q, mp, 0, 0);
			return 1;
		default:
			break;
	}
	mutex_exit (&obj -> lock);
	
	return 0;
    ioc_nak:
	/* obj -> lock is always entered */
	mutex_exit (&obj -> lock);
	miocnak (q, mp, 0, ioc_error);
	return -1;
}

static void expired_queue_cleanup (void *arg)
{
 	obj_t *obj = (obj_t *)arg;
 	queue_t	*q;
	int instance_id;

	mutex_enter (&mmod_lock);
	if (obj == NULL) {
		mutex_exit (&mmod_lock);
		return;
	}
	instance_id = obj -> instance_id;

	obj = ddi_get_soft_state (statep, instance_id);
	if (obj == NULL) {
		mutex_exit (&mmod_lock);
        	return;
	}
	if (obj -> state != MODULE_INSTANCE_STATE_RUNNING) {
		mutex_exit (&mmod_lock);
        	return;
	}
	mutex_exit (&mmod_lock);

	mutex_enter (&obj -> lock);
	if (obj -> rq == NULL) {
		mutex_exit (&obj -> lock);
		return;
	}

 	q = obj -> rq;

	if (obj -> expire_queue != 0) {
		quntimeout (q, obj -> expire_queue);
 		obj -> expire_queue = 0;
		/* Timeout has fired */
	}

 	if (putctl (q, M_CTL) == 0)	/* Failure */
		obj -> expire_queue = qtimeout (q, expired_queue_cleanup,
			    (caddr_t)obj, default_expire_queue_time_period_in_ticks);
	mutex_exit (&obj -> lock);
}

static int
mstrmod_open (queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	obj_t *obj;

	if (q == NULL)
		return EINVAL;
	if (sflag != MODOPEN)
		return EIO;
	if (q -> q_ptr != NULL)	/* Already open */
		return EBUSY;

	mutex_enter (&mmod_lock);
	sim_queues_count++;
	if (ddi_soft_state_zalloc (statep, sim_queues_count) == DDI_FAILURE) {
		mutex_exit (&mmod_lock);
		return ENOMEM;
	}
	obj = ddi_get_soft_state (statep, sim_queues_count);
	if (obj == NULL) {
		mutex_exit (&mmod_lock);
        	return ENXIO;
	}
	bzero (obj, sizeof (obj_t));
	obj -> state = MODULE_INSTANCE_STATE_INITIALIZED;

	mutex_init (&obj -> lock, NULL, MUTEX_DEFAULT, NULL);

	obj -> instance_id = sim_queues_count;

	bootp_start (obj, sim_queues_count);
	if (obj -> main_stat == NULL) {
		goto fail;
	}

	q -> q_ptr = (caddr_t)obj;
	WR (q) -> q_ptr = q -> q_ptr;

	obj -> rq = q;
	obj -> state = MODULE_INSTANCE_STATE_RUNNING;
	mutex_exit (&mmod_lock);

	qprocson (q);

	mutex_enter (&obj -> lock);
	if (obj -> expire_queue == 0)
		obj -> expire_queue = qtimeout (obj -> rq, expired_queue_cleanup,
			     (caddr_t)obj, default_expire_queue_time_period_in_ticks);
	mutex_exit (&obj -> lock);

	return 0;

    fail:
	/* mmod_lock is always entered */
	obj -> state = MODULE_INSTANCE_STATE_FAILED_TO_START;

	bootp_finish (obj);

	mutex_destroy (&obj -> lock);

	ddi_soft_state_free (statep, sim_queues_count);

	if (sim_queues_count > 0)
		sim_queues_count--;

	mutex_exit (&mmod_lock);

	return EIO;
}

static int
mstrmod_close (queue_t *q, int oflag, cred_t *credp)
{
	obj_t *obj;
	int instance_id;

	if (q == NULL)
		return EINVAL;
	if (q -> q_ptr == NULL)	/* Already closed */
		return EINVAL;

	mutex_enter (&mmod_lock);
	obj = (obj_t *)q -> q_ptr;
	if (obj == NULL) {
		mutex_exit (&mmod_lock);
        	return EINVAL;
	}
	instance_id = obj -> instance_id;

	obj = ddi_get_soft_state (statep, instance_id);
	if (obj == NULL) {
		mutex_exit (&mmod_lock);
        	return ENXIO;
	}
	if (obj -> state != MODULE_INSTANCE_STATE_RUNNING) {
		mutex_exit (&mmod_lock);
        	return EBUSY;
	}
	obj -> state = MODULE_INSTANCE_STATE_STOPPED;

	qprocsoff (q);

	mutex_enter (&obj -> lock);
	if (obj -> expire_queue != 0) {
		quntimeout (obj -> rq, obj -> expire_queue);
		obj -> expire_queue = 0;
	}
	mutex_exit (&obj -> lock);

	bootp_finish (obj);

	mutex_destroy (&obj -> lock);

	if (sim_queues_count > 0)
		sim_queues_count--;

	ddi_soft_state_free (statep, instance_id);
	q -> q_ptr = WR (q) -> q_ptr = NULL;
	mutex_exit (&mmod_lock);

	return 0;
}
				       
static int
mstrmod_rput (queue_t *q, mblk_t *mps)
{
	obj_t *obj;
	int instance_id;
	mblk_t *mp, *mpp, *mpbc = NULL;
	uint8_t action = 0;
	uint16_t ip_hdr_len;
	int min_msg_len, msg_len;
	uint8_t ipproto;

	mutex_enter (&mmod_lock);
	obj = (obj_t *)q -> q_ptr;
	if (obj == NULL) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	instance_id = obj -> instance_id;

	obj = ddi_get_soft_state (statep, instance_id);
	if (obj == NULL) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	if (obj -> state != MODULE_INSTANCE_STATE_RUNNING) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	mutex_exit (&mmod_lock);

	if (mps == NULL)
		return 0;
	mpp = mp = mps;

	if (mp -> b_datap == NULL)
		goto drop_pkt;

	if ((mp -> b_datap -> db_type != M_PROTO) &&
	    (mp -> b_datap -> db_type != M_DATA)) {
		if ((mp -> b_datap -> db_type == M_CTL) &&
		    (MBLKL (mp) == 0)) {
			mutex_enter (&obj -> lock);
			process_expired_queued_cpkts (obj);
			if (obj -> expire_queue == 0)
				obj -> expire_queue = qtimeout (obj -> rq, expired_queue_cleanup,
					     (caddr_t)obj, default_expire_queue_time_period_in_ticks);
			mutex_exit (&obj -> lock);
			goto drop_pkt;
		}
		goto ok_pkt;
	}

	for (; mp && mp -> b_datap && (mp -> b_datap -> db_type == M_PROTO); mp = mp -> b_cont)
		;
	if (mp == NULL)
		goto ok_pkt;

	min_msg_len = IPV4_HDR_LEN + BOOTP_OPTIONS_OFFSET + DHCP_OPTION_MSG_TYPE_LEN + DHCP_OPTIONS_END_LEN;
        if (mp -> b_cont && (MBLKL (mp -> b_cont) < min_msg_len)) {
		msg_len = msgdsize (mp -> b_cont);
		if (msg_len == 0)
			    goto drop_pkt;
		mpbc = msgpullup (mp -> b_cont, MIN (min_msg_len, msg_len));
		if (mpbc == NULL)
			    goto drop_pkt;
		freemsg (mp -> b_cont);
		mp -> b_cont = mpbc;
		mp = mp -> b_cont;
	}

	if ((DB_REF (mp) == 0) || (mp -> b_datap == NULL) ||
	    (mp -> b_wptr == NULL) || (mp -> b_rptr == NULL) ||
	    (mp -> b_rptr < mp -> b_datap -> db_base) || (mp -> b_rptr > mp -> b_datap -> db_lim) ||
	    (mp -> b_wptr < mp -> b_datap -> db_base) || (mp -> b_wptr > mp -> b_datap -> db_lim) ||
	    (mp -> b_wptr <= mp -> b_rptr) ||
	    ((int)MBLKL(mp) <= 0))
		goto drop_pkt;

	/*
    	 * Alignment verification
	 */
	if ((uintptr_t)mp -> b_rptr & (sizeof (ushort_t) - 1)) {
		goto drop_pkt;
	}

	if ((mp -> b_datap -> db_type != M_DATA) ||
	    (MBLKL (mp) < IPV4_HDR_LEN + UDPV4_HDR_LEN) ||
	    ((*mp -> b_rptr & 0xF0) != 0x40))
		goto drop_pkt;

	ip_hdr_len = (*mp -> b_rptr & 0x0F) * 4; /* IPv4 header size */
	if (ip_hdr_len != IPV4_HDR_LEN)
		goto drop_pkt;

	ipproto = *(mp -> b_rptr + IP_PROTO_OFFSET);
	if (ipproto != IPPROTO_UDP)
		goto drop_pkt;

	mutex_enter (&obj -> lock);
	action = process_bootpv4 (obj, mp);
	mutex_exit (&obj -> lock);
	if (!action)
		goto drop_pkt;
	if (action == 1)
		goto ok_pkt;

    ok_pkt:
	putnext (q, mpp);
	return 0;
    drop_pkt:
	freemsg (mpp);
	return 0;
}

static int
mstrmod_wput (queue_t *q, mblk_t *mps)
{
	obj_t *obj;
 	struct copyresp *rp;
	int instance_id;

	if (q -> q_ptr == NULL) {
		if (mps != NULL)
			freemsg (mps);
		return 0;
	}

	if (mps == NULL)
		return 0;

	mutex_enter (&mmod_lock);
	obj = (obj_t *)q -> q_ptr;
	if (obj == NULL) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	instance_id = obj -> instance_id;

	obj = ddi_get_soft_state (statep, instance_id);
	if (obj == NULL) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	if (obj -> state != MODULE_INSTANCE_STATE_RUNNING) {
		if (mps != NULL)
			freemsg (mps);
		mutex_exit (&mmod_lock);
        	return 0;
	}
	mutex_exit (&mmod_lock);

	switch (mps -> b_datap -> db_type) {
 		case M_IOCTL:
 			if (mstrmod_ioctl (q, obj, mps) == 0)
				putnext (q, mps);
			break;
		case M_IOCDATA:
 			rp = (struct copyresp *) mps -> b_rptr;
 			if (rp -> cp_rval) {
 				/*
 				 * Failure.
 				 */
 				freemsg (mps);
 				break;
 			}

 			switch (rp -> cp_cmd) {
				case DHCPIOCSDROPANYPPM:
				case DHCPIOCSDROPPOLIFNORA:
				case DHCPIOCSDROPNORAPPM:
				case DHCPIOCSDROPPOLALLNORA:
				case DHCPIOCSDROPPOLBYPPM:
 					if (mstrmod_ioctl (q, obj, mps) == 0)
						putnext (q, mps);
					break;
				default:
					putnext (q, mps);
					break;
			}
			break;
		default:
			putnext (q, mps);
			break;
	}

	return 0;
}
