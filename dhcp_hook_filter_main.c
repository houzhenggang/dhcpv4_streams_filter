/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

#include "dhcp_module.h"

net_instance_t *mmod_global;
kmutex_t	mmod_lock;
timeout_id_t	mmod_timeout;
int sim_inst_count;
int	mmod_registered = 0;
int	mmod_initialized = 0;
int	mmod_continue = 1;
char *mmod_level = NH_PHYSICAL_IN;
//char *mmod_level = NH_FORWARDING;

#if 0
dev_info_t *mmod_dev_info = NULL;

static int mmod_property_main_update (dev_info_t *);
static int mmod_attach (dev_info_t *, ddi_attach_cmd_t);
static int mmod_detach (dev_info_t *, ddi_detach_cmd_t);
static int mmod_getinfo (dev_info_t *, ddi_info_cmd_t, void *, void **);
#endif
static void mmod_expire (void *arg);
static void mmod_strfree (char *);
static char *mmod_strdup (char *, int);

static int mmod_ini (void);
static int mmod_fini (void);

static void *mmod_create (const netid_t id);
static void mmod_shutdown (const netid_t id, void *arg);
static void mmod_destroy (const netid_t id, void *arg);

static int mmod_new_proto (hook_notify_cmd_t cmd, void *arg,
    const char *parent, const char *event, const char *hook);
static int mmod_new_event (hook_notify_cmd_t cmd, void *arg,
    const char *parent, const char *hook, const char *event);
//    const char *parent, const char *event, const char *hook);
static int mmod_new_hook (hook_notify_cmd_t cmd, void *arg,
    const char *parent, const char *event, const char *hook);
static int mmod_new_packet (hook_event_token_t tok, hook_data_t data,
    void *ctx);

/*
 * Module linkage information for the kernel.
 */

#if 0
static struct dev_ops mmod_ops = {
    DEVO_REV,
    0,
    mmod_getinfo,
#if USE_SOLARIS10_OR_MORE
    nulldev,
#else
    mmod_identify,
#endif
    nulldev,
    mmod_attach,
    mmod_detach,
    nodev,		/* reset */
    (struct cb_ops *)0,
//    &mmod_cb_ops,
    (struct bus_ops *)0,
    NULL
};
#endif

extern struct mod_ops mod_driverops;
						    
static struct modldrv mmodldrv = {
	&mod_driverops,		/* drv_modops */
	MODULE_VERSION_TEXT,	/* drv_linkinfo */
//	&mmod_ops
	NULL
};

static struct modlinkage mmodlinkage = {
	MODREV_1,		/* ml_rev */
	{ (void *)&mmodldrv,		/* ml_linkage */
	NULL}
};


static void *mmod_alloc(size_t len, int wait)
{
//	int i;

//	mutex_enter(&mmod_lock);
//	mutex_exit(&mmod_lock);

	return kmem_alloc(len, wait);
}

static void mmod_free(void *ptr, size_t len)
{
//	int i;

//	mutex_enter(&mmod_lock);
//	mutex_exit(&mmod_lock);

	kmem_free(ptr, len);
}

static void mmod_strfree (char *str)
{
	int len;

	if (str != NULL) {
		len = strlen (str);
		mmod_free (str, len + 1);
		str = NULL;
	}
}

static char* mmod_strdup(char *str, int wait)
{
	char *newstr;
	int len;

	if (str == NULL)
		return (NULL);

	len = strlen (str);
	if (len < 1)
		return (NULL);

	newstr = mmod_alloc (len, wait);
	if (newstr != NULL)
		strcpy (newstr, str);

	return (newstr);
}

static void mmod_assert(obj_t *obj)
{
}

int
_init(void)
{
	int error;

	mutex_init (&mmod_lock, NULL, MUTEX_DRIVER, NULL);

	bootp_init ();

	error = mmod_ini();

	if (error == DDI_SUCCESS) {
		error = mod_install (&mmodlinkage);
		if (error != 0) {
			mutex_enter (&mmod_lock);
			mmod_fini();
			mutex_exit (&mmod_lock);
			cmn_err (CE_WARN,
				"init error: %d", error);
		}
	}

	mmod_timeout = NULL;
//	mmod_timeout = timeout (mmod_expire, NULL, drv_usectohz(500000));

	return (error);
}

int
_fini(void)
{
	int error;

	mmod_continue = 0;
	if (mmod_timeout != NULL) {
		untimeout (mmod_timeout);
		mmod_timeout = NULL;
	}

	error = mmod_fini ();
	if (error != 0) {
		return (error);
	}

	error = mod_remove (&mmodlinkage);
	if (error == 0) {
		delay (drv_usectohz(500000));	/* .5 seconds */

		mutex_destroy (&mmod_lock);

		ASSERT (mmod_initialized == 0);
	} else {
		cmn_err (CE_WARN,
			"fini error: %d", error);
	}

	return (error);
}

int _info (struct modinfo *modinfop)
{
	return (mod_info (&mmodlinkage, modinfop));
}

#if 0
static int mmod_property_main_update (dev_info_t *dip)
{
#ifdef DDI_NO_AUTODETACH
 	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
 				DDI_NO_AUTODETACH, 1) != DDI_PROP_SUCCESS) {
 		cmn_err(CE_WARN, "!updating DDI_NO_AUTODETACH failed");
 		return (DDI_FAILURE);
 	}
#else
 	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
 				"ddi-no-autodetach", 1) != DDI_PROP_SUCCESS) {
 		cmn_err(CE_WARN, "!updating ddi-no-autodetach failed");
 		return (DDI_FAILURE);
 	}
#endif
 
 	return (DDI_SUCCESS);
}
#endif					    
static int mmod_ini () {
	if (mmod_registered)
		return (DDI_FAILURE);

	mmod_global = net_instance_alloc (NETINFO_VERSION);
	if (mmod_global == NULL)
		return (DDI_FAILURE);

	mmod_global -> nin_create = mmod_create;
	mmod_global -> nin_shutdown = mmod_shutdown;
	mmod_global -> nin_destroy = mmod_destroy;
	mmod_global -> nin_name = mmod_strdup (MODULE_SHORT_NAME, KM_SLEEP);

	if (mmod_global -> nin_name == NULL) {
		mmod_fini ();
		return (DDI_FAILURE);
	}

	if (net_instance_register (mmod_global) != 0) {
		mmod_fini ();
		return (DDI_FAILURE);
	}
	mutex_enter (&mmod_lock);
	sim_inst_count = 0;
	bootp_init ();
	mmod_registered = 1;
	mutex_exit (&mmod_lock);

//	cmn_err (CE_WARN,
//		"v4:mmod_ini ok ");

	return (DDI_SUCCESS);
}

static int mmod_fini () {
	if (mmod_global != NULL) {
		if (mmod_registered) {
			if (net_instance_unregister (mmod_global) != 0)
				return (EBUSY);
			mutex_enter (&mmod_lock);
			mmod_registered = 0;
			mutex_exit (&mmod_lock);
		}
		if (mmod_global -> nin_name != NULL) {
			mmod_strfree (mmod_global -> nin_name);
			mmod_global -> nin_name = NULL;
		}
		net_instance_free (mmod_global);
		mmod_global = NULL;
//	cmn_err (CE_WARN,
//		"v4:mmod_fini ok ");
	}
	return (0);
}
#if 0
static int mmod_attach (dev_info_t *dip, ddi_attach_cmd_t cmd)
{
//	char *s;
//	int i;
//	int error;
	int instance;

	switch (cmd)
	{
	case DDI_ATTACH:
		instance = ddi_get_instance (dip);
		if (instance > 0)
			return (DDI_FAILURE);

		(void) mmod_property_main_update (dip);

/*
			if (ddi_create_minor_node(dip, s, S_IFCHR, i,
			    DDI_PSEUDO, 0) ==
			    DDI_FAILURE) {
				ddi_remove_minor_node(dip, NULL);
				goto attach_failed;
			}
*/

		mmod_dev_info = dip;

/*		mutex_enter (&mmod_lock);
		bootp_start ();
		mutex_exit (&mmod_lock);

		error = mmod_ini ();
		if (error != DDI_SUCCESS) {
			mmod_fini ();
			goto attach_failed;
		}*/

//		return (error);
		return (DDI_SUCCESS);
	default:
		break;
	}

//attach_failed:
	ddi_prop_remove_all (dip);
	return (DDI_FAILURE);
}


static int mmod_detach (dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i;
//	int error;

	switch (cmd) {
	case DDI_DETACH:
		ddi_prop_remove_all(dip);

		i = ddi_get_instance(dip);
//		ddi_remove_minor_node(dip, NULL);
		if (i > 0) {
			cmn_err(CE_CONT, "still attached (%d)\n", i);
			return (DDI_FAILURE);
		}

/*		error = mmod_fini ();
		if (error != 0)
			return (error);

		mutex_enter (&mmod_lock);
		bootp_finish ();
		mutex_exit (&mmod_lock);
*/
		return (DDI_SUCCESS);
	default:
		break;
	}
	cmn_err (CE_NOTE, "failed to detach");
	return (DDI_FAILURE);
}


#if !USE_SOLARIS10_OR_MORE
static int mmod_identify (dev_info_t *dip)
{
	char *name = ddi_get_name (dip);
 	if ((name != NULL) && (strcmp(ddi_get_name(dip), MODULE_SHORT_NAME) == 0))
 		return (DDI_IDENTIFIED);

 	return (DDI_NOT_IDENTIFIED);
}
#endif

static int mmod_getinfo (dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
    int error;
    
    error = DDI_FAILURE;
    switch (cmd) {
	    case DDI_INFO_DEVT2DEVINFO:
		    *result = mmod_dev_info;
		    error = DDI_SUCCESS;
		    break;
	    case DDI_INFO_DEVT2INSTANCE:
		    *result = (void *)0;
		    error = DDI_SUCCESS;
		    break;
	    default:
		    break;
	}
	return (error);
}
#endif
											    

static void mmod_expire (void *arg)
{

	if (!mmod_continue)
		return;

	mmod_fini();

	if (!mmod_continue)
		return;

	delay(drv_usectohz(5000));	/* .005 seconds */

	if (!mmod_continue)
		return;

	if (mmod_ini() == DDI_SUCCESS)
		mmod_timeout = timeout(mmod_expire, NULL,
		    drv_usectohz(5000));	/* .005 seconds */
}

static void expired_queue_cleanup (void *arg)
{
 	obj_t *obj = (obj_t *)arg;

	if (obj == NULL) {
		return;
	}

	mutex_enter (&obj -> lock);

	/* timeout has fired */
	if (obj -> expire_queue != 0) {
		untimeout (obj -> expire_queue);
 		obj -> expire_queue = 0;
	}

	obj -> expire_queue = timeout (expired_queue_cleanup,
		    (caddr_t)obj, default_expire_queue_time_period_in_ticks);

	process_expired_queued_cpkts (obj);

	mutex_exit (&obj -> lock);
}

static void *mmod_create (const netid_t id) {
	obj_t *obj;
	hook_t *h = NULL;
	char buffer[64];
	int allocated;
	
	allocated = sizeof (obj);
	obj = (obj_t *) kmem_alloc (allocated, KM_SLEEP);
	if (obj == NULL)
		return (NULL);

	bzero (obj, allocated);
	obj -> allocated = allocated;

	obj -> net_id = id;
	obj -> zone_id = net_getzoneidbynetid (id);

	mutex_init (&obj -> lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter (&obj -> lock);
	sim_inst_count++;
	obj -> instance_id = sim_inst_count;
	mutex_exit (&obj -> lock);

	bootp_start (obj, id);

	obj -> expire_queue = timeout (expired_queue_cleanup,
		    (caddr_t)obj, default_expire_queue_time_period_in_ticks);

	if (net_instance_notify_register (obj -> net_id, mmod_new_proto, obj) != 0) {
		goto failed;
	}

	obj -> instance_registered = 1;

	/* Solaris 10: if hook callback is still unregistered ... */
	if (!obj -> v4_hook_registered) {
		if (obj -> zone_id == GLOBAL_ZONEID)
			cmn_err (CE_NOTE,
				"Network protocol events aren't supported by underlying OS version");
		if (!obj -> v4_proto_registered) {
			obj -> v4_handle = net_protocol_lookup (obj -> net_id, NHF_INET);
		}
		if (obj -> v4_handle != NULL) {
			snprintf (buffer, sizeof (buffer) - 1, "%s_%d_%d_%s_%s", mmod_global -> nin_name,
				obj -> zone_id, obj -> net_id,
				"inet", mmod_level);
			h = hook_alloc (HOOK_VERSION);
			if (h == NULL) {
				goto failed;
			}
			h -> h_hint = HH_NONE;
			h -> h_hintvalue = 0;
			h -> h_arg = obj;
			h -> h_name = mmod_strdup (buffer, KM_SLEEP);
			if (h -> h_name == NULL) {
				goto failed;
			}
			h -> h_func = mmod_new_packet;
			h -> h_flags = 0;

			if ((obj -> v4_handle != NULL) &&
			    (net_hook_register (obj -> v4_handle, mmod_level, h) == 0)) {
				obj -> v4_hook_in = h;
				obj -> v4_hook_registered = 1;
				if (obj -> zone_id == GLOBAL_ZONEID)
					cmn_err (CE_CONT,
						"Hook %p registered (zone id %d, ip instance id %d) ",
						obj -> v4_hook_in, obj -> zone_id, obj -> net_id);
			} else {
				goto failed;
			}
		}
	}

	mmod_initialized++;

//	cmn_err (CE_WARN,
//		"v4:create ok %d", obj -> net_id);
	return (obj);
    failed:
	if (h != NULL) {
		if (h -> h_name != NULL) {
			    mmod_strfree (h -> h_name);
			    h -> h_name = NULL;
		}
		hook_free (h);
		h = NULL;
	}
	if (obj -> v4_handle != NULL) {
		net_protocol_release (obj -> v4_handle);
		obj -> v4_handle = NULL;
	}
	if (obj -> expire_queue != 0) {
		untimeout (obj -> expire_queue);
 		obj -> expire_queue = 0;
	}

	mutex_enter (&mmod_lock);
	if (sim_inst_count > 0)
	    sim_inst_count--;
	mutex_exit (&mmod_lock);

	mutex_destroy (&obj -> lock);
//	kmem_free (obj, sizeof (obj_t));
	kmem_free (obj, obj -> allocated);
	obj = NULL;
	return (NULL);
}

static void mmod_shutdown (const netid_t id, void *arg) {
	obj_t *obj = arg;

	if (obj == NULL)
		return;

//	mmod_add_do(__LINE__);

//	cmn_err (CE_WARN,
//		"v4:shutdown start ");
	if (obj -> instance_registered) {
		if (net_instance_notify_unregister (id, mmod_new_proto) != 0)
			return;
		obj -> instance_registered = 0;
	}

	if (obj -> v4_handle != NULL) {
		if (obj -> v4_event_registered) {
			 /* according to hook API event 
			  * should be unregistered before protocol
			  */
			if (net_event_notify_unregister (obj -> v4_handle, mmod_level,
							mmod_new_hook) != 0) {
				if (obj -> zone_id == GLOBAL_ZONEID)
					cmn_err (CE_WARN,
					        "net_event_notify_unregister(%p) failed (zone id %d, ip instance id %d)",
					        obj -> v4_handle, obj -> zone_id, obj -> net_id);
				return;
			} else {
				obj -> v4_event_registered = 0;
				if (obj -> zone_id == GLOBAL_ZONEID)
					cmn_err (CE_CONT,
						"Packet event for %p unregistered (zone id %d, ip instance id %d)",
						obj -> v4_handle, obj -> zone_id, obj -> net_id);
			}
		}
		if (obj -> v4_hook_in != NULL) {
			if (obj -> v4_hook_registered) { 
				if (net_hook_unregister (obj -> v4_handle, mmod_level,
						    obj -> v4_hook_in) != 0) {
					if (obj -> zone_id == GLOBAL_ZONEID)
						cmn_err (CE_WARN,
						"net_hook_unregister(%p) failed (zone id %d, ip instance id %d)",
						obj -> v4_handle, obj -> zone_id, obj -> net_id);
					return;
				} else {
					obj -> v4_hook_registered = 0;
					if (obj -> zone_id == GLOBAL_ZONEID)
						cmn_err (CE_CONT,
							"Hook %p unregistered (zone id %d, ip instance id %d) ",
							obj -> v4_hook_in, obj -> zone_id, obj -> net_id);
				}
			}
			if (obj -> v4_hook_in -> h_name != NULL) {
			    mmod_strfree (obj -> v4_hook_in -> h_name);
			    obj -> v4_hook_in -> h_name = NULL;
			}
			hook_free (obj -> v4_hook_in);
			obj -> v4_hook_in = NULL;
		}
		if (obj -> v4_proto_registered) {
			if (net_protocol_notify_unregister (obj -> v4_handle, mmod_new_event) != 0) {
				if (obj -> zone_id == GLOBAL_ZONEID)
					cmn_err (CE_WARN,
						"net_protocol_notify_unregister(%p) failed (zone id %d, ip instance id %d)",
						obj -> v4_handle, obj -> zone_id, obj -> net_id);
				return;
			} else {
				obj -> v4_proto_registered = 0;
				if (obj -> zone_id == GLOBAL_ZONEID)
					cmn_err (CE_CONT,
						"Protocol event %p unregistered (zone id %d, ip instance id %d) ",
						obj -> v4_handle, obj -> zone_id, obj -> net_id);
			}
		}
		if (net_protocol_release (obj -> v4_handle) != 0)
			return;
//	cmn_err (CE_WARN,
//		"v4:shutdown ok ");
		obj -> v4_handle = NULL;
	}
}

static void mmod_destroy (const netid_t id, void *arg) {
	obj_t *obj = arg;

	if (obj == NULL)
		return;

	mmod_assert (obj);

	ASSERT(obj -> v4_handle == NULL);
	ASSERT(obj -> v4_hook_in == NULL);

	if (obj -> expire_queue != 0) {
		untimeout (obj -> expire_queue);
 		obj -> expire_queue = 0;
	}

	mutex_enter (&mmod_lock);
	if (sim_inst_count > 0)
	    sim_inst_count--;
	mutex_exit (&mmod_lock);

	bootp_finish (obj);
//	cmn_err (CE_WARN,
//		"v4:destroy ok ");
	mutex_destroy (&obj -> lock);

//	kmem_free (obj, sizeof (obj_t));
	kmem_free (obj, obj -> allocated);

	ASSERT (mmod_initialized > 0);
	mmod_initialized--;
}

static int mmod_new_proto (hook_notify_cmd_t cmd, void *arg, const char *parent,
    const char *event, const char *hook) {
	obj_t *obj = arg;

//	cmn_err (CE_WARN,
//		"v4:mmod_new_proto start ");
	if (obj == NULL)
		return (0);

	obj -> event_notify++;

	mmod_assert(obj);

/*	cmn_err (CE_WARN,
		"v4:mmod_new_proto cmd %d, parent %s, event %s, hook %s (id=%d) ",
		cmd,
		(parent != NULL) ? parent : "<empty>",
		(event != NULL) ? event : "<empty>",
		(hook != NULL) ? hook : "<empty>",
		obj -> net_id);
*/
	switch (cmd) {
		case HN_REGISTER :
//		if (strcmp (parent, NHF_INET) == 0) {
			if ((hook != NULL) && (!strcmp (hook, "inet"))) {
				if (obj -> v4_proto_registered) {
					if (obj -> zone_id == GLOBAL_ZONEID)
						cmn_err (CE_WARN,
							"Protocol event already registered (zone id %d, ip instance id %d)",
							obj -> zone_id, obj -> net_id);
					return (0);
				}
				if (obj -> v4_handle == NULL) {
					obj -> v4_handle = net_protocol_lookup (obj -> net_id, NHF_INET);
					if (obj -> v4_handle == NULL) {
						if (obj -> zone_id == GLOBAL_ZONEID)
							cmn_err (CE_WARN,
								"Protocol lookup failed (zone id %d, ip instance id %d) ",
								obj -> zone_id, obj -> net_id);
						return (0);
					}
				}
//			    cmn_err (CE_WARN,
//				    "v4:proto lookup ok (%d) ",
//				    obj -> net_id);
				if (net_protocol_notify_register (obj -> v4_handle, mmod_new_event, obj) == 0)
					obj -> v4_proto_registered = 1;
				if (obj -> v4_proto_registered) {
					if (obj -> zone_id == GLOBAL_ZONEID)
						cmn_err (CE_CONT,
							"Protocol event %p registered (zone id %d, ip instance id %d) ",
							obj -> v4_handle, obj -> zone_id, obj -> net_id);
//			    return (1);
				} else {
					if (net_protocol_release (obj -> v4_handle) != 0)
						return (0);
					obj -> v4_handle = NULL;
				}
			}
			break;

		case HN_UNREGISTER :
		case HN_NONE :
			break;
	}

	return (0);
}

static int mmod_new_event (hook_notify_cmd_t cmd, void *arg, const char *parent,
    const char *hook, const char *event) {
//    const char *event, const char *hook) {
	obj_t *obj = arg;
	char buffer[32];
	hook_t *h;

	if (obj == NULL)
		return (0);

/*	cmn_err (CE_WARN,
		"v4:mmod_new_event cmd %d, parent %s, event %s, hook %s (id=%d) ",
		cmd,
		(parent != NULL) ? parent : "<empty>",
		(event != NULL) ? event : "<empty>",
		(hook != NULL) ? hook : "<empty>",
		obj -> net_id);*/
	mmod_assert (obj);

	switch (cmd) {
		case HN_REGISTER:
//			if (strcmp (parent, NHF_INET) == 0) {
			if ((parent != NULL) && (!strcmp (parent, "inet"))) {
				    if ((event != NULL) && (!strcmp (event, mmod_level))) {
						if (obj -> v4_hook_registered) {
							    if (obj -> zone_id == GLOBAL_ZONEID)
								    cmn_err (CE_WARN,
									    "Hook already registered (zone id %d, ip instance id %d) ",
									    obj -> zone_id, obj -> net_id);
							    return (0);
						}
						if (obj -> v4_hook_in != NULL) {
							    if (obj -> zone_id == GLOBAL_ZONEID)
								    cmn_err (CE_WARN,
									    "Hook %p already present (zone id %d, ip instance id %d) ",
									    obj -> v4_hook_in, obj -> zone_id, obj -> net_id);
							    return (0);
						}
						snprintf (buffer, sizeof (buffer) - 1, "%s_%s_%s", mmod_global -> nin_name, parent, event);
						h = hook_alloc (HOOK_VERSION);
						if (h == NULL)
							    return (0);
						h -> h_hint = HH_NONE;
						h -> h_hintvalue = 0;
						h -> h_arg = obj;
						h -> h_name = mmod_strdup (buffer, KM_SLEEP);
						if (h -> h_name == NULL) {
							    hook_free (h);
							    h = NULL;
							    return (0);
						}
						h -> h_func = mmod_new_packet;
						h -> h_flags = 0;

						if ((obj -> v4_handle != NULL) &&
						    (net_hook_register (obj -> v4_handle, (char *)event, h) == 0)) {
							    obj -> v4_hook_in = h;
							    obj -> v4_hook_registered = 1;
							    if (obj -> zone_id == GLOBAL_ZONEID)
								    cmn_err (CE_CONT,
									    "Hook %p registered (zone id %d, ip instance id %d) ",
									    obj -> v4_hook_in, obj -> zone_id, obj -> net_id);
						} else {
							    if (h -> h_name != NULL) {
									mmod_strfree (h -> h_name);
									h -> h_name = NULL;
							    }
							    hook_free (h);
							    h = NULL;
							    return (0);
						}

						obj -> v4_event_notify++;
						if (!obj -> v4_event_registered) {
							    if ((obj -> v4_handle != NULL) &&
								(net_event_notify_register (obj -> v4_handle, (char *)event,
											    mmod_new_hook, obj) == 0)) {
									obj -> v4_event_registered = 1;
									if (obj -> zone_id == GLOBAL_ZONEID)
										cmn_err (CE_CONT,
											"Packet event for %p registered (zone id %d, ip instance id %d) ",
											obj -> v4_hook_in, obj -> zone_id, obj -> net_id);
							    }
						}
				    }
			}
			break;
		case HN_UNREGISTER:
		case HN_NONE:
			break;
	}
	mmod_assert(obj);

	return (0);
}

static int mmod_new_hook(hook_notify_cmd_t cmd, void *arg, const char *parent,
    const char *event, const char *hook) {
	obj_t *obj = arg;

	if (obj == NULL)
		return (0);

	mmod_assert (obj);

/*	cmn_err (CE_WARN,
		"v4:new hook (%d) ",
		obj -> net_id);
*/
	if ((parent != NULL) && (!strcmp (parent, NHF_INET))) {
		obj -> v4_hook_notify++;

	}
	mmod_assert (obj);

	return (0);
}

static int mmod_new_packet (hook_event_token_t tok, hook_data_t data, void *ctx) {
	obj_t *obj = ctx;
	hook_pkt_event_t *pkt;
	mblk_t *pkt_mb;
	struct ip *ip;
	uint16_t ip_hdr_len;

	uint8_t action = 1;

	if (obj == NULL)
		return (0);

	pkt = (hook_pkt_event_t *)data;

	if (pkt == NULL)
		return (0);

	ip = (struct ip *)pkt -> hpe_hdr;

	if (ip == NULL)
		return (0);

	if (ip -> ip_v != 4)
		return (0);

	if (ip -> ip_p != IPPROTO_UDP)
//	if (ip -> ip_p != IPPROTO_UDP && ip -> ip_p != IPPROTO_TCP)
		return (0);

	pkt_mb = pkt -> hpe_mb;

	if (pkt_mb == NULL)
		return (0);

	if ((pkt_mb -> b_datap == NULL) ||
	    (pkt_mb -> b_wptr == NULL) || (pkt_mb -> b_rptr == NULL) ||
	    (pkt_mb -> b_rptr < pkt_mb -> b_datap -> db_base) || (pkt_mb -> b_rptr > pkt_mb -> b_datap -> db_lim) ||
	    (pkt_mb -> b_wptr < pkt_mb -> b_datap -> db_base) || (pkt_mb -> b_wptr > pkt_mb -> b_datap -> db_lim) ||
	    (pkt_mb -> b_wptr <= pkt_mb -> b_rptr) ||
	    ((int)MBLKL (pkt_mb) <= 0))
		return (0);
	/*
    	 * Alignment verification
	 */
	if ((uintptr_t)pkt_mb -> b_rptr & (sizeof (ushort_t) - 1)) {
		return (0);
	}

	if ((uintptr_t)pkt_mb -> b_wptr & (sizeof (ushort_t) - 1)) {
		return (0);
	}

	if ((pkt_mb -> b_datap -> db_type != M_DATA) ||
	    (MBLKL (pkt_mb) < IPV4_HDR_LEN + UDPV4_HDR_LEN) ||
	    ((*pkt_mb -> b_rptr & 0xF0) != 0x40))
		return (0);

	ip_hdr_len = (*pkt_mb -> b_rptr & 0x0F) * 4; /* IPv4 header size */
	if (ip_hdr_len != IPV4_HDR_LEN)
		return (0);
//	if (ip -> ip_p == IPPROTO_TCP)
//	goto drop_pkt;

	mutex_enter (&obj -> lock);
	action = process_bootpv4 (obj, pkt_mb);
	mutex_exit (&obj -> lock);
	if (!action)
		goto drop_pkt;
	if (action == 1)
		return (0);

	mmod_assert (obj);

	return (0);

    drop_pkt:
//	cmn_err (CE_WARN,
//		"packet drop isn't working on Solaris 10!");
//	return (0);
//	cmn_err (CE_WARN,
//		"packet dst port zeroed");

//	*(pkt_mb -> b_rptr + ip_hdr_len + 2) = 0x00;
//	*(pkt_mb -> b_rptr + ip_hdr_len + 3) = 0x00;

/*	uint16_t dst_port = ntohs(*(uint16_t *)(pkt_mb -> b_rptr + ip_hdr_len + 2));

	cmn_err (CE_CONT,
		"dhcpv4: dst ip %d.%d.%d.%d:%d",
		*(pkt_mb -> b_rptr + 16),
		*(pkt_mb -> b_rptr + 17),
		*(pkt_mb -> b_rptr + 18),
		*(pkt_mb -> b_rptr + 19),
		dst_port);
*/
	if ((pkt -> hpe_mp != NULL) && (*pkt -> hpe_mp != NULL)) {
//		cmn_err (CE_WARN,
//			"packet freed");
		freemsg (*pkt -> hpe_mp);
//		*pkt -> hpe_mp = NULL;
		pkt -> hpe_mp = NULL;
	}

	pkt -> hpe_mb = NULL;
	pkt -> hpe_hdr = NULL;

	return (1);
//	return (0);
}

