/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */
  
#ifndef DHCP_MODULE_HDR
#define DHCP_MODULE_HDR

/*
 * Module instance state flags.
 */
#define MODULE_INSTANCE_STATE_INITIALIZED 0
#define MODULE_INSTANCE_STATE_RUNNING 1
#define MODULE_INSTANCE_STATE_STOPPED 2
#define MODULE_INSTANCE_STATE_FAILED_TO_START 3

/*
 * Ioctls.
 */
#define	DHCPIOC		('D' << 8)
#define	DHCPIOCSDROPANYPPM	(DHCPIOC|1)	/* set dropping rate per min */
#define	DHCPIOCSDROPPOLIFNORA	(DHCPIOC|2)	/* set dropping policy if no DHCP Option 82 info */
#define	DHCPIOCSDROPNORAPPM	(DHCPIOC|3)	/* set dropping rate per min if no DHCP Option 82 info */
#define	DHCPIOCSDROPPOLALLNORA	(DHCPIOC|4)	/* set dropping policy for all packets if no DHCP Option 82 info */
#define	DHCPIOCSDROPPOLBYPPM	(DHCPIOC|5)	/* set dropping policy by rate */

#if defined MAKE_HOOK_MODULE
#include "sys_dep_hookmod.h"
#else
#include "sys_dep_strmod.h"
#endif

#define IPV4_MAX_PKTLEN (65535)
#define UDPV4_DGRAM_MAX_LEN (IPV4_MAX_PKTLEN)
#define IPV4_HDR_LEN (20)
#define UDPV4_HDR_LEN (8)
#define UDPV4_DATA_LEN_OFFSET (2 + 2)
#define IPV4_SRCADDR_OFFSET (12)
#define IPV4_DSTADDR_OFFSET (16)
#define IP_PROTO_OFFSET (9)
#define IPV4_FLAGS_OFFSET (6)
#define IPV4_FRAG_OFFSET_OFFSET (7)
#define IPV4_DATA_LEN_OFFSET (2)
#define UDPV4_SRCPORT_OFFSET (0)
#define UDPV4_DSTPORT_OFFSET (2)

#define BOOTP_DEFAULT_SERVER_PORT (67)
#define BOOTP_DEFAULT_CLIENT_PORT (68)

#define BOOTP_REQUEST (1)
#define BOOTP_REPLY (2)

#define BOOTP_HW_ETHER (1)
#define BOOTP_HW_ETHER_LEN (6)

#define DHCP_DISCOVER        (1)
#define DHCP_OFFER	     (2)
#define DHCP_REQUEST	     (3)
#define DHCP_DECLINE	     (4)
#define DHCP_ACK	     (5)
#define DHCP_NAK	     (6)
#define DHCP_RELEASE	     (7)
#define DHCP_INFORM	     (8)
#define DHCP_FORCERENEW	     (9)
#define DHCP_LEASEQUERY	     (10)
#define DHCP_LEASEUNASSIGNED (11)
#define DHCP_LEASEUNKNOWN    (12)
#define DHCP_LEASEACTIVE     (13)
#define DHCP_MSG_TYPES (DHCP_LEASEACTIVE)

#define DHCP_NONUDP_PKTLEN (236)
#define DHCP_MIN_PKTLEN (DHCP_NONUDP_PKTLEN + IPV4_HDR_LEN + UDPV4_HDR_LEN)
#define DHCP_MAX_PKTLEN (1500)
#define DHCP_OPTIONS_MAX_PKTLEN (DHCP_MAX_PKTLEN - DHCP_MIN_PKTLEN)
#define BOOTP_MIN_PKTLEN (300)

#define DHCP_OPTION_OVERLOAD (52)
#define DHCP_OPTION_MSG_TYPE (53)
#define DHCP_OPTION_CLIENT_IDENTIFIER (61)
#define DHCP_OPTION_RELAY_AGENT (82)

#define BOOTP_MSG_OFFSET (UDPV4_HDR_LEN)
#define BOOTP_HWTYPE_OFFSET (BOOTP_MSG_OFFSET + 1)
#define BOOTP_HWLEN_OFFSET (BOOTP_MSG_OFFSET + 2)
#define BOOTP_HOPS_OFFSET (BOOTP_MSG_OFFSET + 3)
#define BOOTP_XID_OFFSET (BOOTP_MSG_OFFSET + 4)
#define BOOTP_SECS_OFFSET (BOOTP_MSG_OFFSET + 8)
#define BOOTP_FLAGS_OFFSET (BOOTP_MSG_OFFSET + 10)
#define BOOTP_CIADDR_OFFSET (BOOTP_MSG_OFFSET + 12)
#define BOOTP_YIADDR_OFFSET (BOOTP_MSG_OFFSET + 16)
#define BOOTP_SIADDR_OFFSET (BOOTP_MSG_OFFSET + 20)
#define BOOTP_GIADDR_OFFSET (BOOTP_MSG_OFFSET + 24)
#define BOOTP_CHADDR_OFFSET (BOOTP_MSG_OFFSET + 28)
#define BOOTP_CHPAD_OFFSET (BOOTP_MSG_OFFSET + 34)
#define BOOTP_SERVER_OFFSET (BOOTP_MSG_OFFSET + 44)
#define BOOTP_FILE_OFFSET (BOOTP_MSG_OFFSET + 108)
#define BOOTP_COOKIE_OFFSET (BOOTP_MSG_OFFSET + 236)
#define BOOTP_OPTIONS_OFFSET (BOOTP_MSG_OFFSET + 240)

#define DHCP_OPTION_CODE_LEN (1)
#define DHCP_OPTION_LENGTH_LEN (1)
#define DHCP_OPTION_MSG_TYPE_LEN (DHCP_OPTION_CODE_LEN + DHCP_OPTION_LENGTH_LEN + 1)
#define DHCP_OPTIONS_END_LEN (1)

#define BOOTP_OPTIONS_PAD (0)
#define BOOTP_OPTIONS_END (255)

#define BOOTP_MAX_OPTIONS_LEN (255)

#define BOOTP_COOKIE_VALUE (0x63825363)

typedef struct _hash_entry hash_entry;
struct _hash_entry {
    hash_entry *next;
    void *val;
    char *name;
    uint16_t name_len;
    int is_allocated;
    int allocated;
};

typedef struct _hash_table hash_table;
struct _hash_table {
    hash_entry *hash;
    unsigned long values;
    unsigned long buckets;
    int allocated;
};

typedef struct _cached_pkt cached_pkt;
struct _cached_pkt {
    cached_pkt *next;
    char *hash_name;
    hrtime_t enqueue;
    hrtime_t start;
    hrtime_t last;
    uint64_t pkt_count[DHCP_MSG_TYPES];
    uint64_t pkt_count_passed[DHCP_MSG_TYPES];
    uint64_t pkt_count_dropped[DHCP_MSG_TYPES];
    uint8_t flag;
#define ON_RATES_QUEUE (2)
    int allocated;
};

int hash_add_item (hash_table **, char *, uint16_t, void *, int);
int hash_remove_item (hash_table *, char *);
hash_entry *hash_lookup (hash_table *, char *, uint16_t);
int hash_free_table (hash_table **, unsigned long *, unsigned long *);

extern hrtime_t default_1sec_in_ticks;
extern hrtime_t default_time_period_in_ticks;
extern hrtime_t default_storage_time_period_in_ticks;
extern hrtime_t default_expire_queue_time_period_in_ticks;

#if defined MAKE_HOOK_MODULE
#include "cust_dep_hookmod.h"
#else
#include "cust_dep_strmod.h"
#endif

int process_expired_queued_cpkts (obj_t *);
int queue_lookup_cpkt (void *);
void queue_add_cpkt (obj_t *, void *, hrtime_t);
void queue_remove_cpkt (obj_t *, void *);
void queue_remove_cpkts (obj_t *);
void queue_free_cpkts (obj_t *);

int bootp_init (void);
int bootp_start (obj_t *, int);
int bootp_finish (obj_t *);
int process_bootpv4 (obj_t *, mblk_t *);

int obj_kstat_update (kstat_t *, int);
void obj_kstat_init (obj_t *, int);
void obj_kstat_fini (obj_t *);

#define MAX_ULONG_STRING_LEN 40

unsigned int blength_ulong (unsigned long);
unsigned int bput_ulong (char *, unsigned long);
unsigned int bfmt_ulong (char *, unsigned long);
//uint64_t uint64val_up1 (obj_t *, uint64_t *);
//uint64_t uint64val_attrib (obj_t *, uint64_t *, uint64_t);

#endif
