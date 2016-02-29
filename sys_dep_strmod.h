/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */
  
#ifndef SYS_DEPEND_HDR
#define SYS_DEPEND_HDR

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/stat.h>

#include <sys/kstat.h>
#include <sys/crc32.h>
#include <netinet/in.h>
#include <netinet/ip.h>


#define MODULE_FULL_NAME "dhcpmod_filter"
#define MODULE_SHORT_NAME "dhcpmod"
#define MODULE_NAME MODULE_SHORT_NAME

#define MODULE_VERSION 0.1.9
#define MODULE_VERSION_TEXT "streams DHCPv4 filter v0.1.9"

#define USE_SOLARIS10_OR_MORE 1

#include "dhcp_module.h"

#endif
