#ifndef _ARPRESOLV_H_
#define _ARPRESOLV_H_

#include <net/if.h>
#include <net/if_types.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#else
#include <net/if_ether.h>
#endif

int arpresolv(const char *, struct in_addr *, struct in_addr *, struct ether_addr *, unsigned int, unsigned int);

#endif /* _ARPRESOLV_H_ */
