/*	$Id: adjustmtu.c,v 1.27 2012/03/21 08:59:03 ryo Exp $	*/
/*-
 *
 * Copyright (c) 2010 SHIMIZU Ryo <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <time.h>
#include <err.h>
#include <errno.h>

#undef RTMSG_DEBUG

#ifndef __packed
#define __packed __attribute__((packed))
#endif

int main(int, char *[]);
static int usage(void);
static int adjustmtu_daemon(void);
static int adj_route_mtu(struct in_addr, struct in_addr, int);
static void set_route_mtu(struct in_addr, unsigned int);
static int rtmsg_proc(struct rt_msghdr *, size_t);
static int detectmtu(struct in_addr, struct in_addr, int);
static int pinger(int, struct in_addr, struct in_addr,
                  unsigned int, uint16_t, unsigned int, int);
static unsigned long tv_delta(struct timeval *, struct timeval *);
static void logging(int, char const *fmt, ...);

struct iflist_item {
	LIST_ENTRY(iflist_item) si_list;
	char si_str[];
};
LIST_HEAD(, iflist_item) iflist;

static struct iflist_item *iflist_append(char *);
static struct iflist_item *iflist_exists(char *);
static int iflist_count(void);


static int do_daemon = 0;

#define PING_TIMEOUT		(200 * 1000)	/* 200msec */
#define MTUSIZE_MAX		(1024 * 64)
#define MTUSIZE_MIN		1280
#define MTUSIZE_ETHER_MIN	1500
static int mtusize_min = MTUSIZE_MIN;

static int
usage()
{
	fprintf(stderr, "usage: adjustmtu [options] [if0 [if1 ...]]\n");
	fprintf(stderr, "\t-d\t\tdaemon mode\n");
	fprintf(stderr, "\t-o <host>\ttarget host (one shot mode)\n");
	return 1;
}

static unsigned long
tv_delta(struct timeval *a, struct timeval *b)
{
	unsigned long d;

	d = (b->tv_sec * 1000000 + b->tv_usec) -
	    (a->tv_sec * 1000000 + a->tv_usec);

	return d;
}

static u_int16_t
in_cksum(uint16_t *p, int len)
{
	u_int32_t sum;

	for (sum = 0; len >= 2; len -= 2)
		sum += *p++;

	if (len == 1)
		sum += ntohs(*(uint8_t *)p * 256);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

uint8_t packetbuf[MTUSIZE_MAX];
uint8_t rcvbuf[MTUSIZE_MAX];

static int
pinger(int s, struct in_addr src, struct in_addr dst,
       unsigned int size, uint16_t seq, unsigned int timeout, int dontroute)
{
	struct sockaddr_in sin;
	fd_set readfds;
	struct timeval tv_wait, tv_send, tv_recv;
	struct pingpkt {
		struct {
			struct ip ip;
			struct {
				uint8_t type;
				uint8_t code;
				uint16_t cksum;
				uint16_t id;
				uint16_t seq;
			} icmp __packed;
		} header;
		uint8_t data[];
	} __packed *pktbuf;
	struct ip *ip;
	struct icmp *icmp;
	ssize_t rc;
	int nfound, i;

	pktbuf = (struct pingpkt *)packetbuf;

	/*
	 * build a <size> bytes of ping echo-request packet
	 */
	memset(pktbuf, 0, sizeof(pktbuf->header));

	/* icmp payload */
	for (i = 0; i < (int)(size - offsetof(struct pingpkt, data)); i += 2) {
		pktbuf->data[i] = size >> 8;
		pktbuf->data[i + 1] = size & 0xff;
	}
	/* for tcpdumper :-) */
	snprintf((char *)&pktbuf->data[4], 16, "pktsize=%d", size);

	/* build IP and ICMP header */
	pktbuf->header.ip.ip_v = IPVERSION;
	pktbuf->header.ip.ip_hl = sizeof(struct ip) >> 2;
	pktbuf->header.ip.ip_tos = 0;
#if defined(__OpenBSD__)
	pktbuf->header.ip.ip_len = htons(size);
	pktbuf->header.ip.ip_off = htons(IP_DF);
#else
	pktbuf->header.ip.ip_len = size;
	pktbuf->header.ip.ip_off = IP_DF;
#endif
	pktbuf->header.ip.ip_ttl = dontroute ? 2 : IPDEFTTL;
	pktbuf->header.ip.ip_p = IPPROTO_ICMP;
	pktbuf->header.ip.ip_src = src;
	pktbuf->header.ip.ip_dst = dst;

	pktbuf->header.icmp.type = ICMP_ECHO;
	pktbuf->header.icmp.code = 0;
	pktbuf->header.icmp.cksum = 0;
	pktbuf->header.icmp.id = arc4random() & 0xffff;
	pktbuf->header.icmp.seq = htons(seq);
	pktbuf->header.icmp.cksum = in_cksum((uint16_t *)&pktbuf->header.icmp,
	    size - sizeof(struct ip));
	pktbuf->header.ip.ip_sum = in_cksum((uint16_t *)&pktbuf->header.ip, size);


	/*
	 * FIRE A PACKET!
	 */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_addr = dst;

	gettimeofday(&tv_send, NULL);
	rc = sendto(s, pktbuf, size, dontroute ? MSG_DONTROUTE : 0,
	    (struct sockaddr *)&sin, sizeof(sin));
	if (rc < 0) {
		if (errno == EMSGSIZE) {
			logging(LOG_DEBUG, "%s: send %d bytes icmp: %s",
			    inet_ntoa(dst), size, strerror(errno));
			/* continuable error */
			return 3;
		}
		logging(LOG_ERR, "%s: send %d bytes icmp: %s",
		    inet_ntoa(dst), size, strerror(errno));
		return -1;
	}

 retry:
	/* receive icmp echo reply */
	tv_wait.tv_sec = timeout / 1000000;
	tv_wait.tv_usec = timeout % 1000000;
	FD_ZERO(&readfds);
	FD_SET(s, &readfds);

	nfound = select(s + 1, &readfds, NULL, NULL, &tv_wait);
	gettimeofday(&tv_recv, NULL);
	if (nfound < 0) {
		logging(LOG_ERR, "select: %s", strerror(errno));
		return -1;
	}
	if (nfound == 0) {
		/* icmp request timeout */
		logging(LOG_NOTICE, "%s: %d bytes ping timeout",
		    inet_ntoa(dst), size);
		/* continuable error */
		return 1;
	}

	rc = read(s, rcvbuf, sizeof(rcvbuf));
	if (rc <= 0) {
		logging(LOG_ERR, "read: %s", strerror(errno));
		return -1;
	}

	ip = (struct ip *)rcvbuf;
	if (ip->ip_p == IPPROTO_ICMP) {
		int iphdrlen;

		iphdrlen = ip->ip_hl * 4;
		icmp = (struct icmp *)(rcvbuf + iphdrlen);

		switch (icmp->icmp_type) {
		case ICMP_ECHOREPLY:
			if (icmp->icmp_code != 0 ||
#if defined(__OpenBSD__)
			    ntohs(ip->ip_len) != size ||
#else
			    ip->ip_len != (size - iphdrlen) ||
#endif
			    icmp->icmp_id != pktbuf->header.icmp.id ||
			    icmp->icmp_seq != pktbuf->header.icmp.seq) {
				/* not for me? retry to receive */
				goto retry;
			}
			logging(LOG_INFO,
			    "%s: send %d bytes icmp: echo reply OK (%.3f ms)",
			    inet_ntoa(dst), size,
			    tv_delta(&tv_send, &tv_recv) / 1000.0);
			break;
		case ICMP_UNREACH:
			logging(LOG_ERR,
			    "%s: send %d bytes icmp: ICMP Unreachable code %d",
			    inet_ntoa(dst), size, icmp->icmp_code);
			return 2;
		default:
			logging(LOG_ERR,
			    "%s: send %d bytes icmp: ICMP Error type %d code %d",
			    inet_ntoa(dst), size,
			    icmp->icmp_type, icmp->icmp_code);
			return -1;
		}
	}

	return 0;
}

static int
detectmtu(struct in_addr dst, struct in_addr src, int dontroute)
{
	unsigned int base, d, mtu;
	int i, s, n, rc, result;
	uint16_t seq;

	s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s < 0) {
		logging(LOG_ERR, "socket: AF_INET: SOCK_RAW: %s",
		    strerror(errno));
		return -1;
	}

	n = MTUSIZE_MAX;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) == -1) {
		logging(LOG_ERR, "setsockopt: IP_SNDBUF", strerror(errno));
		return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == -1) {
		logging(LOG_ERR, "setsockopt: IP_RCVBUF", strerror(errno));
		return -1;
	}

	n = 1;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&n, sizeof(n)) == -1) {
		logging(LOG_ERR, "setsockopt: IP_HDRINCL", strerror(errno));
		return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&n, sizeof(n)) == -1) {
		logging(LOG_ERR, "setsockopt: SO_DONTROUTE", strerror(errno));
		return -1;
	}


	/*
	 * detect MTU size with binary search.
	 * MTU size must be even.
	 */
	result = -1;
	seq = 0;
	for (base = 0, d = MTUSIZE_MAX / 2 + 1;
	    d != 0; d >>= 1) {
		mtu = base + (d >> 1);

		if (mtu <= (unsigned int)(mtusize_min / 2))
			rc = 0;
		else {
			/* retry 3 times, if failure */
			for (i = 0; i < 3; i++) {
				rc = pinger(s, src, dst, mtu * 2, seq++, PING_TIMEOUT,
				    dontroute);
				if (rc != 1)	/* not timeout */
					break;
			}
		}

		if (rc < 0)
			return -1;
		if (rc == 0) {
			result = mtu * 2;
			base = mtu + 1;
			d--;
		}
	}
	return result;
}

/*
 * similarly to "/sbin/route change <addr> -mtu <mtu>"
 */
static void
set_route_mtu(struct in_addr addr, unsigned int mtu)
{
	struct {
		struct rt_msghdr rtmsg_rtm;
		struct sockaddr_in rtmsg_sin;
	} rtmsg;
	ssize_t rc;
	int s;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s == -1) {
		logging(LOG_ERR, "socket: PF_ROUTE: %s", strerror(errno));
		return;
	}
	shutdown(s, SHUT_RD);

	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.rtmsg_sin.sin_len = sizeof(struct sockaddr_in);
	rtmsg.rtmsg_sin.sin_family = AF_INET;
	rtmsg.rtmsg_sin.sin_addr = addr;

	rtmsg.rtmsg_rtm.rtm_msglen = sizeof(rtmsg);
	rtmsg.rtmsg_rtm.rtm_version = RTM_VERSION;
	rtmsg.rtmsg_rtm.rtm_type = RTM_CHANGE;
	rtmsg.rtmsg_rtm.rtm_flags =
	    RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_STATIC;
	rtmsg.rtmsg_rtm.rtm_addrs = RTA_DST;
	rtmsg.rtmsg_rtm.rtm_inits = RTV_MTU;
	rtmsg.rtmsg_rtm.rtm_rmx.rmx_mtu = mtu;

	rc = write(s, &rtmsg, rtmsg.rtmsg_rtm.rtm_msglen);
	if (rc == -1) {
		logging(LOG_ERR, "write to routing socket: %s: %s",
		    inet_ntoa(addr), strerror(errno));
	}

	close(s);
}

static int
adj_route_mtu(struct in_addr dst, struct in_addr src, int dontroute)
{
	int mtu;

	mtu = detectmtu(dst, src, dontroute);
	if (mtu < 0)
		return -1;
	if (mtu > 0) {
		logging(LOG_INFO, "detect %s MTU %d",
		    inet_ntoa(dst), mtu);

		set_route_mtu(dst, mtu);
	}
	return 0;
}

static void
logging(int prio, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (do_daemon) {
		vsyslog(prio, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		printf("\n");
	}
	va_end(ap);
}

static struct iflist_item *
iflist_append(char *str)
{
	size_t len;
	struct iflist_item *elm;

	/* already exists? */
	if ((elm = iflist_exists(str)) != NULL)
		return elm;

	len = strlen(str);
	if (len == 0)
		return NULL;

	elm = malloc(sizeof(struct iflist_item) + len + 1);
	if (elm == NULL)
		return NULL;

	strlcpy(elm->si_str, str, len + 1);
	LIST_INSERT_HEAD(&iflist, elm, si_list);

	return elm;
}

static int
iflist_count()
{
	struct iflist_item *elm;
	int n;

	n = 0;
	LIST_FOREACH(elm, &iflist, si_list)
		n++;

	return n;
}

static struct iflist_item *
iflist_exists(char *str)
{
	struct iflist_item *elm;

	LIST_FOREACH(elm, &iflist, si_list) {
		if (strcmp(elm->si_str, str) == 0)
			return elm;
	}
	return NULL;
}

static int
rtmsg_proc(struct rt_msghdr *rtm, size_t size)
{
	char *end;
#ifdef RTMSG_DEBUG
	char logbuf[1024];
#endif
	struct sockaddr_in *sin;

	for (end = (char *)rtm + size; (char *)rtm < end; 
	    rtm = (struct rt_msghdr *)((char *)rtm + rtm->rtm_msglen)) {

		/*
		 * pickup adding arp entry
		 */
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (rtm->rtm_type != RTM_ADD)
			continue;

		if ((rtm->rtm_flags & (RTF_UP|RTF_HOST|RTF_LLINFO)) !=
		    (RTF_UP|RTF_HOST|RTF_LLINFO)) {
			logging(LOG_DEBUG,
			    "rtm_flags: 0x%x: no arp entry? ignore",
			    rtm->rtm_flags);
			continue;
		}
		if (rtm->rtm_addrs != (RTA_DST|RTA_GATEWAY|RTA_IFP|RTA_IFA)) {
			logging(LOG_DEBUG,
			    "rtm_addrs: 0x%x: no arp entry? ignore",
			    rtm->rtm_addrs);
			continue;
		}

		{
			int i;
			char *p;
			struct sockaddr *saddr[RTAX_MAX];
			struct sockaddr *sa;
			struct sockaddr_dl *sadl;
			char ifname[IF_NAMESIZE];

#ifdef RTMSG_DEBUG
			printf("====================\n");
			printf("rtm_flags=0x%x\n", rtm->rtm_flags);
			printf("rtm_addrs=0x%x\n", rtm->rtm_addrs);
#endif /* RTMSG_DEBUG */

			p = (char *)(rtm + 1);
			for (i = 0; i < RTAX_MAX; i++) {
				if ((1 << i) & rtm->rtm_addrs) {
					sa = (struct sockaddr *)p;
					saddr[i] = sa;
#ifndef ROUNDUP
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif
#ifndef RT_ADVANCE
#define RT_ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#endif
					RT_ADVANCE(p, sa);
				} else {
					saddr[i] = NULL;
				}
			}

#ifdef RTMSG_DEBUG
			printf("af=%d: ", saddr[RTAX_DST]->sa_family);
			getnameinfo(saddr[RTAX_DST], saddr[RTAX_DST]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_DST: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_GATEWAY]->sa_family);
			getnameinfo(saddr[RTAX_GATEWAY], saddr[RTAX_GATEWAY]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_GATEWAY: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_IFP]->sa_family);
			getnameinfo(saddr[RTAX_IFP], saddr[RTAX_IFP]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_IFP: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_IFA]->sa_family);
			getnameinfo(saddr[RTAX_IFA], saddr[RTAX_IFA]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_IFA: %s\n", logbuf);
#endif /* RTMSG_DEBUG */

			/* extract interface name */
			sadl = (struct sockaddr_dl *)saddr[RTAX_IFP];
			if (sadl->sdl_nlen < sizeof(ifname)) {
				memcpy(ifname, sadl->sdl_data, sadl->sdl_nlen);
				ifname[sadl->sdl_nlen] = '\0';
			}

			/* no need to watch this interface */
			if (iflist_exists(ifname) == NULL)
				continue;

			switch (sadl->sdl_type) {
			case IFT_ETHER:
			/* case IFT_XXX: // other jumbo frame interface */
				break;
			default:
				continue;
			}

			if (saddr[RTAX_DST]->sa_family == AF_INET) {
				struct in_addr src;
				src.s_addr = INADDR_ANY;

				sin = (struct sockaddr_in *)saddr[RTAX_DST];
				if (adj_route_mtu(sin->sin_addr, src, 1) < 0)
					return -1;
			}
		}
	}

	return 0;
}

static int
adjustmtu_daemon(void)
{
	int s;
	ssize_t rc;
	struct {
		struct rt_msghdr rtmsg_rtm;
		char rtmsg_buf[];
	} *rtmsg;
#define RTMSG_BUFSIZE	(1024 * 64)

	s = -1;
	rtmsg = malloc(RTMSG_BUFSIZE);
	if (rtmsg == NULL) {
		logging(LOG_ERR, "cannot allocate memory");
		goto daemon_failure;
	}

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s == -1) {
		free(rtmsg);
		logging(LOG_ERR, "socket: PF_ROUTE: %s", strerror(errno));
		goto daemon_failure;
	}

	/* daemon loop */
	for (;;) {
		rc = read(s, rtmsg, RTMSG_BUFSIZE);

		if (rc <= 0) {
			logging(LOG_ERR, "read: %s", strerror(errno));
			goto daemon_failure;
		}

		if (rtmsg_proc(&rtmsg->rtmsg_rtm, rc) < 0)
			goto daemon_failure;
	}

 daemon_failure:
	if (rtmsg != NULL)
		free(rtmsg);
	if (s >= 0)
		close(s);

	return -1;
}

int
main(int argc, char *argv[])
{
	int ch, error, i;
	struct in_addr dst, src;
	int oneshot;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;

	oneshot = 0;
	dst.s_addr = INADDR_ANY;
	src.s_addr = INADDR_ANY;
	while ((ch = getopt(argc, argv, "dI:o:")) != -1) {
		switch (ch) {
		case 'd':
			do_daemon = 1;
			break;
		case 'I':
			error = getaddrinfo(optarg, NULL, &hints, &res);
			if (error) {
				fprintf(stderr, "%s: %s\n", optarg,
				    gai_strerror(error));
				exit(1);
			}
			src = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			freeaddrinfo(res);
			break;
		case 'o':
			error = getaddrinfo(optarg, NULL, &hints, &res);
			if (error) {
				fprintf(stderr, "%s: %s\n", optarg,
				    gai_strerror(error));
				exit(1);
			}
			dst = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			freeaddrinfo(res);

			adj_route_mtu(dst, src, 0);
			oneshot++;
			break;
		case '?':
		default:
			return usage();
		}
	}
	argc -= optind;
	argv += optind;

	LIST_INIT(&iflist);
	for (i = 0; i < argc; i++)
		iflist_append(argv[i]);

	if (iflist_count() != 0) {
		if (do_daemon) {
			daemon(0, 0);
			openlog("adjustmtu", LOG_PID, LOG_DAEMON);
		}
		mtusize_min = MTUSIZE_ETHER_MIN;

		adjustmtu_daemon();

		logging(LOG_ERR, "exiting");
		return 1;
	}

	if (oneshot == 0)
		return usage();

	return 0;
}
