/*	$Id: adjustmtu.c,v 1.32 2022/09/12 16:02:31 ryo Exp $	*/
/*-
 *
 * Copyright (c) 2010 Ryo Shimizu <ryo@nerv.org>
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
#include <sys/event.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>

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
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#include "adjustmtu.h"
#include "arpresolv.h"
#include "logging.h"
#include "rtmsg_utils.h"

#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif

struct iflist_item {
	LIST_ENTRY(iflist_item) si_list;
	char si_str[];
};
LIST_HEAD(, iflist_item) iflist;

static struct iflist_item *iflist_append(char *);
static struct iflist_item *iflist_exists(char *);
static int iflist_count(void);


static int use_arp = 1;
static int use_ping = 1;
static int dont_set_route = 0;
static int do_daemon = 0;

static int sigalrm;
static int siginfo;
static int sighup;
static int sigterm;

#define REPLY_TIMEOUT		(200 * 1000)	/* PING or ARP reply timeout. default 200msec */

#define MTUSIZE_MAX		(1024 * 64 - 2)
#define MTUSIZE_ETHER_MIN	1500
static int timeout_us = REPLY_TIMEOUT;
static int mtusize_min = MTUSIZE_ETHER_MIN;

static int
usage(void)
{
	fprintf(stderr, "usage: adjustmtu [options] [<host> ...]\n");
	fprintf(stderr, "	<host>		Target host (one shot mode)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "	-v		Verbose.\n");
	fprintf(stderr, "	-n		Only detects mtu, does not set the\n");
	fprintf(stderr, "			routing table.\n");
	fprintf(stderr, "	-t <timeout>	Specifies ping/arp timeout in millisecond.\n");
	fprintf(stderr, "			Default is 50.\n");
	fprintf(stderr, "	-A		Always use padded arp to detect mtu.\n");
	fprintf(stderr, "	-P		Always use ping (ICMP-ECHO) to detect mtu.\n");
	fprintf(stderr, "	-I <addr>	Specifies the source address to be used\n");
	fprintf(stderr, "			for ping/arp.\n");
	fprintf(stderr, "	-i <interface>	Specifies the interface to monitor.\n");
	fprintf(stderr, "			May be specified more than once.\n");
	fprintf(stderr, "	-d		Daemon mode. (Used with the -i)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "	e.g.) adjustmtu -v host1		# one shot mode\n");
	fprintf(stderr, "	e.g.) adjustmtu -d -i wm0 -i aq0	# daemon mode\n");
	fprintf(stderr, "\n");
	return EX_USAGE;
}

static u_int16_t
in_cksum(void *p0, int len)
{
	u_int32_t sum;
	uint16_t *p = p0;

	for (sum = 0; len >= 2; len -= 2)
		sum += *p++;

	if (len == 1)
		sum += ntohs(*(uint8_t *)p * 256);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

uint8_t packetbuf[MTUSIZE_MAX] __aligned(4);
uint8_t rcvbuf[MTUSIZE_MAX] __aligned(4);

/* zero is returned if the ping succeeds */
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
			} icmp __packed __aligned(4);
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
	pktbuf->header.icmp.cksum = in_cksum(&pktbuf->header.icmp,
	    size - sizeof(struct ip));
	pktbuf->header.ip.ip_sum = in_cksum(&pktbuf->header.ip, size);


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
			return errno;
		}
		logging(LOG_ERR, "%s: send %d bytes icmp: %s",
		    inet_ntoa(dst), size, strerror(errno));
		return errno;
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
		return errno;
	}
	if (nfound == 0) {
		/* icmp request timeout */
		logging(LOG_DEBUG, "%s: %d bytes ping timeout",
		    inet_ntoa(dst), size);
		return ETIMEDOUT;
	}

	rc = read(s, rcvbuf, sizeof(rcvbuf));
	if (rc <= 0) {
		logging(LOG_ERR, "read: %s", strerror(errno));
		return errno;
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
			logging(LOG_DEBUG,
			    "%s: send %d bytes icmp: echo reply OK (%.3f ms)",
			    inet_ntoa(dst), size,
			    tv_delta(&tv_send, &tv_recv) / 1000.0);
			break;
		case ICMP_UNREACH:
			logging(LOG_ERR,
			    "%s: send %d bytes icmp: ICMP Unreachable code %d",
			    inet_ntoa(dst), size, icmp->icmp_code);
			return EHOSTUNREACH;
		default:
			logging(LOG_ERR,
			    "%s: send %d bytes icmp: ICMP Error type %d code %d",
			    inet_ntoa(dst), size,
			    icmp->icmp_type, icmp->icmp_code);
			return ECONNREFUSED;
		}
	}

	return 0;
}

static int
detectmtu(struct in_addr dst, struct in_addr src, int dontroute)
{
	unsigned int base, d, mtu;
	int i, s = -1, rc, result;
	uint16_t seq;
	char ifname[IFNAMSIZ + 1];

	if (use_arp) {
		struct rtmaddrs_ss rtmaddrs_ss;

		memset(&rtmaddrs_ss, 0, sizeof(rtmaddrs_ss));
		sockaddr_init((struct sockaddr *)&rtmaddrs_ss.dst, AF_INET);
		((struct sockaddr_in *)&rtmaddrs_ss.dst)->sin_addr = dst;
		sockaddr_init((struct sockaddr *)&rtmaddrs_ss.ifp, AF_LINK);
		rc = route_get(&rtmaddrs_ss);
		if (rc != 0)
			return -1;

		src = ((struct sockaddr_in *)&rtmaddrs_ss.ifa)->sin_addr;
		memset(ifname, 0, sizeof(ifname));
		i = ((struct sockaddr_dl *)&rtmaddrs_ss.ifp)->sdl_nlen;
		if (i >= (int)sizeof(ifname))
			i = sizeof(ifname) - 1;
		strncpy(ifname, ((struct sockaddr_dl *)&rtmaddrs_ss.ifp)->sdl_data, i);
	} else {
		int n;

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
		if (dontroute && setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&n, sizeof(n)) == -1) {
			logging(LOG_ERR, "setsockopt: SO_DONTROUTE", strerror(errno));
			return -1;
		}
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
			/* retry 3 times, if it timed out */
			for (i = 0; i < 3; i++) {
				if (use_arp) {
					struct ether_addr eth;
					rc = arpresolv(ifname, &src, &dst, &eth,
					    mtu * 2 + ETHER_HDR_LEN,
					    timeout_us);
				} else {
					rc = pinger(s, src, dst, mtu * 2, seq++,
					    timeout_us, dontroute);
				}
				if (rc != ETIMEDOUT)
					break;
			}
		}

		switch (rc) {
		case 0:
			result = mtu * 2;
			base = mtu + 1;
			d--;
			break;
		case EMSGSIZE:
			break;
		case ETIMEDOUT:
			break;
		default:
			/* other (system?) errors */
			return -1;
		}
	}
	return result;
}

/*
 * similarly to "/sbin/route change/add <addr> <addr> -mtu <mtu>"
 */
static void
set_route_mtu(struct in_addr addr, unsigned int mtu)
{
	struct {
		struct rt_msghdr rtmsg_rtm;
		struct sockaddr_in rtmsg_sin;
		struct sockaddr_in rtmsg_sin2;
	} rtmsg;
	ssize_t rc;
	int s;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s == -1) {
		logging(LOG_ERR, "socket: PF_ROUTE: %s", strerror(errno));
		return;
	}
	shutdown(s, SHUT_RD);

	/* First, try "route change", and if that fails, try "route add" */
	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.rtmsg_sin.sin_len = sizeof(struct sockaddr_in);
	rtmsg.rtmsg_sin.sin_family = AF_INET;
	rtmsg.rtmsg_sin.sin_addr = addr;
	rtmsg.rtmsg_sin2.sin_len = sizeof(struct sockaddr_in);
	rtmsg.rtmsg_sin2.sin_family = AF_INET;
	rtmsg.rtmsg_sin2.sin_addr = addr;

	rtmsg.rtmsg_rtm.rtm_msglen = sizeof(rtmsg);
	rtmsg.rtmsg_rtm.rtm_version = RTM_VERSION;
	rtmsg.rtmsg_rtm.rtm_type = RTM_CHANGE;
	rtmsg.rtmsg_rtm.rtm_flags =
	    RTF_GATEWAY | RTF_HOST | RTF_UP;
	rtmsg.rtmsg_rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
	rtmsg.rtmsg_rtm.rtm_inits = RTV_MTU;
	rtmsg.rtmsg_rtm.rtm_rmx.rmx_mtu = mtu;

	rc = write(s, &rtmsg, rtmsg.rtmsg_rtm.rtm_msglen);

	/* failed "route change", retry "route add" */
	if (rc == -1 && errno == ESRCH &&
	    rtmsg.rtmsg_rtm.rtm_type == RTM_CHANGE) {
		rtmsg.rtmsg_rtm.rtm_type = RTM_ADD;
		rc = write(s, &rtmsg, rtmsg.rtmsg_rtm.rtm_msglen);
	}

	if (rc == -1) {
		logging(LOG_ERR, "write to routing socket: %s: %s",
		    inet_ntoa(addr), strerror(errno));
	}

	close(s);
}

static void
adj_route_mtu(struct in_addr dst, struct in_addr src, int dontroute)
{
	int mtu;

	mtu = detectmtu(dst, src, dontroute);
	if (mtu < 0)
		return;

	logging(LOG_NOTICE, "detect %s mtu %d",
	    inet_ntoa(dst), mtu);

	if (mtu >= mtusize_min && !dont_set_route)
		set_route_mtu(dst, mtu);
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

	for (end = (char *)rtm + size; (char *)rtm < end; 
	    rtm = (struct rt_msghdr *)((char *)rtm + rtm->rtm_msglen)) {

		/*
		 * pickup adding arp entry
		 */
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (rtm->rtm_type != RTM_ADD)
			continue;

#ifndef RTF_LLINFO
#define RTF_LLINFO	0x400	/* generated by ARP or NDP */
#endif
#ifndef RTF_CLONED
#define RTF_CLONED	0x2000	/* this is a cloned route */
#endif
		if ((rtm->rtm_flags & (RTF_UP|RTF_HOST|RTF_LLINFO|RTF_CLONED)) !=
		    (RTF_UP|RTF_HOST|RTF_LLINFO|RTF_CLONED))
			continue;
		if (rtm->rtm_addrs != (RTA_DST|RTA_GATEWAY))
			continue;

		struct rtmaddrs_ss rtmaddrs_ss;
		rtmaddr_unpack(rtm, &rtmaddrs_ss);
		if (rtmaddrs_ss.dst.ss_family != AF_INET)
			continue;

		struct sockaddr_in *dst = (struct sockaddr_in *)&rtmaddrs_ss.dst;
		struct in_addr src;
		src.s_addr = INADDR_ANY;
		adj_route_mtu(dst->sin_addr, src, 1);
	}

	return 0;
}

static void
sighandler(int signo)
{
	switch (signo) {
	case SIGALRM:
		sigalrm = 1;
		break;
	case SIGINFO:
		siginfo = 1;
		break;
	case SIGHUP:
		sighup = 1;
		break;
	case SIGTERM:
		sigterm = 1;
		break;
	default:
		break;
	}
}


static int
adjustmtu_daemon(int s)
{
	ssize_t rc;
	struct {
		struct rt_msghdr rtmsg_rtm;
		char rtmsg_buf[];
	} *rtmsg;
#define RTMSG_BUFSIZE			(1024 * 64)
#define NKEVENT	1
	struct kevent kev[NKEVENT];
	struct kevent ev[NKEVENT];
	int kq, nev, nfd;

	rtmsg = malloc(RTMSG_BUFSIZE);
	if (rtmsg == NULL) {
		logging(LOG_ERR, "cannot allocate memory");
		rc = -1;
		goto daemon_exit;
	}

	/* setup signal handlers */
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sighandler;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGALRM, &sa, NULL) != 0 ||
	    sigaction(SIGHUP, &sa, NULL) != 0 ||
	    sigaction(SIGTERM, &sa, NULL) != 0 ||
	    sigaction(SIGINFO, &sa, NULL) != 0) {
		logging(LOG_ERR, "sigaction: %s", strerror(errno));
		return -1;
	};

	if ((kq = kqueue()) == -1) {
		logging(LOG_ERR, "kqueue: %s", strerror(errno));
		return -1;
	}
	nfd = 0;
	EV_SET(&kev[nfd++], s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	if (kevent(kq, kev, nfd, NULL, 0, NULL) == -1) {
		logging(LOG_ERR, "kevent: %s", strerror(errno));
		return -1;
	}

	/* daemon loop */
	for (;;) {
		if (sigalrm) {
			sigalrm = 0;
			logging(LOG_DEBUG, "catch SIGALRM");
		}

		if (siginfo) {
			siginfo = 0;
			logging(LOG_DEBUG, "catch SIGINFO");
		}

		if (sighup || sigterm) {
			sighup = sigterm = 0;
			logging(LOG_DEBUG, "caught signal. Terminate");
			rc = 0;
			goto daemon_exit;
		}

		nev = kevent(kq, NULL, 0, ev, nfd, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			logging(LOG_ERR, "kevent: %s", strerror(errno));
			rc = -1;
			goto daemon_exit;
		}
		if (nev == 0)
			continue;

		rc = read(s, rtmsg, RTMSG_BUFSIZE);
		if (rc <= 0) {
			logging(LOG_ERR, "read: %s", strerror(errno));
			rc = -1;
			goto daemon_exit;
		}

		if (rtmsg_proc(&rtmsg->rtmsg_rtm, rc) < 0) {
			rc = -1;
			goto daemon_exit;
		}
	}

 daemon_exit:
	if (rtmsg != NULL)
		free(rtmsg);

	return rc;
}

int
main(int argc, char *argv[])
{
	struct in_addr dst, src;
	struct addrinfo hints, *res;
	int ch, error, s;

	logging_filter(LOG_DEBUG, 0);
	logging_filter(LOG_INFO, 0);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;

	dst.s_addr = INADDR_ANY;
	src.s_addr = INADDR_ANY;

	LIST_INIT(&iflist);

	while ((ch = getopt(argc, argv, "AdI:i:nPt:v")) != -1) {
		switch (ch) {
		case 'A':
			use_arp = 1;
			use_ping = 0;
			break;
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
		case 'i':
			iflist_append(optarg);
			break;
		case 'n':
			dont_set_route = 1;
			break;
		case 'P':
			use_ping = 1;
			use_arp = 0;
			break;
		case 't':
			timeout_us = strtou(optarg, NULL, 10, 0, 0xffffffff, NULL) * 1000;
			break;
		case 'v':
			logging_filter(LOG_DEBUG, 1);
			logging_filter(LOG_INFO, 1);
			break;
		case '?':
		default:
			return usage();
		}
	}
	argc -= optind;
	argv += optind;


	for (int i = 0; i < argc; i++) {
		error = getaddrinfo(argv[i], NULL, &hints, &res);
		if (error) {
			fprintf(stderr, "%s: %s\n", optarg,
			    gai_strerror(error));
			exit(1);
		}
		dst = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
		freeaddrinfo(res);

		adj_route_mtu(dst, src, 1);
	}

	if (iflist_count() == 0)
		return EX_OK;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s == -1) {
		logging(LOG_ERR, "socket: PF_ROUTE: %s", strerror(errno));
		return EX_OSERR;
	}

	if (do_daemon) {
		daemon(0, 0);
		logging_open("adjustmtu", LOG_PID, LOG_DAEMON);
		error = adjustmtu_daemon(s);
		logging(LOG_ERR, "exiting");
	} else {
		/* foreground daemon mode */
		error = adjustmtu_daemon(s);
	}
	close(s);

	if (error != 0)
		return EX_OSERR;
	return EX_OK;
}
