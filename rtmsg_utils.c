#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include <arpa/inet.h>
#include <net/route.h>
#include <net/if_dl.h>

#include "rtmsg_utils.h"

#undef RTGET_DEBUG


#ifdef __FreeBSD__
#define RT_ROUNDUP(n)		((((n) == 0) ? sizeof(long) : 1 + (((n) - 1) | (sizeof(long) - 1))))
#define RT_ADVANCE(x, n)	(x += RT_ROUNDUP((n)->sa_len))
#endif
#ifdef __OpenBSD__
#define RT_ROUNDUP(a)		((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define RT_ADVANCE(x, n)	(x += RT_ROUNDUP((n)->sa_len))
#endif

int
sockaddr_init(struct sockaddr *sa, sa_family_t family)
{
	switch (family) {
	case AF_INET:
		memset(sa, 0, sizeof(struct sockaddr_in));
		sa->sa_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		memset(sa, 0, sizeof(struct sockaddr_in6));
		sa->sa_len = sizeof(struct sockaddr_in6);
		break;
	case AF_LINK:
		memset(sa, 0, sizeof(struct sockaddr_dl));
		sa->sa_len = sizeof(struct sockaddr_dl);
		break;
	case AF_LOCAL:
		memset(sa, 0, sizeof(struct sockaddr_un));
		sa->sa_len = sizeof(struct sockaddr_un);
		break;
	case AF_UNSPEC:
	case AF_APPLETALK:
	default:
		return -1;
	}
	sa->sa_family = family;
	return 0;
}

int
sockaddr_pton(struct sockaddr *sa, const char *src)
{
	if (inet_aton(src, &((struct sockaddr_in *)sa)->sin_addr) == 1) {
		((struct sockaddr_in *)sa)->sin_family = AF_INET;
		((struct sockaddr_in *)sa)->sin_len = sizeof(struct sockaddr_in);
		return 0;
	}
	if (inet_pton(AF_INET6, src, &((struct sockaddr_in6 *)sa)->sin6_addr) == 1) {
		((struct sockaddr_in6 *)sa)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)sa)->sin6_len = sizeof(struct sockaddr_in6);
		return 0;
	}
	return -1;
}


void
rtmaddr_pack(const struct rtmaddrs_ss * const rtmaddrs_ss, struct rt_msghdr *rtmsg)
{
	char *cp = (char *)(rtmsg + 1);
	int rtmaddrs = 0;

#define _PACK_RTA(x, rta_flag)						\
	if (rtmaddrs_ss->x.ss_len > 0) {				\
		memcpy(cp, &rtmaddrs_ss->x, rtmaddrs_ss->x.ss_len);	\
		cp += RT_ROUNDUP(rtmaddrs_ss->x.ss_len);		\
		rtmaddrs |= (rta_flag);					\
	}
	_PACK_RTA(dst, RTA_DST)
	_PACK_RTA(gateway, RTA_GATEWAY)
	_PACK_RTA(netmask, RTA_NETMASK)
	_PACK_RTA(genmask,RTA_GENMASK)
	_PACK_RTA(ifp, RTA_IFP)
	_PACK_RTA(ifa, RTA_IFA)
	_PACK_RTA(tag, RTA_TAG)
#undef _PACK_RTA

	rtmsg->rtm_msglen = cp - (char *)rtmsg;
	rtmsg->rtm_version = RTM_VERSION;
	rtmsg->rtm_addrs = rtmaddrs;
	/* Other members must be filled in by the caller */
}

void
rtmaddr_unpack(const struct rt_msghdr * const rtmsg, struct rtmaddrs_ss *rtmaddrs_ss)
{
	const char *cp = (const char *)(rtmsg + 1);

	memset(rtmaddrs_ss, 0, sizeof(*rtmaddrs_ss));

	for (int i = 0; i < 32; i++) {
		if ((rtmsg->rtm_addrs & __BIT(i)) == 0)
			continue;

		const struct sockaddr *sa = (const struct sockaddr *)cp;
		switch (__BIT(i)) {
		case RTA_DST:
			memcpy(&rtmaddrs_ss->dst, sa, sa->sa_len);
			break;
		case RTA_GATEWAY:
			memcpy(&rtmaddrs_ss->gateway, sa, sa->sa_len);
			break;
		case RTA_NETMASK:
			/*
			 * XXX: The sockaddr corresponding to
			 * RTA_NETMASK has a special structure.
			 * so converte to the same address
			 * family as RTA_DST.
			 */
			if (sa->sa_len == 0) {
				sockaddr_init(
				    (struct sockaddr *)&rtmaddrs_ss->netmask,
				    rtmaddrs_ss->dst.ss_family);
			} else {
				memcpy(&rtmaddrs_ss->netmask, sa, sa->sa_len);
			}
			rtmaddrs_ss->netmask.ss_family = rtmaddrs_ss->dst.ss_family;
			rtmaddrs_ss->netmask.ss_len = rtmaddrs_ss->dst.ss_len;
			break;
		case RTA_IFP:
			memcpy(&rtmaddrs_ss->ifp, sa, sa->sa_len);
			break;
		case RTA_IFA:
			memcpy(&rtmaddrs_ss->ifa, sa, sa->sa_len);
			break;
		case RTA_TAG:
			memcpy(&rtmaddrs_ss->tag, sa, sa->sa_len);
			break;
		default:
			/* ignore unknown RTA_* */
			break;
		}
		RT_ADVANCE(cp, sa);
	}
}

void
rtmaddrs_dump(struct rtmaddrs_ss *rtmaddrs_ss)
{
	char buf[256];
	struct {
		struct sockaddr_storage *ss;
		const char *label;
	} sss[] = {
		{ &rtmaddrs_ss->dst, "RTA_DST" },
		{ &rtmaddrs_ss->gateway, "RTA_GATEWAY" },
		{ &rtmaddrs_ss->netmask, "RTA_NETMASK" },
		{ &rtmaddrs_ss->genmask, "RTA_GENMASK" },
		{ &rtmaddrs_ss->ifp, "RTA_IFP" },
		{ &rtmaddrs_ss->ifa, "RTA_IFA" },
		{ &rtmaddrs_ss->tag, "RTA_TAG" }
	};
	for (int i = 0; i < (int)__arraycount(sss); i++) {
		if (sss[i].ss->ss_len == 0)
			continue;

		sockaddr_snprintf(buf, sizeof(buf), "%a / %D", (struct sockaddr *)sss[i].ss);
		printf(" %s: %s\n", sss[i].label, buf);
	}
}

void
rtmsg_dump(const struct rt_msghdr *rtmsg)
{
	struct rtmaddrs_ss rtmaddrs_ss;
	char buf[128];

	printf("[rt_msghdr=%p]\n", rtmsg);
	printf(" rtm_msglen=%u\n", rtmsg->rtm_msglen);
	printf(" rtm_version=%u\n", rtmsg->rtm_version);
	printf(" rtm_type=%u\n", rtmsg->rtm_type);
	printf(" rtm_index=%u\n", rtmsg->rtm_index);

	snprintb(buf, sizeof(buf), RTFBITS, rtmsg->rtm_flags);
	printf(" rtm_flags=%s\n", buf);
	snprintb(buf, sizeof(buf), RTABITS, rtmsg->rtm_addrs);
	printf(" rtm_addrs=%s\n", buf);

	printf(" rtm_pid=%u\n", rtmsg->rtm_pid);
	printf(" rtm_seq=%d\n", rtmsg->rtm_seq);
	printf(" rtm_errno=%d\n", rtmsg->rtm_errno);
	printf(" rtm_use=%d\n", rtmsg->rtm_use);
	printf(" rtm_inits=%d\n", rtmsg->rtm_inits);

	printf(" rtm_rmx.rmx_locks=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_locks);
	printf(" rtm_rmx.rmx_mtu=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_mtu);
	printf(" rtm_rmx.rmx_hopcount=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_hopcount);
	printf(" rtm_rmx.rmx_recvpipe=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_recvpipe);
	printf(" rtm_rmx.rmx_sendpipe=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_sendpipe);
	printf(" rtm_rmx.rmx_ssthresh=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_ssthresh);
	printf(" rtm_rmx.rmx_rtt=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_rtt);
	printf(" rtm_rmx.rmx_rttvar=%" PRIu64 "\n", rtmsg->rtm_rmx.rmx_rttvar);
	printf(" rtm_rmx.rmx_expire=%" PRId64 "\n", rtmsg->rtm_rmx.rmx_expire);
	printf(" rtm_rmx.rmx_pksent=%" PRId64 "\n", rtmsg->rtm_rmx.rmx_pksent);

	rtmaddr_unpack(rtmsg, &rtmaddrs_ss);
	rtmaddrs_dump(&rtmaddrs_ss);
	printf("\n");
}

/*
 * route_get() returns a structure with the same information as displayed by the
 * "route get" command. The `struct rtmaddrs_ss' used as argument and return value
 * is an expanded and simplified version of sockaddrs in `struct rt_msghdr'.
 */
int
route_get(struct rtmaddrs_ss *rtmaddrs_ss)
{
	static int rtseq = 0;
	struct rt_msghdr *rtmsg;
	char rtmsgbuf[sizeof(struct rt_msghdr) + 512];	/* XXX */
	ssize_t rc;
	int s, pid;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s == -1) {
		warn("socket: PF_ROUTE");
		return -1;
	}
#ifdef RO_MSGFILTER
	unsigned char msgfilter[] = { RTM_GET };
	setsockopt(s, PF_ROUTE, RO_MSGFILTER, &msgfilter, sizeof(msgfilter));
#endif

	memset(rtmsgbuf, 0, sizeof(rtmsgbuf));
	rtmsg = (struct rt_msghdr *)rtmsgbuf;
	rtmsg->rtm_type = RTM_GET;
	rtmsg->rtm_seq = ++rtseq;
	rtmsg->rtm_flags = RTF_UP|RTF_GATEWAY|RTF_HOST|RTF_STATIC;
	rtmaddr_pack(rtmaddrs_ss, rtmsg);

	do {
		rc = write(s, rtmsg, rtmsg->rtm_msglen);
	} while (rc == -1 && errno == ENOBUFS);
	if (rc == -1) {
		warn("write");
		close(s);
		return -1;
	}

	rtmsg = (struct rt_msghdr *)rtmsgbuf;
	pid = getpid();
	do {
		rc = read(s, rtmsg, sizeof(rtmsgbuf));
	} while (rc > 0 &&
	    (rtmsg->rtm_seq != rtseq || rtmsg->rtm_pid != pid));
	if (rc <= 0) {
		warn("read");
		close(s);
		return -1;
	}
	close(s);

#if defined(RTGET_DEBUG) && defined(RTABITS)
	rtmsg_dump(rtmsg);
	{
		char buf[128];
		snprintb(buf, sizeof(buf), RTABITS, rtmsg->rtm_addrs);
		printf("rtmaddrs=%s\n", buf);
	}
#endif

	rtmaddr_unpack(rtmsg, rtmaddrs_ss);
	return 0;
}

#ifdef STANDALONE_TEST
int
main(int argc, char *argv[])
{
	int i, rc;
	char buf[128];

	if (argc != 2) {
		fprintf(stderr, "usage: rtget addr\n");
		exit(1);
	}

	struct rtmaddrs_ss rtmaddrs_ss;
	memset(&rtmaddrs_ss, 0, sizeof(rtmaddrs_ss));

	if (sockaddr_pton((struct sockaddr *)&rtmaddrs_ss.dst, argv[1]) < 0) {
		fprintf(stderr, "%s: invalid address\n", argv[1]);
		exit(2);
	}
	sockaddr_init((struct sockaddr *)&rtmaddrs_ss.ifp, AF_LINK);

	rc = route_get(&rtmaddrs_ss);
	if (rc != 0) {
		sockaddr_snprintf(buf, sizeof(buf), "%D", (struct sockaddr *)&rtmaddrs_ss.dst);
		fprintf(stderr, "cannot get route: %s\n", buf);
		exit(3);
	}

#ifdef RTGET_DEBUG
	rtmaddrs_dump(&rtmaddrs_ss);
#endif

	return 0;
}
#endif /* STANDALONE_TEST */
