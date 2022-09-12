/*
 * Copyright (c) 2013 Ryo Shimizu <ryo@nerv.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#else
#include <net/if_ether.h>
#endif
#include <net/bpf.h>
#include <net/route.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "adjustmtu.h"
#include "arpresolv.h"
#include "logging.h"

static int bpfslot(void);
static int arpquery(int, const char *, struct ether_addr *, struct in_addr *, struct in_addr *, unsigned int);
static int bpfopen(const char *, int, unsigned int *);
static void bpfclose(int);
static int bpf_arpfilter(int);
static int getifinfo(const char *, int *, uint8_t *);

/* for compatibility */
#ifdef __FreeBSD__
#define ether_addr_octet octet
#endif

struct bpf_insn arp_reply_filter[] = {
	/* check ethertype */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_ADDR_LEN * 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 5),

	/* check ar_hrd == ARPHDR_ETHER && ar_pro == ETHERTYPE_IP */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ARPHRD_ETHER << 16) + ETHERTYPE_IP, 0, 3),
	/* check ar_hln, ar_pln, ar_op */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETHER_HDR_LEN + 4),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
	    (ETHER_ADDR_LEN << 24) + (sizeof(struct in_addr) << 16) +
	    ARPOP_REPLY, 0, 1),

	BPF_STMT(BPF_RET + BPF_K, -1),	/* return -1 */
	BPF_STMT(BPF_RET + BPF_K, 0),	/* return 0 */
};

#define BPFBUFSIZE	(1024 * 64)
static unsigned char bpfbuf[BPFBUFSIZE];
static unsigned int bpfbuflen = BPFBUFSIZE;
static char zeropadding[1024 * 64];

/* ethernet arp packet */
struct arppkt {
	struct ether_header eheader;
	struct {
		uint16_t ar_hrd;			/* +0x00 */
		uint16_t ar_pro;			/* +0x02 */
		uint8_t ar_hln;				/* +0x04 */
		uint8_t ar_pln;				/* +0x05 */
		uint16_t ar_op;				/* +0x06 */
		uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
		struct in_addr ar_spa;			/* +0x0e */
		uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
		struct in_addr ar_tpa;			/* +0x18 */
							/* +0x1c */
	} __packed arp;
} __packed;

int
arpresolv(const char *ifname, struct in_addr *src, struct in_addr *dst, struct ether_addr *found_macaddr, unsigned int pktsize, unsigned int timeout_us)
{
	fd_set rfd;
	struct timeval tv_wait, tv_send, tv_recv;
	struct ether_addr my_macaddr;
	int rc, mtu;
	int fd = -1;

	if ((rc = getifinfo(ifname, &mtu, my_macaddr.ether_addr_octet)) != 0)
		return rc;
	if ((fd = bpfopen(ifname, 0, &bpfbuflen)) < 0)
		return fd;

	bpf_arpfilter(fd);


	gettimeofday(&tv_send, NULL);
	rc = arpquery(fd, ifname, &my_macaddr, src, dst, pktsize);
	if (rc < 0) {
		if (errno == EMSGSIZE) {
			logging(LOG_DEBUG, "%s: send %d+%d bytes padded arp query: %s",
			    inet_ntoa(*dst), ETHER_HDR_LEN, pktsize - ETHER_HDR_LEN, strerror(errno));
			return errno;
		}
		logging(LOG_ERR, "%s: send %d+%d bytes padded arp query: %s",
		    inet_ntoa(*dst), ETHER_HDR_LEN, pktsize - ETHER_HDR_LEN, strerror(errno));
		return errno;
	}


	for (;;) {
		tv_wait.tv_sec = timeout_us / 1000000;
		tv_wait.tv_usec = timeout_us % 1000000;
		FD_ZERO(&rfd);
		FD_SET(fd, &rfd);
		int nfound = select(fd + 1, &rfd, NULL, NULL, &tv_wait);
		gettimeofday(&tv_recv, NULL);
		if (nfound < 0) {
			logging(LOG_ERR, "select: %s", strerror(errno));
			rc = -1;
			break;
		}

		if (nfound == 0) {
			logging(LOG_DEBUG, "%s: %d+%d bytes padded arp query timeout",
			    inet_ntoa(*dst), ETHER_HDR_LEN, pktsize - ETHER_HDR_LEN);
			rc = ETIMEDOUT;
			break;
		}
		if (FD_ISSET(fd, &rfd)) {
			ssize_t size = read(fd, bpfbuf, bpfbuflen);
			if (size == 0) {
				logging(LOG_ERR, "read: bpf: no data");
				rc = -1;
				break;
			}
			if (size < 0) {
				logging(LOG_ERR, "read: %s", strerror(errno));
				rc = -1;
				break;
			}

			uint8_t *p = bpfbuf;
			uint8_t *end = p + size;
			while (p < end) {
				unsigned int capsize =
				    ((struct bpf_hdr*)p)->bh_hdrlen +
				    ((struct bpf_hdr*)p)->bh_caplen;

				struct arppkt *arppkt = (struct arppkt *)((uint8_t *)p + ((struct bpf_hdr*)p)->bh_hdrlen);
				__unused unsigned int arplen = ((struct bpf_hdr*)p)->bh_datalen;

#ifdef ARPRESOLV_DEBUG
				char xbuf[64];
				printf("pktsize = %u\n", pktsize);
				printf("RECV: sha=%s\n", ether_ntoa((const struct ether_addr *)arppkt->arp.ar_sha));
				printf("RECV: tha=%s\n", ether_ntoa((const struct ether_addr *)arppkt->arp.ar_tha));
				printf("RECV: spa=%s\n", inet_ntop(AF_INET, &arppkt->arp.ar_spa, xbuf, sizeof(xbuf)));
				printf("RECV: tpa=%s\n", inet_ntop(AF_INET, &arppkt->arp.ar_tpa, xbuf, sizeof(xbuf)));
				printf("MyMacaddr=%s\n", ether_ntoa((const struct ether_addr *)my_macaddr.ether_addr_octet));
				printf("  dstaddr=%s\n", inet_ntop(AF_INET, dst, xbuf, sizeof(xbuf)));
				printf("  srcaddr=%s\n", inet_ntop(AF_INET, src, xbuf, sizeof(xbuf)));
#endif

				/* Ensure that it is a reply to my arp request */
				if (arppkt->arp.ar_spa.s_addr == dst->s_addr &&
				    arppkt->arp.ar_tpa.s_addr == src->s_addr &&
				    memcmp(arppkt->arp.ar_tha, my_macaddr.ether_addr_octet, ETHER_ADDR_LEN) == 0) {
					memcpy(found_macaddr, arppkt->arp.ar_sha, sizeof(*found_macaddr));

					/* catch the arp reply successfully */
					logging(LOG_DEBUG,
					    "%s: send %d+%d bytes arp query: echo arp reply OK (%.3f ms)",
					    inet_ntoa(*dst), ETHER_HDR_LEN, pktsize - ETHER_HDR_LEN,
					    tv_delta(&tv_send, &tv_recv) / 1000.0);

					rc = 0;
					goto done;
				}

				p += BPF_WORDALIGN(capsize);
			}
		}
	}
 done:

	bpfclose(fd);

	return rc;
}

static int
arpquery(int fd, const char *ifname, struct ether_addr *sha, struct in_addr *src, struct in_addr *dst, unsigned int pktsize)
{
	ssize_t rc;
	struct arppkt aquery;
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* build arp reply packet */
	memset(&aquery, 0, sizeof(aquery));
	memcpy(&aquery.eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN);
	memcpy(&aquery.eheader.ether_shost, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	aquery.eheader.ether_type = htons(ETHERTYPE_ARP);
	aquery.arp.ar_hrd = htons(ARPHRD_ETHER);
	aquery.arp.ar_pro = htons(ETHERTYPE_IP);
	aquery.arp.ar_hln = ETHER_ADDR_LEN;
	aquery.arp.ar_pln = sizeof(struct in_addr);
	aquery.arp.ar_op = htons(ARPOP_REQUEST);
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet,
	    ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_spa, src, sizeof(struct in_addr));
	memcpy(&aquery.arp.ar_sha, sha->ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&aquery.arp.ar_tpa, dst, sizeof(struct in_addr));

	if (pktsize < sizeof(struct arppkt))
		pktsize = sizeof(struct arppkt);

	int paddingsize = pktsize - sizeof(struct arppkt);

	/* send an arp-query via bpf */
	if (paddingsize == 0) {
		rc = write(fd, &aquery, sizeof(aquery));
	} else {
		struct iovec iov[2];
		iov[0].iov_base = &aquery;
		iov[0].iov_len = sizeof(aquery);
		iov[1].iov_base = zeropadding;
		iov[1].iov_len = paddingsize;
		rc = writev(fd, iov, 2);
	}
	if (rc < 0)
		return -1;
	return 0;
}

static int
bpfslot()
{
	int fd, i;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[PATH_MAX + 1];

	memset(devbpf, 0, sizeof(devbpf));
	i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

static int
bpf_arpfilter(int fd)
{
	struct bpf_program bpfprog;
	int rc;

	memset(&bpfprog, 0, sizeof(bpfprog));

	bpfprog.bf_len = __arraycount(arp_reply_filter);
	bpfprog.bf_insns = arp_reply_filter;

	rc = ioctl(fd, BIOCSETF, &bpfprog);
	if (rc != 0)
		warn("ioctl: BIOCSETF (arp filter)");

	return rc;
}

static int
bpfopen(const char *ifname, int promisc, unsigned int *buflen)
{
	int fd, flag, rc;
	struct ifreq ifr;
	struct bpf_version bv;

	rc = 0;
	fd = bpfslot();
	if (fd < 0) {
		warn("open: bpf");
		rc = -1;
		goto bpfopen_err;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		warn("ioctl: BIOCVERSION");
		rc = -1;
		goto bpfopen_err;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		fprintf(stderr, "kernel bpf filter out of date");
		rc = -1;
		goto bpfopen_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (ifname != NULL) {
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
			warn("ioctl: %s: BIOCSETIF", ifname);
			rc = -2;
			goto bpfopen_warn;
		}
	}

	flag = 1;
	ioctl(fd, BIOCIMMEDIATE, &flag);

	if (promisc) {
		if (ioctl(fd, BIOCPROMISC, 0) != 0) {
			warn("ioctl: BIOCPROMISC: %s", ifname);
		}
	}

	ioctl(fd, BIOCSBLEN, buflen);
	ioctl(fd, BIOCGBLEN, buflen);	/* return value for caller */

	return fd;

 bpfopen_warn:
 bpfopen_err:
	if (fd >= 0)
		close(fd);

	return rc;
}

static void
bpfclose(int fd)
{
	close(fd);
}

static int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int mib[6] = {
		CTL_NET,
		AF_ROUTE,
		0,
		AF_LINK,
		NET_RT_IFLIST,
		0
	};
	uint8_t *buf, *end, *msghdr;
	struct if_msghdr *ifm;
	struct if_data *ifd = NULL;
	struct sockaddr_dl *sdl;
	size_t len;
	int rc;

	rc = -1;
	buf = NULL;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist size",
		    strerror(errno));
		goto getifinfo_done;
	}
	if ((buf = malloc(len)) == NULL) {
		fprintf(stderr, "cannot allocate memory");
		goto getifinfo_done;
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		fprintf(stderr, "sysctl: %s: cannot get iflist",
		    strerror(errno));
		goto getifinfo_done;
	}

	end = buf + len;
	for (msghdr = buf; msghdr < end; msghdr += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)msghdr;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);

			if (sdl->sdl_type != IFT_ETHER)
				continue;
			if (sdl->sdl_nlen != strnlen(ifname, IFNAMSIZ))
				continue;
			if (strncmp(&sdl->sdl_data[0], ifname, sdl->sdl_nlen)
			    != 0)
				continue;

			ifd = &ifm->ifm_data;
			if (mtu != NULL)
				*mtu = ifd->ifi_mtu;
			memcpy(hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			rc = 0;
			break;
		}
	}
	if (rc != 0)
		fprintf(stderr,
		    "%s: Not a ethernet interface or no such interface\n",
		    ifname);

 getifinfo_done:
	if (buf != NULL)
		free(buf);

	return rc;
}
