#ifndef _RTMSG_UTILS_H_
#define _RTMSG_UTILS_H_

struct rtmaddrs_ss {
	struct sockaddr_storage dst;		/* RTA_DST */
	struct sockaddr_storage gateway;	/* RTA_GATEWAY */
	struct sockaddr_storage netmask;	/* RTA_NETMASK */
	struct sockaddr_storage genmask;	/* RTA_GENMASK */
	struct sockaddr_storage ifp;		/* RTA_IFP */
	struct sockaddr_storage ifa;		/* RTA_IFA */
#if 0
	struct sockaddr_storage author;		/* RTA_AUTHOR */
	struct sockaddr_storage brd;		/* RTA_BRD */
#endif
	struct sockaddr_storage tag;		/* RTA_TAG */
};

void rtmaddr_pack(const struct rtmaddrs_ss * const, struct rt_msghdr *);
void rtmaddr_unpack(const struct rt_msghdr * const, struct rtmaddrs_ss *);
void rtmaddrs_dump(struct rtmaddrs_ss *);
void rtmsg_dump(const struct rt_msghdr *);

int route_get(struct rtmaddrs_ss *);
int sockaddr_init(struct sockaddr *, sa_family_t);
int sockaddr_pton(struct sockaddr *, const char *);


#endif /* _RTMSG_UTILS_H_ */
