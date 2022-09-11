#	$Id: Makefile,v 1.5 2022/09/09 19:26:54 ryo Exp $

PROG=	adjustmtu
SRCS=	adjustmtu.c rtmsg_utils.c arpresolv.c logging.c
WARNS=	4

NOMAN=	yes

LDADD+=	-lutil
DPADD+=	

.include <bsd.prog.mk>
