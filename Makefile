#	$Id: Makefile,v 1.3 2010/08/02 04:00:15 ryo Exp $

PROG=	adjustmtu
SRCS=	adjustmtu.c

NOMAN=	yes

LDADD+=	
DPADD+=	

.include <bsd.prog.mk>
