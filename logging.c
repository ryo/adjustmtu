#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "logging.h"

static int syslog_opened = 0;
static unsigned int logging_bitmap = 0xffffffff;

void
logging_open(const char *ident, int logopt, int facility)
{
	openlog("adjustmtu", LOG_PID, LOG_DAEMON);
	syslog_opened = 1;
}

void
logging_close(void)
{
	syslog_opened = 0;
}

void
logging_filter(int prio, int show)
{
	if (prio < 0 || prio >= 32)
		return;

	if (show)
		logging_bitmap |= (1U << prio);
	else
		logging_bitmap &= ~(1U << prio);
}

void
logging(int prio, char const *fmt, ...)
{
	va_list ap;

	if ((logging_bitmap & (1U << prio)) == 0)
		return;

	va_start(ap, fmt);
	if (syslog_opened) {
		vsyslog(prio, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		printf("\n");
	}
	va_end(ap);
}

