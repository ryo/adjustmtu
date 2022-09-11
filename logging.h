#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <syslog.h>

void logging_open(const char *ident, int logopt, int facility);
void logging_filter(int, int);
void logging(int, char const *fmt, ...);
void logging_close(void);

#endif /* _LOGGING_H_ */
