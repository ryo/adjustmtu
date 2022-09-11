#ifndef _ADJUSTMTU_H_
#define _ADJUSTMTU_H_

inline static unsigned long
tv_delta(struct timeval *a, struct timeval *b)
{
	unsigned long d;

	d = (b->tv_sec * 1000000 + b->tv_usec) -
	    (a->tv_sec * 1000000 + a->tv_usec);

	return d;
}

#endif /* _ADJUSTMTU_H_ */
