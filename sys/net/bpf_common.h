/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *      @(#)bpf_filter.c	8.1 (Berkeley) 6/10/93
 */

#ifndef __i386__
#define BPF_ALIGN
#endif

#ifndef BPF_ALIGN
#define EXTRACT_SHORT(p)	((u_int16_t)ntohs(*(u_int16_t *)p))
#define EXTRACT_LONG(p)		(ntohl(*(u_int32_t *)p))
#else
#define EXTRACT_SHORT(p)\
	((u_int16_t)\
		((u_int16_t)*((u_char *)p+0)<<8|\
		 (u_int16_t)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((u_int32_t)*((u_char *)p+0)<<24|\
		 (u_int32_t)*((u_char *)p+1)<<16|\
		 (u_int32_t)*((u_char *)p+2)<<8|\
		 (u_int32_t)*((u_char *)p+3)<<0)
#endif

#ifdef _KERNEL
#include <sys/mbuf.h>
#else
#include <stdlib.h>
#endif
#include <net/bpf.h>
#ifdef _KERNEL
#define MINDEX(m, k) \
{ \
	int len = m->m_len; \
 \
	while (k >= len) { \
		k -= len; \
		m = m->m_next; \
		if (m == 0) \
			return (0); \
		len = m->m_len; \
	} \
}

static u_int16_t	m_xhalf(struct mbuf *m, bpf_u_int32 k, int *err);
static u_int32_t	m_xword(struct mbuf *m, bpf_u_int32 k, int *err);

static u_int32_t
m_xword(struct mbuf *m, bpf_u_int32 k, int *err)
{
	size_t len;
	u_char *cp, *np;
	struct mbuf *m0;

	len = m->m_len;
	while (k >= len) {
		k -= len;
		m = m->m_next;
		if (m == NULL)
			goto bad;
		len = m->m_len;
	}
	cp = mtod(m, u_char *) + k;
	if (len - k >= 4) {
		*err = 0;
		return (EXTRACT_LONG(cp));
	}
	m0 = m->m_next;
	if (m0 == NULL || m0->m_len + len - k < 4)
		goto bad;
	*err = 0;
	np = mtod(m0, u_char *);
	switch (len - k) {
	case 1:
		return (((u_int32_t)cp[0] << 24) |
		    ((u_int32_t)np[0] << 16) |
		    ((u_int32_t)np[1] << 8)  |
		    (u_int32_t)np[2]);

	case 2:
		return (((u_int32_t)cp[0] << 24) |
		    ((u_int32_t)cp[1] << 16) |
		    ((u_int32_t)np[0] << 8) |
		    (u_int32_t)np[1]);

	default:
		return (((u_int32_t)cp[0] << 24) |
		    ((u_int32_t)cp[1] << 16) |
		    ((u_int32_t)cp[2] << 8) |
		    (u_int32_t)np[0]);
	}
    bad:
	*err = 1;
	return (0);
}

static u_int16_t
m_xhalf(struct mbuf *m, bpf_u_int32 k, int *err)
{
	size_t len;
	u_char *cp;
	struct mbuf *m0;

	len = m->m_len;
	while (k >= len) {
		k -= len;
		m = m->m_next;
		if (m == NULL)
			goto bad;
		len = m->m_len;
	}
	cp = mtod(m, u_char *) + k;
	if (len - k >= 2) {
		*err = 0;
		return (EXTRACT_SHORT(cp));
	}
	m0 = m->m_next;
	if (m0 == NULL)
		goto bad;
	*err = 0;
	return ((cp[0] << 8) | mtod(m0, u_char *)[0]);
 bad:
	*err = 1;
	return (0);
}
#endif
