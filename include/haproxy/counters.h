/*
 * include/haproxy/counters.h
 * objects counters management
 *
 * Copyright 2025 HAProxy Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_COUNTERS_H
# define _HAPROXY_COUNTERS_H

#include <stddef.h>

#include <haproxy/counters-t.h>
#include <haproxy/guid-t.h>

extern THREAD_LOCAL void *trash_counters;

int counters_fe_shared_prepare(struct fe_counters_shared *counters, const struct guid_node *guid, char **errmsg);
int counters_be_shared_prepare(struct be_counters_shared *counters, const struct guid_node *guid, char **errmsg);

void counters_fe_shared_drop(struct fe_counters_shared *counters);
void counters_be_shared_drop(struct be_counters_shared *counters);

/* time oriented helper: get last time (relative to current time) on a given
 * <scounter> array, for <elem> member (one member per thread group) which is
 * assumed to be unsigned long type.
 *
 * wrapping is handled by taking the lowest diff between now and last counter.
 * But since wrapping is expected once every ~136 years (starting 01/01/1970),
 * perhaps it's not worth the extra CPU cost.. let's see.
 */
#define COUNTERS_SHARED_LAST_OFFSET(scounters, type, offset)                  \
({                                                                            \
	unsigned long last = 0;                                               \
	unsigned long now_seconds = ns_to_sec(now_ns);                        \
	int it;                                                               \
                                                                              \
	if (scounters)                                                        \
		last = HA_ATOMIC_LOAD((type *)((char *)scounters[0] + offset));\
	for (it = 1; (it < global.nbtgroups && scounters); it++) {            \
		unsigned long cur = HA_ATOMIC_LOAD((type *)((char *)scounters[it] + offset));\
		if ((now_seconds - cur) < (now_seconds - last))               \
			last = cur;                                           \
        }                                                                     \
	last;                                                                 \
})

#define COUNTERS_SHARED_LAST(scounters, elem)                                 \
({                                                                            \
        int offset = offsetof(typeof(**scounters), elem);                     \
        unsigned long last = COUNTERS_SHARED_LAST_OFFSET(scounters, typeof(scounters[0]->elem), offset);  \
	                                                                      \
	last;                                                                 \
})


/* generic unsigned integer addition for all <elem> members from
 * <scounters> array (one member per thread group)
 * <rfunc> is function taking pointer as parameter to read from the memory
 * location pointed to scounters[it].elem
 */
#define COUNTERS_SHARED_TOTAL_OFFSET(scounters, type, offset, rfunc)          \
({                                                                            \
	uint64_t __ret = 0;                                                   \
        int it;                                                               \
                                                                              \
	for (it = 0; (it < global.nbtgroups && scounters); it++)              \
		__ret += rfunc((type *)((char *)scounters[it] + offset));     \
	__ret;                                                                \
})

#define COUNTERS_SHARED_TOTAL(scounters, elem, rfunc)                         \
({                                                                            \
	int offset = offsetof(typeof(**scounters), elem);                     \
	uint64_t __ret = COUNTERS_SHARED_TOTAL_OFFSET(scounters, typeof(scounters[0]->elem), offset, rfunc);\
                                                                              \
	__ret;                                                                \
})
/* same as COUNTERS_SHARED_TOTAL but with <rfunc> taking 2 extras arguments:
 * <arg1> and <arg2>
 */
#define COUNTERS_SHARED_TOTAL_ARG2(scounters, elem, rfunc, arg1, arg2)        \
({                                                                            \
	uint64_t __ret = 0;                                                   \
	int it;                                                               \
                                                                              \
	for (it = 0; (it < global.nbtgroups && scounters); it++)              \
		__ret += rfunc(&scounters[it]->elem, arg1, arg2);             \
	__ret;                                                                \
})

/* Manipulation of extra_counters, for boot-time registrable modules */
#define EXTRA_COUNTERS_GET(counters, mod) \
	(likely(counters) ? \
		((void *)(*(counters)->datap + (mod)->counters_off[(counters)->type])) : \
		(trash_counters))

#define EXTRA_COUNTERS_REGISTER(counters, ctype, alloc_failed_label, storage)	\
	do {                                                         \
		typeof(*counters) _ctr;                              \
		_ctr = calloc(1, sizeof(*_ctr));                     \
		if (!_ctr)                                           \
			goto alloc_failed_label;                     \
		_ctr->type = (ctype);                                \
		_ctr->datap = (storage);                             \
		*(counters) = _ctr;                                  \
	} while (0)

#define EXTRA_COUNTERS_ADD(mod, counters, new_counters, csize) \
	do {                                                   \
		typeof(counters) _ctr = (counters);            \
		(mod)->counters_off[_ctr->type] = _ctr->size;  \
		_ctr->size += (csize);                         \
	} while (0)

#define EXTRA_COUNTERS_ALLOC(counters, alloc_failed_label) \
	do {                                               \
		typeof(counters) _ctr = (counters);        \
		*_ctr->datap = malloc((_ctr)->size);       \
		if (!*_ctr->datap)                         \
			goto alloc_failed_label;           \
	} while (0)

#define EXTRA_COUNTERS_INIT(counters, mod, init_counters, init_counters_size) \
	do {                                                                  \
		typeof(counters) _ctr = (counters);                           \
		memcpy(*_ctr->datap + mod->counters_off[_ctr->type],          \
		       (init_counters), (init_counters_size));                \
	} while (0)

#define EXTRA_COUNTERS_FREE(counters)           \
	do {                                    \
		if (counters) {                 \
			ha_free((counters)->datap);\
			free(counters);         \
		}                               \
	} while (0)

#endif /* _HAPROXY_COUNTERS_H */
