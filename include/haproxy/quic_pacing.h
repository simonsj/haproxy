#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

#include <haproxy/list.h>
#include <haproxy/quic_frame.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc_path *path)
{
	LIST_INIT(&pacer->frms);
	pacer->path = path;
	pacer->next = 0;
}

static inline void quic_pacing_reset(struct quic_pacer *pacer)
{
	struct quic_frame *frm;

	while (!LIST_ISEMPTY(&pacer->frms)) {
		frm = LIST_ELEM(pacer->frms.n, struct quic_frame *, list);
		/* qc_frm_free is responsible to detach frm from pacer list. */
		qc_frm_free(NULL, &frm);
	}
}

static inline struct list *quic_pacing_frms(struct quic_pacer *pacer)
{
	return &pacer->frms;
}

static inline ullong quic_pacing_ns_pkt(const struct quic_pacer *pacer)
{
	return pacer->path->loss.srtt * 1000000 / (pacer->path->cwnd / pacer->path->mtu + 1);
}

int quic_pacing_expired(const struct quic_pacer *pacer);

void quic_pacing_sent_done(struct quic_pacer *pacer, int sent);

#endif /* _HAPROXY_QUIC_PACING_H */
