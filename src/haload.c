#include <openssl/ssl.h>

#include <haproxy/api.h>
#include <haproxy/dynbuf.h>
#include <haproxy/errors.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/hastream-t.h>
#include <haproxy/haload.h>
#include <haproxy/proxy.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/protocol.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>

/* haload stream state flags */
#define HXS_ST_IN_ALLOC    0x0001
#define HXS_ST_OUT_ALLOC   0x0002
#define HXS_ST_CONN_ERR    0x0004
#define HXS_ST_HDRS_SENT   0x0008
#define HXS_ST_MUST_SEND   0x0010
#define HXS_ST_MUST_RECV   0x0020
#define HXS_ST_GOT_RESP_SL 0x0040

struct haload_thr_info {
	struct timeval now;          // current time
	struct freq_ctr req_rate;    // thread's measured request rate
	struct freq_ctr conn_rate;   // thread's measured connection rate
	uint32_t cur_req;            // number of active requests
	uint32_t curconn;            // number of active connections
	uint32_t maxconn;            // max number of active connections
	uint32_t is_ssl;             // non-zero if SSL is used
	uint64_t tot_conn;           // total conns attempted on this thread
	uint64_t tot_req;            // total requests started on this thread
	uint64_t tot_done;           // total requests finished (successes+failures)
	uint64_t tot_sent;           // total bytes sent on this thread
	uint64_t tot_rcvd;           // total bytes received on this thread
	uint64_t tot_serr;           // total socket errors on this thread
	uint64_t tot_cerr;           // total connection errors on this thread
	uint64_t tot_xerr;           // total xfer errors on this thread
	uint64_t tot_perr;           // total protocol errors on this thread
	uint64_t tot_cto;            // total connection timeouts on this thread
	uint64_t tot_xto;            // total xfer timeouts on this thread
	uint64_t tot_fbs;            // total number of ttfb samples
	uint64_t tot_ttfb;           // total time-to-first-byte (us)
	uint64_t tot_lbs;            // total number of ttlb samples
	uint64_t tot_ttlb;           // total time-to-last-byte (us)
	uint64_t *ttfb_pct;          // counts per ttfb value for percentile
	uint64_t *ttlb_pct;          // counts per ttlb value for percentile
	uint64_t tot_sc[5];          // total status codes on this thread: 1xx,2xx,3xx,4xx,5xx
	int epollfd;                 // poller's FD
	int start_len;               // request's start line's length
	char *start_line;            // copy of the request's start line to be sent
	char *hdr_block;             // copy of the request's header block to be sent
	int hdr_len;                 // request's header block's length
	int ka_req_len;              // keep-alive request length
	char *ka_req;                // fully assembled keep-alive request
	char *cl_req;                // fully assembled close request
	int cl_req_len;              // close request length
	int tid;                     // thread number
	struct timeval start_date;   // thread's start date
	struct sockaddr_storage dst; // destination address
	struct sockaddr_storage pre_heat; // destination address for pre-heat
	struct epoll_event *events;  // event buffer
#if defined(USE_SSL)
	SSL_CTX *ssl_ctx;            // ssl context
	unsigned char *ssl_sess;     // stored ssl session;
	int ssl_sess_size;           // size of current stored session.
	int ssl_sess_allocated;      // current allocated size of stored session
#endif
	__attribute__((aligned(64))) union { } __pad;
};

struct haload_thr_info *thrs_info;

struct haload_srv haload_srv;
struct list haload_hdrs = LIST_HEAD_INIT(haload_hdrs);
struct proxy haload_proxy;
struct task *mtask; // main task (stats listing every 1s)

const char *arg_host;
const char *arg_conn_hdr;
const char *arg_uri;
const char *arg_path;

int nbc = 1;
int arg_long;
int arg_head;
int conn_tid;

#define TRACE_SOURCE &trace_haload
struct trace_source trace_haload;
static void haload_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                         const struct ist where, const struct ist func,
                         const void *a1, const void *a2, const void *a3, const void *a4);
struct task *haload_io_cb(struct task *t, void *context, unsigned int state);
static inline void hastream_free(struct hastream **hs);

static const struct name_desc haload_trace_logon_args[4] = {
	/* arg1 */ { /* already used by the haload stream */ },
	/* arg2 */ {
		.name = "haload",
		.desc = "haload client",
	},
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct trace_event haload_trace_events[] = {
#define HXS_EV_TX     (1ULL << 0)
	{ .mask = HXS_EV_TX,     .name = "tx",     .desc = "haload sending" },
#define HXS_EV_TX_BLK (1ULL << 1)
	{ .mask = HXS_EV_TX_BLK, .name = "tx_blk", .desc = "haload sending blocked" },
#define HXS_EV_RX     (1ULL << 2)
	{ .mask = HXS_EV_RX,     .name = "rx",     .desc = "haload receiving" },
#define HXS_EV_RX_BLK (1ULL << 3)
	{ .mask = HXS_EV_RX_BLK, .name = "rx_blk", .desc = "haload receiving blocked" },
#define HXS_EV_TASK   (1ULL << 4)
	{ .mask = HXS_EV_TASK, .name = "task",     .desc = "haload main task" },
#define HXS_EV_IO_CB  (1ULL << 5)
	{ .mask = HXS_EV_IO_CB, .name = "io_cb",   .desc = "stconn i/o callback call" },
};

static const struct name_desc haload_trace_decoding[] = {
#define HALOAD_VERB_CLEAN 1
	{ .name = "clean", .desc = "only user-friendly stuff, generally suitable for level \"user\"" },
};

struct trace_source trace_haload = {
	.name = IST("haload"),
	.desc = "haload benchmark tool",
	/* TRACE()'s first argument is always a haload stream */
	.arg_def = TRC_ARG1_HXSTRM,
	.default_cb = haload_trace,
	.known_events = haload_trace_events,
	.lockon_args = haload_trace_logon_args,
	.decoding = haload_trace_decoding,
	.report_events = ~0, /* report everything by default */
};

INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static void haload_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                         const struct ist where, const struct ist func,
                         const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct hastream *hs = a1;

	if (!hs || src->verbosity < HALOAD_VERB_CLEAN)
		return;

	chunk_appendf(&trace_buf, " hs@%p to_send=%llu", hs, hs->to_send);
	if (hs->sc) {
		struct connection *conn = sc_conn(hs->sc);
		chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn ? conn->flags : 0);
		chunk_appendf(&trace_buf, " sc=%p(0x%08x)", hs->sc, hs->sc->flags);
	}
}

int hastream_buf_available(void *target)
{
	struct hastream *hs = target;

	if ((hs->flags & HXS_ST_IN_ALLOC) && b_alloc(&hs->bi, DB_CHANNEL)) {
		hs->flags &= ~HXS_ST_IN_ALLOC;
		TRACE_STATE("unblocking stream, input buffer allocated",
		            HXS_EV_RX|HXS_EV_RX_BLK, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	if ((hs->flags & HXS_ST_OUT_ALLOC) && b_alloc(&hs->bo, DB_CHANNEL)) {
		hs->flags &= ~HXS_ST_OUT_ALLOC;
		TRACE_STATE("unblocking stream, ouput buffer allocated",
		            HXS_EV_TX|HXS_EV_TX_BLK, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	return 0;
}

/* Allocate a buffer. If it fails, it adds the stream in buffer wait queue */
struct buffer *hastream_get_buf(struct hastream *hs, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&hs->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_CHANNEL)) == NULL)) {
		b_queue(DB_CHANNEL, &hs->buf_wait, hs, hastream_buf_available);
	}

	return buf;
}

static inline struct buffer *hastream_get_obuf(struct hastream *hs)
{
	return hastream_get_buf(hs, &hs->bo);
}

static inline struct buffer *hastream_get_ibuf(struct hastream *hs)
{
	return hastream_get_buf(hs, &hs->bi);
}

/* Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
void hastream_release_buf(struct hastream *hs, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(hs->buf_wait.target, 1);
	}
}

static inline void hastream_release_ibuf(struct hastream *hs)
{
	hastream_release_buf(hs, &hs->bi);
}

static inline void hastream_release_obuf(struct hastream *hs)
{
	hastream_release_buf(hs, &hs->bo);
}

/* Creates a new stream connector from a haload connection. There is no endpoint
 * here, thus it will be created by sc_new(). So the SE_FL_DETACHED flag is set.
 * It returns NULL on error. On success, the new stream connector is returned.
 */
struct stconn *sc_new_from_hastream(struct hastream *hs, unsigned int flags)
{
	struct stconn *sc;

	sc = sc_new(NULL);
	if (unlikely(!sc))
		return NULL;

	sc->flags |= flags;
	sc_ep_set(sc, SE_FL_DETACHED);
	sc->app = &hs->obj_type;
	return sc;
}

int haload_sc_attach_mux(struct stconn *sc, void *sd, void *ctx)
{
	struct connection *conn = ctx;
	struct sedesc *sedesc = sc->sedesc;

	if (sc_hastream(sc)) {
		if (!sc->wait_event.tasklet) {
			sc->wait_event.tasklet = tasklet_new();
			if (!sc->wait_event.tasklet)
				return -1;
			sc->wait_event.tasklet->process = haload_io_cb;
			sc->wait_event.tasklet->context = sc;
			sc->wait_event.events = 0;
		}
	}

	sedesc->se = sd;
	sedesc->conn = ctx;
	se_fl_set(sedesc, SE_FL_T_MUX);
	se_fl_clr(sedesc, SE_FL_DETACHED);
	if (!conn->ctx)
		conn->ctx = sc;

	return 0;
}

/* main task */
static struct task *mtask_cb(struct task *t, void *context, unsigned int state)
{
	
	TRACE_ENTER(HXS_EV_TX);
	mtask->expire = tick_add(now_ms, MS_TO_TICKS(1000));
leave:
	TRACE_LEAVE(HXS_EV_TX);
	return t;
}

static int hastream_build_http_req(struct hastream *hs, struct ist uri, int eom)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	struct htx_sl *sl;
	struct ist meth_ist;
	struct haload_hdr *hdr;
#if 1
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_HAS_SCHM | HTX_SL_F_HAS_AUTHORITY |
		(!hs->to_send ? HTX_SL_F_BODYLESS : 0);
#else
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_HAS_SCHM | HTX_SL_F_HAS_AUTHORITY;
#endif

	TRACE_ENTER(HXS_EV_TX, hs);
	buf = hastream_get_obuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for ouput buffer", HXS_EV_TX|HXS_EV_TX_BLK, hs);
		hs->flags |= HXS_ST_OUT_ALLOC;
		goto leave;
	}

	htx = htx_from_buf(buf);
	meth_ist = !arg_head ? ist("GET") : ist("HEAD");
	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth_ist, ist(arg_path), ist("HTTP/1.1"));
	if (!sl)
		goto err;

	sl->info.req.meth = !arg_head ? HTTP_METH_GET : HTTP_METH_HEAD;
	list_for_each_entry(hdr, &haload_hdrs, list)
		if (!htx_add_header(htx, hdr->name, hdr->value))
			goto err;
	
	if (!arg_host && !http_update_host(htx, sl, uri))
	    goto err;

	if (!arg_conn_hdr && !http_add_header(htx, ist("Connection"), ist("close")))
		goto err;

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto err;

	if (eom)
		htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &hs->bo);
 leave:
	ret = 1;
	TRACE_LEAVE(HXS_EV_TX, hs);
	return ret;
 err:
	hs->flags |= HXS_ST_CONN_ERR;
	TRACE_DEVEL("leaving on error", HXS_EV_TX, hs);
	goto leave;
}

/* Send HTX data prepared for <hs> haload stream from <conn> connection */
static int hastream_htx_buf_snd(struct connection *conn, struct hastream *hs)
{
	struct stconn *sc = hs->sc;
	int ret = 0;
	int nret;

	TRACE_ENTER(HXS_EV_TX, hs);

	if (!htxbuf(&hs->bo)->data) {
		/* This is possible after having drained the body, so after
		 * having sent the response here when req_after_res=1.
		 */
		ret = 1;
		goto out;
	}

	fprintf(stderr, "to send=%d", htxbuf(&hs->bo)->data);
	nret = conn->mux->snd_buf(hs->sc, &hs->bo, htxbuf(&hs->bo)->data, 0);
	fprintf(stderr, " sent=%d\n", nret);
	if (nret <= 0) {
		if (hs->flags & HXS_ST_CONN_ERR ||
		    conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR)) {
			TRACE_DEVEL("connection error during send", HXS_EV_TX, hs);
			goto out;
		}
	}

	/* The HTX data are not fully sent if the last HTX data
	 * were not fully transfered or if there are remaining data
	 * to send (->to_send > 0).
	 */
	if (!htx_is_empty(htxbuf(&hs->bo))) {
		TRACE_DEVEL("data not fully sent, wait", HXS_EV_TX, hs);
		conn->mux->subscribe(sc, SUB_RETRY_SEND, &sc->wait_event);
	}
	else if (hs->to_send) {
		TRACE_STATE("waking up task", HXS_EV_TX, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}

	ret = 1;
 out:
	if (htx_is_empty(htxbuf(&hs->bo)) || ret == 0) {
		TRACE_DEVEL("releasing underlying buffer", HXS_EV_TX, hs);
		hastream_release_obuf(hs);
	}

	TRACE_LEAVE(HXS_EV_TX, hs);
	return ret;
}

static void hastream_htx_buf_rcv(struct connection *conn,
                                 struct hastream *hs, int *fin)
{
	struct buffer *buf;
	size_t max, read = 0, cur_read = 0;
	int is_empty;
	struct htx_sl *sl = NULL;

	TRACE_ENTER(HXS_EV_RX, hs);

	*fin = 0;
	if (hs->sc->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("subscribed for RECV, waiting for data", HXS_EV_RX, hs);
		goto leave;
	}

	if (sc_ep_test(hs->sc, SE_FL_EOS)) {
		TRACE_STATE("end of stream", HXS_EV_RX, hs);
		goto leave;
	}

	if (hs->flags & HXS_ST_IN_ALLOC) {
		TRACE_STATE("waiting for input buffer", HXS_EV_RX, hs);
		goto leave;
	}

	buf = hastream_get_ibuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for input buffer", HXS_EV_RX, hs);
		hs->flags |= HXS_ST_IN_ALLOC;
		goto leave;
	}

	while (sc_ep_test(hs->sc, SE_FL_RCV_MORE) ||
	       (!(conn->flags & CO_FL_ERROR) &&
	        !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS))) {
		htx_reset(htxbuf(&hs->bi));
		max = (IS_HTX_SC(hs->sc) ?
		       htx_free_space(htxbuf(&hs->bi)) : b_room(&hs->bi));
		sc_ep_clr(hs->sc, SE_FL_WANT_ROOM);
		read = conn->mux->rcv_buf(hs->sc, &hs->bi, max, 0);
		if (!(hs->flags & HXS_ST_GOT_RESP_SL) && read && !sl) {
			sl = http_get_stline(htx_from_buf(&hs->bi));
			if (!sl) {
				TRACE_ERROR("start line not found", HXS_EV_RX, hs);
				hs->flags |= HXS_ST_CONN_ERR;
				goto leave;
			}

			hs->flags |= HXS_ST_GOT_RESP_SL;
			TRACE_PRINTF(TRACE_LEVEL_PROTO, HXS_EV_RX, hs, 0, 0, 0,
			             "HTTP status: %d cur_read=%d\n",
			             sl->info.res.status, (int)cur_read);
		}

		cur_read += read;
		if (!htx_expect_more(htxbuf(&hs->bi))) {
		    *fin = 1;
		    break;
		}

		if (!read)
			break;
	}

	is_empty = (IS_HTX_SC(hs->sc) ?
	            htx_is_empty(htxbuf(&hs->bi)) : !b_data(&hs->bi));
	if (is_empty &&
	    ((conn->flags & CO_FL_ERROR) || sc_ep_test(hs->sc, SE_FL_ERROR))) {
		/* Report network errors only if we got no other data. Otherwise
		 * we'll let the upper layers decide whether the response is OK
		 * or not. It is very common that an RST sent by the server is
		 * reported as an error just after the last data chunk.
		 */
		TRACE_ERROR("connection error during recv", HXS_EV_RX, hs);
		hs->flags |= HXS_ST_CONN_ERR;
	}
	else if (!read && !*fin && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS)) {
		TRACE_DEVEL("subscribing for read data", HXS_EV_RX, hs);
		conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
	}

 leave:
	hastream_release_ibuf(hs);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HXS_EV_RX, hs, 0, 0, 0,
	             "data received (%llu) read=%d *fin=%d",
	             (unsigned long long)cur_read, (int)read, *fin);
	TRACE_LEAVE(HXS_EV_RX, hs);
}

/* I/O handler wakeup from MUX */
struct task *haload_io_cb(struct task *t, void *context, unsigned int state)
{
	struct stconn *sc = context;
	struct connection *conn;
	struct hastream *hs = __sc_hastream(sc);

	fprintf(stderr, "%s sc@%p\n", __func__, sc);
	sc = hs->sc;
	conn = sc_conn(sc);

	fprintf(stderr, "%s sc@%p conn@%p %d %d\n",
	        __func__, sc, conn, !!(conn->flags & CO_FL_ERROR), sc_ep_test(sc, SE_FL_ERROR));

	if ((conn->flags & CO_FL_ERROR) || sc_ep_test(sc, SE_FL_ERROR)) {
		TRACE_ERROR("connection error", HXS_EV_IO_CB, hs);
		hs->flags |= HXS_ST_CONN_ERR;
		task_wakeup(hs->task, TASK_WOKEN_IO);
		goto err;
	}

	task_wakeup(hs->task, TASK_WOKEN_IO);
 err:
	return t;
}

/* haload stream connector task */
static struct task *hastream_task(struct task *t, void *context, unsigned int state)
{
	struct hastream *hs = context;
	struct stconn *sc = hs->sc;
	
	TRACE_ENTER(HXS_EV_TASK, hs);
	if (!hs->sess) {
		struct connection *conn = NULL;
		struct protocol *proto;
		struct server *s = hs->srv;
		const struct mux_ops *mux_ops;
		int status;

		hs->sess = session_new(&haload_proxy, NULL, &hs->obj_type);
		if (!hs->sess) {
			TRACE_ERROR("session allocation failure", HXS_EV_TASK, hs);
			goto err;
		}

		hastream_release_ibuf(hs);
		hastream_release_obuf(hs);

		conn = conn_new(&hs->srv->obj_type);
		if (!conn) {
			TRACE_ERROR("stconn allocation error", HXS_EV_TASK, hs);
			goto err;
		}

		fprintf(stderr, "%s conn@%p\n", __func__, conn);
		if (haload_sc_attach_mux(hs->sc, NULL, conn) < 0) {
			TRACE_ERROR("mux attach error", HXS_EV_TASK, hs);
			conn_free(conn);
			conn = NULL;
			goto err;
		}

		conn->flags |= CO_FL_SSL_NO_CACHED_INFO;
		conn->ctx = hs->sc;
		conn_set_owner(conn, hs->sess, NULL);

		if (!sockaddr_alloc(&conn->dst, NULL, 0)) {
			TRACE_ERROR("sockaddr allocation error", HXS_EV_TASK, hs);
			goto err;
		}

		*conn->dst = s->addr;
		proto = protocol_lookup(conn->dst->ss_family,
		                        s->addr_type.proto_type, s->alt_proto);
		set_host_port(conn->dst, s->svc_port);

		if (conn_prepare(conn, proto, s->xprt) < 0) {
			TRACE_ERROR("xprt allocation error", HXS_EV_TASK, hs);
			goto err;
		}

		BUG_ON(!proto || !proto->connect);
		/* XXX check the flags XXX */
		status = proto->connect(conn, 0);
		if (status != SF_ERR_NONE) {
			TRACE_ERROR("proto connect error", HXS_EV_TASK, hs);
			goto err;
		}

		conn_set_private(conn);
		conn->ctx = hs->sc;

		if (conn_xprt_start(conn) < 0) {
			TRACE_ERROR("could not start xprt", HXS_EV_TASK, hs);
			goto err;
		}

		mux_ops = conn_get_best_mux(conn, IST_NULL, PROTO_SIDE_BE, PROTO_MODE_HTTP);
		if (mux_ops && conn_install_mux(conn, mux_ops, hs->sc, &haload_proxy, hs->sess) < 0) {
			TRACE_ERROR("mux installation failed", HXS_EV_TASK, hs);
			goto err;
		}

		if (conn->flags & CO_FL_WAIT_XPRT) {
			if (conn->mux)
				conn->mux->subscribe(hs->sc, SUB_RETRY_SEND, &hs->sc->wait_event);
		}

		hs->flags |= HXS_ST_MUST_SEND;
	}
	else {
		int fin = 0;
		struct connection *conn = sc_conn(sc);

		if (hs->flags & HXS_ST_MUST_SEND) {
			if (!hastream_build_http_req(hs, ist(arg_uri), 1))
				goto out;

			if (!hastream_htx_buf_snd(conn, hs))
				goto out;

			hs->flags &= ~HXS_ST_MUST_SEND;
			hs->flags |= HXS_ST_MUST_RECV;
			conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
		}
		else if (hs->flags & HXS_ST_MUST_RECV) {
			hastream_htx_buf_rcv(conn, hs, &fin);
			if (fin)
				goto err;
		}
	}

 out:
	if (hs->flags & HXS_ST_CONN_ERR) {
		TRACE_ERROR("haload stream error", HXS_EV_TASK, hs);
		goto err;
	}

	TRACE_LEAVE(HXS_EV_TASK, hs);
	return t;
 err:
	hastream_free(&hs);
	return NULL;
}

static inline void hastream_free(struct hastream **hs)
{
	struct hastream *h = *hs;

	sc_destroy(h->sc);
	session_free(h->sess);
	task_destroy(h->task);
	hastream_release_ibuf(h);
	hastream_release_obuf(h);
	ha_free(hs);
}

/* Instantiate a haload stream and wake up its underlying task */
static inline struct hastream *hastream_new(struct haload_srv *hasrv)
{
	struct hastream *hs;
	struct task *t;
	struct stconn *sc = NULL;

	hs = malloc(sizeof(*hs));
	t = task_new_on(conn_tid++ % global.nbthread);
	if (!hs || !t) {
		ha_alert("could not allocate a new hastream task\n");
		goto err;
	}

	sc = sc_new_from_hastream(hs, SC_FL_NONE);
	if (!sc) {
		ha_alert("could not allocate a new stconn\n");
		goto err;
	}

	t->process = hastream_task;
	t->context = hs;
	t->expire = TICK_ETERNITY;

	hs->obj_type = OBJ_TYPE_HXLOAD;
	hs->sess = NULL;
	hs->srv = hasrv->srv;
	hs->sc = sc;
	hs->bi = hs->bo = BUF_NULL;
	LIST_INIT(&hs->buf_wait.list);
	hs->task = t;
	hs->flags = 0;
	hs->state = 0;
	hs->to_send = 0;
	task_wakeup(t, TASK_WOKEN_INIT);

	return hs;
 err:
	sc_free(sc);
	task_destroy(t);
	free(hs);
	return NULL;
}

static int haload_init(void)
{
	int i, ret = ERR_ALERT | ERR_FATAL;
	char *errmsg = NULL;

	mtask = task_new_anywhere();
	if (!mtask) {
		ha_alert("could start main task\n");
		goto leave;
	}

	if (arg_long >= 2)
		printf("#_____time conns tot_conn  tot_req      tot_bytes"
		       "    err thr cps rps Bps bps ttfb(us) ttlb(us)");
	else if (arg_long)
		printf("#     time conns tot_conn  tot_req      tot_bytes"
		       "    err  cps  rps  Bps  bps   ttfb   ttlb");
	else
		printf("#     time conns tot_conn  tot_req      tot_bytes"
		       "    err  cps  rps  bps   ttfb");

	mtask->process = mtask_cb;
	mtask->expire = tick_add(now_ms, MS_TO_TICKS(1000));
	task_queue(mtask);

	/* streams initializations */
	for (i = 0; i < nbc; i++) {
		struct hastream *hs;

		hs = hastream_new(&haload_srv);
		if (!hs) {
			ha_alert("could not allocate a new haload stream\n");
			goto leave;
		}
	}

	ret = ERR_NONE;
 leave:
	ha_free(&errmsg);
	return ret;
}
REGISTER_POST_CHECK(haload_init);

static int haload_alloc_thrs_info(void)
{
	thrs_info = calloc(global.nbthread, sizeof(*thrs_info));
	if (!thrs_info) {
		ha_alert("failed to alloct threads information array.\n");
		return -1;
	}

	return 1;
}
REGISTER_POST_CHECK(haload_alloc_thrs_info);
