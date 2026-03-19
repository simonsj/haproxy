#ifndef  _HAPROXY_HASTREAM_T_H
#define _HAPROXY_HASTREAM_T_H

#include <haproxy/buf-t.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/session-t.h>
#include <haproxy/stconn-t.h>
#include <haproxy/task-t.h>

struct hastream {
	enum obj_type obj_type;
	struct session *sess;
	struct server *srv;          /* XXX check: if this needed? */
	struct stconn *sc;
	struct buffer bi, bo;
	struct buffer_wait buf_wait; /* wait list for buffer allocation */
	struct task *task;
	int flags;
	int state;
	unsigned long long to_send; /* number of body data bytes to send */
};

#endif /* _HAPROXY_HASTREAM_T_H */
