#ifndef _HAPROXY_HALOAD_H
#define _HAPROXY_HALOAD_H

#include <import/ist.h>
#include <haproxy/list-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/task-t.h>

struct haload_srv {
	struct server *srv;
	const char *addr;
	int ssl;
};

/* haload header */
struct haload_hdr {
	struct ist name;
	struct ist value;
	struct list list;
};

extern const char *arg_host;
extern const char *arg_conn_hdr;
extern const char *arg_uri;
extern const char *arg_path;
extern struct list haload_hdrs;

extern struct proxy haload_proxy;
extern int nbc;      // peak connection count
extern int arg_long; // -l option
extern int arg_head; // -I option
extern struct haload_srv haload_srv;

#endif /* _HAPROXY_HALOAD_H */
