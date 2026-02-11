#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>

static int httpterm_debug;

/*
 * This function prints the command line usage for httpterm and exits
 */
static void httpterm_usage(char *name)
{
	fprintf(stderr,
		"Usage : %s -L [<ip>]:<clear port>:<TCP&QUIC SSL port> [-L...]*\n"
		"        -G <line> : multiple option; append <line> to the global section\n"
		"        -F <line> : multiple option; append <line> to the frontend section\n"
		"        -d : dump the configuration and enable the traces for all http protocols\n"
		"        -D goes daemon\n", name);
	exit(1);
}

#define HTTPTERM_FRONTEND_NAME   "___httpterm_frontend___"
#define HTTPTERM_RSA_CERT_NAME   "httpterm.pem.rsa"
#define HTTPTERM_ECDSA_CERT_NAME "httpterm.pem.ecdsa"

static const char *httpterm_cfg_str =
        "defaults\n"
            "\tmode httpterm\n"
            "\ttimeout client 25s\n"
        "\n"
        "frontend " HTTPTERM_FRONTEND_NAME "\n";
#ifdef USE_OPENSSL
static const char *httpterm_cfg_crt_store_str =
        "crt-store\n"
            "\tload generate-dummy on keytype RSA crt "   HTTPTERM_RSA_CERT_NAME   "\n"
            "\tload generate-dummy on keytype ECDSA crt " HTTPTERM_ECDSA_CERT_NAME "\n"
        "\n";
#endif
static const char *httpterm_cfg_traces_str =
        "traces\n"
            "\ttrace httpterm sink stderr level developer start now\n"
            "\ttrace h1 sink stderr level developer start now\n"
            "\ttrace h2 sink stderr level developer start now\n"
            "\ttrace h3 sink stderr level developer start now\n"
            "\ttrace qmux sink stderr level developer start now\n"
            "\ttrace ssl sink stderr level developer start now\n";

/* Very small API similar to buffer API to carefully build some strings */
#define HBUF_NULL ((struct hbuf) { })
#define HBUF_SIZE (16 << 10) /* bytes */
struct hbuf {
	char *area;
	size_t data;
	size_t size;
};

static struct hbuf *hbuf_alloc(struct hbuf *h)
{
	h->area = malloc(HBUF_SIZE);
	if (!h->area)
		return NULL;

	h->size = HBUF_SIZE;
	h->data = 0;
	return h;
}

static inline void free_hbuf(struct hbuf *h)
{
	free(h->area);
}

__attribute__ ((format(printf, 2, 3)))
static void hbuf_appendf(struct hbuf *h, char *fmt, ...)
{
	va_list argp;
	size_t room;
	int ret;

	room = h->size - h->data;
	if (!room)
		return;

	va_start(argp, fmt);
	ret = vsnprintf(h->area + h->data, room, fmt, argp);
	if (ret >= room)
		h->area[h->data] = '\0';
	else
		h->data += ret;
	va_end(argp);
}

static inline size_t hbuf_is_null(const struct hbuf *h)
{
	return h->size == 0;
}

/* Simple function, to append <line> to <b> without without
 * trailing '\0' character.
 * Take into an account the '\t' and '\n' escaped sequeces.
 */
static void hstream_str_buf_append(struct hbuf *h, const char *line)
{
	const char *p, *end;
	char *to = h->area + h->data;

	p = line;
	end = line + strlen(line);
	while (p < end && to < h->area + h->size) {
		if (*p == '\\') {
			if (!*++p || p >= end)
				break;
			if (*p == 'n')
				*to++ = '\n';
			else if (*p == 't')
				*to++ = '\t';
			p++;
			h->data++;
		}
		else {
			*to++ = *p++;
			h->data++;
		}
	}
}

/* This function initialises the httpterm HTTP benchmark server from
 * <argv>. This consists in building a configuration file in memory
 * using the haproxy configuration language.
 * Make exit(1) the process in case of any failure.
 */
void haproxy_init_args(int argc, char **argv)
{
	/* Initialize httpterm fileless cfgfile from <argv> arguments array.
	 * Never fails.
	 */
	int has_bind = 0, err = 1;
	struct hbuf mbuf = HBUF_NULL; // to build the main of the cfgfile
	struct hbuf gbuf = HBUF_NULL; // "global" section
	struct hbuf fbuf = HBUF_NULL; // "frontend" section

	fileless_mode = 1;
	if (argc <= 1)
		httpterm_usage(progname);

	if (hbuf_alloc(&mbuf) == NULL) {
		ha_alert("failed to alloce a buffer.\n");
		exit(1);
	}

#ifdef USE_OPENSSL
	hbuf_appendf(&mbuf, "%s", httpterm_cfg_crt_store_str);
#endif
	hbuf_appendf(&mbuf, "%s", httpterm_cfg_str);
	/* skip program name and start */
	argc--; argv++;
	while (argc > 0) {
		char *opt;

		if (**argv == '-') {
			opt = *argv + 1;
			if (*opt == 'd') {
				/* debug mode */
				httpterm_debug = 1;
			}
			else if (*opt == 'D') {
				global.mode |= MODE_DAEMON;
			}
			else if (*opt == 'F') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					httpterm_usage(progname);

				if (hbuf_is_null(&fbuf) &&hbuf_alloc(&fbuf) == NULL) {
					ha_alert("failed to allocate a buffer.\n");
					goto leave;
				}

				hstream_str_buf_append(&fbuf, *argv);
			}
			else if (*opt == 'G') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					httpterm_usage(progname);

				if (hbuf_is_null(&gbuf)) {
					if (hbuf_alloc(&gbuf) == NULL) {
						ha_alert("failed to allocate a buffer.\n");
						goto leave;
					}

					hbuf_appendf(&gbuf, "global\n");
				}

				hstream_str_buf_append(&gbuf, *argv);
			}
			else if (*opt == 'L') {
				/* binding */
#ifdef USE_QUIC
				int ipv6 = 0;
#endif
				char *ip, *port, *port1 = NULL, *port2 = NULL;

				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					httpterm_usage(progname);

				port = ip = *argv;
				if (*ip == '[') {
					/* IPv6 address */
					ip++;
					port = strchr(port, ']');
					if (!port)
						httpterm_usage(progname);
					*port++ = '\0';
#ifdef USE_QUIC
					ipv6 = 1;
#endif
				}

				while ((port = strchr(port, ':'))) {
					*port++ = '\0';
					if (!port1)
						port1 = port;
					else {
						if (port2)
							httpterm_usage(progname);

						port2 = port;
					}
				}

				if (!port1)
					httpterm_usage(progname);

				/* clear HTTP */
				hbuf_appendf(&mbuf, "\tbind %s:%s\n", ip, port1);
				has_bind = 1;
				if (port2) {
#ifdef USE_OPENSSL
					/* SSL/TCP binding */
					hbuf_appendf(&mbuf, "\tbind %s:%s ssl "
					             "alpn h2,http1.1,http1.0"
					             " crt " HTTPTERM_RSA_CERT_NAME
					             " crt " HTTPTERM_ECDSA_CERT_NAME "\n",
					             ip, port2);
#else
					ha_warning("OpenSSL support not compiled."
					           " '%s' second port ignored for TLS/TCP.\n", port2);
#endif

#ifdef USE_QUIC
					/* QUIC binding */
					hbuf_appendf(&mbuf, "\tbind %s@%s:%s ssl"
					             " crt " HTTPTERM_RSA_CERT_NAME
					             " crt " HTTPTERM_ECDSA_CERT_NAME "\n",
					             ipv6 ? "quic6" : "quic4", ip, port2);
#else
					ha_warning("QUIC support not compiled."
					           " '%s' second port ignored for QUIC.\n", port2);
#endif
				}
			}
			else
				httpterm_usage(progname);
		}
		else
			httpterm_usage(progname);
		argv++; argc--;
	}

	if (!has_bind) {
		ha_alert("No binding! Existing...\n");
		httpterm_usage(progname);
		goto leave;
	}

	if (!hbuf_is_null(&fbuf))
		hbuf_appendf(&mbuf, "%.*s", (int)fbuf.data, fbuf.area);
	if (!hbuf_is_null(&gbuf))
		hbuf_appendf(&mbuf, "%.*s", (int)gbuf.data, gbuf.area);
	if (httpterm_debug)
		hbuf_appendf(&mbuf, "%s", httpterm_cfg_traces_str);

	fileless_cfg.filename = strdup("httpterm cfgfile");
	fileless_cfg.content = strdup(mbuf.area);
	if (!fileless_cfg.filename || !fileless_cfg.content) {
		ha_alert("cfgfile strdup() failed.\n");
		goto leave;
	}

	fileless_cfg.size = mbuf.data;
	if (httpterm_debug)
		ha_notice("config:\n%.*s\n",
		          (int)fileless_cfg.size, fileless_cfg.content);

	err = 0;
 leave:
    free_hbuf(&mbuf);
    free_hbuf(&gbuf);
    free_hbuf(&fbuf);
    if (err)
	    exit(1);
}
