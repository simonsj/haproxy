#include <errno.h>

#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/hbuf.h>
#include <haproxy/haload.h>
#include <haproxy/proxy.h>
#include <haproxy/version.h>
#include <haproxy/server.h>

static int haload_debug;

static const char *haterm_cfg_dflt_str =
        "defaults\n"
            "\tmode http\n"
            "\thttp-reuse never\n"
            "\ttimeout connect 5s\n"
            "\ttimeout server 5s\n";

static void  haload_usage(char *name, int argc, int line)
{
	fprintf(stderr, "argc=%d\n", argc);
	fprintf(stderr,
		"%d: Usage : %s [opts]\n"
		"        -c <conn>      peak concurrent connections\n"
		"        -l             enable long output format; double for raw values\n"
		"        -C             dump the configuration and exit\n"
		"        -H \"foo:bar\"   add this header name and value\n"
		"        -I             use HEAD instead of GET\n"
		"        -v             shows version\n"
		"        --traces       enable the traces for all the HTTP protocols\n"
		"where <opts> may be any combination of:\n",
		line, name);
	exit(1);
}

static const char *haload_cfg_traces_str =
        "traces\n"
            "\ttrace haload sink stderr level developer start now verbosity clean\n"
            "\ttrace h1 sink stderr level developer start now verbosity minimal\n"
            "\ttrace h2 sink stderr level user start now verbosity minimal\n"
            "\ttrace h3 sink stderr level user start now verbosity minimal\n"
            "\ttrace qmux sink stderr level user start now verbosity minimal\n";

static struct haload_hdr *haload_parse_hdr(char *hdr_str)
{
	struct haload_hdr *hdr= NULL;
	char *value = strchr(hdr_str, ':');

	if (value) {
		*value++ = '\0';
		if (!*value)
			value = NULL;
	}

	if (strcasecmp(hdr_str, "host") == 0)
		arg_host = value;
	else if (strcasecmp(hdr_str, "connection") == 0)
		arg_conn_hdr = value;

	hdr = malloc(sizeof(*hdr));
	if (hdr) {
		hdr->name = ist(hdr_str);
		hdr->value = ist(value);
	}

	return hdr;
}

void haproxy_init_args(int argc, char **argv)
{
	int err = 1, dump = 0;
	struct hbuf buf = HBUF_NULL;  // cfgfile
	struct hbuf gbuf = HBUF_NULL; // "global" section
	struct hbuf tbuf = HBUF_NULL; // "traces" section
	int ssl = 0;
	char *errmsg = NULL;
	char *addr = NULL, *path = NULL;
	int alt_proto, port;
	struct sockaddr_storage *sk;
	struct server *srv;

	if (argc <= 1)
		haload_usage(progname, argc, __LINE__);

	if (hbuf_alloc(&buf) == NULL) {
		ha_alert("failed to allocate a buffer\n");
		exit(1);
	}

	fileless_mode = 1;
	client_mode = 1;
	/* skip program name and start */
	argc--; argv++;

	while (argc > 0 && **argv == '-') {
		char *opt = *argv + 1;

		//fprintf(stderr, "||||**argv='%c' argc=%d\n", **argv, argc);
		//fprintf(stderr, "====> *opt='%c'\n", *opt);
		if (*opt == '-') {
			/* long option */
			opt++;
			if (strcmp(opt, "traces") == 0) {
				haload_debug = 1;
#if 0
				/* optional argument */
				if (argc - 1 > 0 && **(argv + 1) != '-') {
					fprintf(stderr, "trace arg: '%s'\n", *(argv + 1));
					if (hbuf_is_null(&tbuf) && hbuf_alloc(&tbuf) == NULL) {
						ha_alert("failed to allocate a buffer.\n");
						goto leave;
					}

					hbuf_str_append(&tbuf, *(argv + 1));
					argc--; argv++;
				}
#endif
			}
			else
				haload_usage(progname, argc, __LINE__);
		}
		else if (*opt == 'c') {
			char *endptr;

			opt++;
			if (!*opt) {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					haload_usage(progname, argc, __LINE__);

				opt = *argv;
			}

			nbc = strtol(opt, &endptr, 0);
			if (endptr == opt || nbc < 0)
				haload_usage(progname, argc, __LINE__);
		}
		else if (*opt == 'l') {
			arg_long++;
			while (*++opt && *opt == 'l')
				arg_long++;
		}
		else if (*opt == 'C') {
			/* empty option */
			if (*(opt + 1))
				haload_usage(progname, argc, __LINE__);

			dump = 1;
			break;
		}
		else if (*opt == 'H') {
			char *hdr_str;
			struct haload_hdr *hdr;

			opt++;
			if (!*opt) {
				argv++; argc--;
				if ((argc <= 0 || **argv == '-'))
					haload_usage(progname, argc, __LINE__);

				opt = *argv;
			}
			hdr_str = opt;
			hdr = haload_parse_hdr(hdr_str);
			if (!hdr) {
				ha_alert("could not allocate a header\n");
				goto leave;
			}

			LIST_APPEND(&haload_hdrs, &hdr->list);
		}
		else if (*opt == 'I') {
			/* empty option */
			if (*(opt + 1))
				haload_usage(progname, argc, __LINE__);

			arg_head = 1;
		}
		else if (*opt == 'G') {
			argv++; argc--;
			if (argc <= 0 || **argv == '-')
				haload_usage(progname, argc, __LINE__);

			if (hbuf_is_null(&gbuf)) {
				if (hbuf_alloc(&gbuf) == NULL) {
					ha_alert("failed to allocate a buffer.\n");
					goto leave;
				}

				hbuf_appendf(&gbuf, "global\n");
			}

			hbuf_str_append(&gbuf, *argv);
		}
		else if (*opt == 'v') {
			/* empty option */
			if (*(opt + 1))
				haload_usage(progname, argc, __LINE__);

			printf("haload version " HAPROXY_VERSION " released " HAPROXY_DATE "\n");
			exit(0);
		}
		else {
			//fprintf(stderr, "BUG: *opt=%c\n", *opt);
			haload_usage(progname, argc, __LINE__);
		}

		argv++; argc--;
		//fprintf(stderr, "///argc=%d argv='%s'\n", argc, *argv);
	}

	/* "global" section */
	if (!hbuf_is_null(&gbuf))
		hbuf_appendf(&buf, "%.*s\n", (int)gbuf.data, gbuf.area);
	/* "traces" section */
	if (haload_debug) {
		hbuf_appendf(&buf, "%s", haload_cfg_traces_str);
		if (!hbuf_is_null(&tbuf))
			hbuf_appendf(&buf, "%.*s\n", (int)tbuf.data, tbuf.area);
	}

	hbuf_appendf(&buf, "%s\n", haterm_cfg_dflt_str);

	fileless_cfg.filename = strdup("haterm cfgfile");
	fileless_cfg.content = strdup(buf.area);
	if (!fileless_cfg.filename || !fileless_cfg.content) {
		ha_alert("cfgfile strdup() failed.\n");
		goto leave;
	}

	fileless_cfg.size = buf.data;

	/* Config dump */
	if (dump) {
		fprintf(stdout, "%.*s", (int)fileless_cfg.size, fileless_cfg.content);
		exit(0);
	}

	if (!argc)
		haload_usage(progname, argc, __LINE__);

	if (argc > 1) {
		ha_alert("Unhandled extraneous argument '%s' after URL\n", argv[1]);
		goto leave;
	}

	/* URL parsing */
	//fprintf(stderr, "URL: '%s'\n", *argv);
	if (strncmp(*argv, "https://", 8) == 0) {
		ssl = 1;
		addr = *argv + 8;
	}
	else if (strncmp(*argv, "http://", 7) == 0) {
		ssl = 0;
		addr = *argv + 7;
	}
	else {
		ha_alert("wrong url '%s'\n", *argv);
		goto leave;
	}

	path = strchr(addr, '/');
	if (path) {
		char *new_path = strdup(path);
		*path = '\0';
		path = new_path;
	}
	else
		path = strdup("/");

	if (!path) {
		ha_alert("failed to allocate a new path\n");
		goto leave;
	}

	arg_path = path;
	arg_uri = *argv;
	addr = strdup(addr);
	if (!addr) {
		ha_alert("failed to allocate a new addr\n");
		goto leave;
	}

	haload_srv.addr = addr;
	haload_srv.ssl = ssl;

	if (!setup_new_proxy(&haload_proxy, "HALOAD-FE",
	                     PR_CAP_FE | PR_CAP_BE | PR_CAP_INT, &errmsg)) {
		ha_alert("could not setup internal proxy: %s\n", errmsg);
		ha_free(&errmsg);
		goto leave;
	}

	srv = new_server(&haload_proxy);
	if (!srv) {
		ha_alert("could not allocate a new server\n");
		goto leave;
	}

	sk = str2sa_range(haload_srv.addr, &port, NULL, NULL, NULL, NULL,
					  &srv->addr_type, &errmsg, NULL, NULL, &alt_proto,
					  PA_O_PORT_OK | PA_O_STREAM | PA_O_DGRAM | PA_O_XPRT);
	if (!sk) {
		ha_alert("%s\n", errmsg);
		ha_free(&errmsg);
		goto leave;
	}

	srv->id = strdup("haload");
	srv->addr = *sk;
	srv->svc_port = port;
	srv->alt_proto = alt_proto;
	srv_settings_init(srv);
	haload_srv.srv = srv;

	err = 0;
leave:
	free_hbuf(&gbuf);
	free_hbuf(&buf);
	if (err)
		exit(1);
}

/* Dummy argv copier function */
char **copy_argv(int argc, char **argv)
{
	char **ret = calloc(1, sizeof(*ret));

	if (ret)
		*ret = strdup("");

	return ret;
}
