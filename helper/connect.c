/* This if a copy of the minimal things necessary from git-core/connect.c
 * to make parse_connect_url and prepare_ssh_command work. These two
 * functions are part of changes to git-core/connect.c currently under
 * discussion on the git mailing list. */
#include "git-compat-util.h"
#include "cache.h"
#include "run-command.h"
#include "connect.h"
#include "url.h"
#include "transport.h"

enum protocol {
	PROTO_LOCAL = 1,
	PROTO_FILE,
	PROTO_SSH,
	PROTO_GIT
};

static const char *prot_name(enum protocol protocol)
{
	switch (protocol) {
		case PROTO_LOCAL:
		case PROTO_FILE:
			return "file";
		case PROTO_SSH:
			return "ssh";
		case PROTO_GIT:
			return "git";
		default:
			return "unknown protocol";
	}
}

static enum protocol get_protocol(const char *name)
{
	if (!strcmp(name, "ssh"))
		return PROTO_SSH;
	if (!strcmp(name, "git"))
		return PROTO_GIT;
	if (!strcmp(name, "git+ssh")) /* deprecated - do not use */
		return PROTO_SSH;
	if (!strcmp(name, "ssh+git")) /* deprecated - do not use */
		return PROTO_SSH;
	if (!strcmp(name, "file"))
		return PROTO_FILE;
	die("I don't handle protocol '%s'", name);
}

static char *host_end(char **hoststart, int removebrackets)
{
	char *host = *hoststart;
	char *end;
	char *start = strstr(host, "@[");
	if (start)
		start++; /* Jump over '@' */
	else
		start = host;
	if (start[0] == '[') {
		end = strchr(start + 1, ']');
		if (end) {
			if (removebrackets) {
				*end = 0;
				memmove(start, start + 1, end - start);
				end++;
			}
		} else
			end = host;
	} else
		end = host;
	return end;
}

#define STR_(s)	# s
#define STR(s)	STR_(s)

static void get_host_and_port(char **host, const char **port)
{
	char *colon, *end;
	end = host_end(host, 1);
	colon = strchr(end, ':');
	if (colon) {
		long portnr = strtol(colon + 1, &end, 10);
		if (end != colon + 1 && *end == '\0' && 0 <= portnr && portnr < 65536) {
			*colon = 0;
			*port = colon + 1;
		} else if (!colon[1]) {
			*colon = 0;
		}
	}
}

static char *get_port(char *host)
{
	char *end;
	char *p = strchr(host, ':');

	if (p) {
		long port = strtol(p + 1, &end, 10);
		if (end != p + 1 && *end == '\0' && 0 <= port && port < 65536) {
			*p = '\0';
			return p+1;
		}
	}

	return NULL;
}

/*
 * Extract protocol and relevant parts from the specified connection URL.
 * The caller must free() the returned strings.
 */
static enum protocol parse_connect_url(const char *url_orig, char **ret_user,
				       char **ret_host, char **ret_port,
				       char **ret_path)
{
	char *url;
	char *host, *path;
	const char *user = NULL;
	const char *port = NULL;
	char *end;
	int separator = '/';
	enum protocol protocol = PROTO_LOCAL;

	if (is_url(url_orig))
		url = url_decode(url_orig);
	else
		url = xstrdup(url_orig);

	host = strstr(url, "://");
	if (host) {
		*host = '\0';
		protocol = get_protocol(url);
		host += 3;
	} else {
		host = url;
		if (!url_is_local_not_ssh(url)) {
			protocol = PROTO_SSH;
			separator = ':';
		}
	}

	/*
	 * Don't do destructive transforms as protocol code does
	 * '[]' unwrapping in get_host_and_port()
	 */
	end = host_end(&host, 0);

	if (protocol == PROTO_LOCAL)
		path = end;
	else if (protocol == PROTO_FILE && has_dos_drive_prefix(end))
		path = end; /* "file://$(pwd)" may be "file://C:/projects/repo" */
	else
		path = strchr(end, separator);

	if (!path || !*path)
		die("No path specified. See 'man git-pull' for valid url syntax");

	/*
	 * null-terminate hostname and point path to ~ for URL's like this:
	 *    ssh://host.xz/~user/repo
	 */

	end = path; /* Need to \0 terminate host here */
	if (separator == ':')
		path++; /* path starts after ':' */
	if (protocol == PROTO_GIT || protocol == PROTO_SSH) {
		if (path[1] == '~')
			path++;
	}

	path = xstrdup(path);
	*end = '\0';

	get_host_and_port(&host, &port);

	if (*host) {
		/* The host might contain a user:password string, ignore it
		 * when searching for the port again */
		char *end_user = strrchr(host, '@');
		if (end_user) {
			*end_user = '\0';
			user = host;
			host = end_user + 1;
		}
	}
	if (!port)
		port = get_port(host);

	*ret_user = user ? xstrdup(user) : NULL;
	*ret_host = xstrdup(host);
	*ret_port = port ? xstrdup(port) : NULL;
	*ret_path = path;
	free(url);
	return protocol;
}

static int prepare_ssh_command(struct argv_array *cmd, const char *user,
			       const char *host, const char *port, int flags)
{
	const char *ssh;
	int putty = 0, tortoiseplink = 0, use_shell = 1;
	transport_check_allowed("ssh");

	ssh = getenv("GIT_SSH_COMMAND");
	if (!ssh) {
		const char *base;
		char *ssh_dup;

		/*
		 * GIT_SSH is the no-shell version of
		 * GIT_SSH_COMMAND (and must remain so for
		 * historical compatibility).
		 */
		use_shell = 0;

		ssh = getenv("GIT_SSH");
		if (!ssh)
			ssh = "ssh";

		ssh_dup = xstrdup(ssh);
		base = basename(ssh_dup);

		tortoiseplink = !strcasecmp(base, "tortoiseplink") ||
			!strcasecmp(base, "tortoiseplink.exe");
		putty = tortoiseplink ||
			!strcasecmp(base, "plink") ||
			!strcasecmp(base, "plink.exe");

		free(ssh_dup);
	}

	argv_array_push(cmd, ssh);
	if (flags & CONNECT_IPV4)
		argv_array_push(cmd, "-4");
	else if (flags & CONNECT_IPV6)
		argv_array_push(cmd, "-6");
	if (tortoiseplink)
		argv_array_push(cmd, "-batch");
	if (port) {
		/* P is for PuTTY, p is for OpenSSH */
		argv_array_push(cmd, putty ? "-P" : "-p");
		argv_array_push(cmd, port);
	}
	if (user) {
		argv_array_push(cmd, "-l");
		argv_array_push(cmd, user);
	}
	argv_array_push(cmd, host);

	return use_shell;
}
