/*
 * nsntrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * nsntrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with nsntraces; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#define _GNU_SOURCE
#include <grp.h>
#include <getopt.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>

#include "capture.h"
#include "net.h"

/*
 * This application attempts to trace the network traffic of a single process.
 * It does so by creating a new network namespace. In Linux a network namespace
 * partitions the use of the network effecticly virtualizing the network,
 * devices, addresses, ports, routes firewall rules, etc into separate boxes.
 *
 * So what this application does is use the clone syscall to create a new
 * network namespace (CLONE_NEWNET) and from that namespace launch the
 * requested process as well as start a trace. This will ensure that all
 * the packets we trace come from the process.
 *
 * The problem we are left with is that the process is isolated in the
 * namespace and can not reach any other network. We get around that by
 * creating virtual network interfaces. We keep one of them in the
 * root network namespace and but the other one in the newly created one where
 * our tracing takes place. We set the root namespaced one as the default gw
 * of the trace namespaced virtual device.
 *
 * And then to make sure we can reach our indented net, we use ip
 * tables and NAT to forward all traffic from the virtual device to our
 * default network interface.
 *
 * This will allow us to capture the packets from a single process while
 * it is communicating with our default network. A limitation is that our
 * ip address will be the NAT one of the virtual device.
 *
 * Another limitation is, that since we are using iptables and since
 * we are tracing raw sockets. This application needs to be run as root.
 *
 */

#define APP_TIMEOUT (2000000L) /* 2 seconds */
#define STACK_SIZE (1024 * 64) /* 64 kB stack */
#define DEFAULT_OUTFILE "nsntrace.pcap"

struct nsntrace_options {
	char *outfile;
	char *device;
	char *user;
	char *filter;
	char * const *args;
};

static const char *short_opt = "o:d:u:f:h";
static struct option long_opt[] = {
	{ "outfile", required_argument, NULL, 'o' },
	{ "device",  required_argument, NULL, 'd' },
	{ "user",    required_argument, NULL, 'u' },
	{ "filter",  required_argument, NULL, 'f' },
	{ "help",    required_argument, NULL, 'h' },
	{ NULL,	     0,			NULL,  0 }
};

static char child_stack[STACK_SIZE];
static pid_t child_pid;

/*
 * We will attempt to catch the signals that can make us exit since
 * we want to remove the temporary network configurations when we elave
 *
 * This is hard. Which signals should we catch? This is what we have
 * now:
 *
 * SIGHUP:  Disconnects a process from the parent process.
 * SIGINT:  Same as pressing ctrl-c.
 * SIGABRT: The abort signal, most often used on one self.
 * SIGTERM: A request to a process to stop running (kill $pid),
 * SIGQUIT: Similar to SIGINT but also a request to core dump.
 * SIGSEGV: Generally sent to process by the kernel when the
 *	    process is accessing memory incorrectly. There are
 *	    no gurantees for what we can do when this happens.
 *	    But let's try to clean up!
 */
const int nsntrace_signals[] = {
	SIGHUP,
	SIGINT,
	SIGABRT,
	SIGTERM,
	SIGQUIT,
	SIGSEGV,
};

static void
_nsntrace_handle_signals(void (*handler)(int))
{
	struct sigaction action = { 0 };
	int s;

	action.sa_handler = handler;
	for (s = 0; s < sizeof(nsntrace_signals) / sizeof(int); s++) {
		sigaction(nsntrace_signals[s], &action, NULL);
	}
}

static void
_nsntrace_cleanup_ns()
{
	kill(child_pid, SIGTERM);
	waitpid(child_pid, NULL, 0);

	printf("Finished capturing %lu packets.\n",
	       nsntrace_capture_packet_count());
	nsntrace_capture_flush();
	exit(EXIT_SUCCESS);
}

static void
_nsntrace_cleanup() {
	/*
	 * Make sure we do not just die when we receive our
	 * terminating signals. We need to clean up after
	 * our children.
	 */
	printf("Capture interrupted, cleaning up\n");
}

static void
_nsntrace_start_tracer(struct nsntrace_options *options)
{
	const char *ip;
	const char *interface;

	ip = nsntrace_net_get_capture_ip();
	interface = nsntrace_net_get_capture_interface();

	printf("Starting network trace of '%s' on interface %s.\n"
	       "Your IP address in this trace is %s.\n"
	       "Use ctrl-c to end at any time.\n\n",
	       options->args[0], options->device, ip);
	nsntrace_capture_start(interface, options->filter, options->outfile);
}

static void
_nsntrace_start_tracee(struct nsntrace_options *options)
{
	uid_t uid;
	gid_t gid;

	/*
	 * The getpwnam() function will return a pointer to fields in
	 * the password database that matches the username given. This can
	 * be the local password file or NIS, LDAP etc.
	 *
	 * If the user supplied a username to run the traced process as, then
	 * we look up the uid and gid and set those ids on our newly forked
	 * process. Along with other user specific goodies.
	 */
	if (options->user) {
		struct passwd* pwd;

		if (!(pwd = getpwnam(options->user))) {
			fprintf(stderr,"Cannot find user '%s'\n",
				options->user);
			_nsntrace_cleanup_ns();
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
		/*
		 * Set common environment variables that application looks
		 * at and expects to reflect the user.
		 *
		 * Any more that should be set?
		 */
		setenv("HOME", pwd->pw_dir, 1);
		setenv("USER", pwd->pw_name, 1);
		setenv("USERNAME", pwd->pw_name, 1);
		/*
		 * The initgroups() function needs to be run before we
		 * lose privileges (setuid).
		 */
		initgroups(options->user, gid);
	} else {
		uid = getuid();
		gid = getgid();
	}

	if (setgid(gid) < 0) {
		fprintf(stderr, "Unable to set process group ID");
	}

	if (setuid(uid) < 0) {
		fprintf(stderr, "Unable to set process user ID");
	}

	/* launch the application to trace */
	if (execvp(options->args[0], options->args) < 0) {
		fprintf(stderr, "Unable to start '%s'\n", options->args[0]);
	}
}

static int
netns_main(void *arg) {
	int ret;
	struct nsntrace_options *options = (struct nsntrace_options *) arg;

	if ((ret = nsntrace_net_ns_init()) < 0) {
		fprintf(stderr, "failed to setup network environment\n");
		return EXIT_FAILURE;
	}

	_nsntrace_handle_signals(_nsntrace_cleanup_ns);
	_nsntrace_start_tracer(options);

	child_pid = fork();
	if (child_pid < 0) {
		return EXIT_FAILURE;
	} else if (child_pid > 0) { /* parent - tracer */
		waitpid(child_pid, NULL, 0);

		/* sleep so that all packets can be processed */
		usleep(APP_TIMEOUT);

		/* the tracee exited, we waited, stop capture */
		nsntrace_capture_stop();

		/* broken out of capture loop, clean up */
		_nsntrace_cleanup_ns();
	} else { /* child - tracee */
		_nsntrace_start_tracee(options);
	}

	return 0;
}

static void
_nsntrace_usage()
{
	printf("usage: nsntrace [-o file] [-d device] "
	       "[-u username] PROG [ARGS]\n"
	       "Perform network trace of a single process by using "
	       "network namespaces.\n\n"
	       "-o file\t\tsend trace output to file (default nsntrace.pcap)\n"
	       "-d device\tthe network device to trace\n"
	       "-f filter\tan optional capture filter\n"
	       "-u username\trun PROG as username\n");
}

static void
_nsntrace_parse_options(struct nsntrace_options *options,
			int argc, char **argv)
{
	int c;

	opterr = 0;
	while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) > 0) {
		switch(c) {
		case -1:
		case 0:
			break;

		case 'o':
			options->outfile = strdup(optarg);
			break;

		case 'd':
			options->device = strdup(optarg);
			break;

		case 'u':
			options->user = strdup(optarg);
			break;

		case 'f':
			options->filter = strdup(optarg);
			break;

		case 'h':
			_nsntrace_usage();
			exit(EXIT_SUCCESS);
			break;

		default:
			fprintf(stderr, "Invalid option '%c'\n", c);
			_nsntrace_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (!options->device) {
		options->device = strdup(nsntrace_capture_default_device());
	}
	if (!options->outfile) {
		options->outfile = strdup(DEFAULT_OUTFILE);
	}
	options->args = argv + optind; /* the arguments after options parsed */
	if (!options->args[0]) {
		_nsntrace_usage();
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char **argv)
{
	struct nsntrace_options options = { 0 };
	pid_t pid;
	int status;
	int ret = EXIT_SUCCESS;

	_nsntrace_parse_options(&options, argc, argv);

	/* geteuid() returns the effective user ID, 0 if root */
	if (geteuid() != 0) {
		fprintf(stderr,
			"You need root privileges to run this application\n");
		exit(EXIT_FAILURE);
	}

	if (!nsntrace_net_ip_forward_enabled()) {
		fprintf(stderr,
			"IP forward must be enabled to run this application\n"
			"# cat /proc/sys/net/ipv4/ip_forward\n");
		exit(EXIT_FAILURE);
	}

	/* here we create a new process in a new network namespace */
	pid = clone(netns_main, child_stack + STACK_SIZE,
		    CLONE_NEWNET | SIGCHLD, &options);

	_nsntrace_handle_signals(_nsntrace_cleanup);

	if ((ret = nsntrace_net_init(pid, options.device)) < 0) {
		fprintf(stderr, "Failed to setup networking environment\n");
		kill(pid, SIGTERM);
	}

	/* wait here until our traced process exists or the user aborts */
	waitpid(pid, &status, 0);
	ret = WEXITSTATUS(status);

	nsntrace_net_deinit(options.device);
	return ret;
}
