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
 */

#include <pcap.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "capture.h"

/*
 * We use libpcap to capture network data. It was originally developed by
 * the tcpdump developers.
 *
 * Each time we get a packet, we count it and dump it to file.
 * And we also check that the program we are supposed to trace is still
 * alive.
 */

static pcap_dumper_t *pcap_dumper;
static pcap_t *handle;
static unsigned long packet_count;

static void
_nsntrace_capture_callback(unsigned char *user_data,
			   struct pcap_pkthdr *header,
			   unsigned char *package)
{
	int ret;

	packet_count++;
	pcap_dump(user_data, header, package);

	if ((ret = waitpid(-1, NULL, WNOHANG)) < 0) {
		pcap_breakloop(handle);
	}
}

int
nsntrace_capture_start(const char *iface,
		       const char *filter,
		       const char *outfile)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	if (!(handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf))) {
		fprintf(stderr, "Couldn't open iface: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	if (filter) {
		int ret = pcap_compile(handle, &fp, filter,
				       0, PCAP_NETMASK_UNKNOWN);
		if (ret < 0) {
			fprintf(stderr, "Failed to set filter: %s\n", filter);
		} else {
			pcap_setfilter(handle, &fp);
		}
	}

	if (!(pcap_dumper = pcap_dump_open(handle, outfile))) {
		fprintf(stderr, "Couldn't open output: %s: %s\n",
			outfile, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	pcap_loop(handle, -1, (pcap_handler) _nsntrace_capture_callback,
		  (unsigned char *) pcap_dumper);
	pcap_close(handle);

	return EXIT_SUCCESS;
}

unsigned long
nsntrace_capture_packet_count()
{
	return packet_count;
}

void
nsntrace_capture_flush()
{
	pcap_dump_flush(pcap_dumper);
}

char *
nsntrace_capture_default_device()
{
	return pcap_lookupdev(NULL);
}
