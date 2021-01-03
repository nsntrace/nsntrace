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
 * with nsntraces; if not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/if.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
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
static pthread_t capture_thread;
static unsigned long packet_count;

static void
_nsntrace_capture_callback(unsigned char *user_data,
			   struct pcap_pkthdr *header,
			   unsigned char *package)
{
	packet_count++;
	pcap_dump(user_data, header, package);
}

static void *
_nsntrace_capture_thread(void *data)
{
	pcap_loop(handle, -1, (pcap_handler) _nsntrace_capture_callback,
		  (unsigned char *) pcap_dumper);
	pcap_close(handle);

	return NULL;
}

void
nsntrace_capture_stop()
{
	pcap_breakloop(handle);
}

int
nsntrace_capture_start(const char *iface,
		       const char *filter,
		       FILE *fp)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf_fp;
	int ret;

	if (!(handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf))) {
		fprintf(stderr, "Couldn't open iface: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	if (filter) {
		ret = pcap_compile(handle, &bpf_fp, filter,
				   0, PCAP_NETMASK_UNKNOWN);
		if (ret < 0) {
			fprintf(stderr, "Failed to set filter: %s\n", filter);
			return EXIT_FAILURE;
		} else {
			pcap_setfilter(handle, &bpf_fp);
		}
	}

	if (!(pcap_dumper = pcap_dump_fopen(handle, fp))) {
		fprintf(stderr, "Couldn't open output: %s\n", pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	ret = pthread_create(&capture_thread, NULL,
			    _nsntrace_capture_thread, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to create capture thread\n");
		return EXIT_FAILURE;
	}

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
	pcap_if_t *interfaces;
	char *name;

	if (pcap_findalldevs(&interfaces, NULL) < 0) {
		return NULL;
	}

	name = strndup(interfaces->name, IFNAMSIZ);
	pcap_freealldevs(interfaces);

	return name;
}

int
nsntrace_capture_check_device(char *iface)
{
	pcap_if_t *dev;
	pcap_if_t *devList;
	int ret = EXIT_FAILURE;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&devList, errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	for (dev = devList; dev != NULL; dev = dev->next) {
		if (strcmp(dev->name, iface) == 0) {
			ret = EXIT_SUCCESS;
			goto out;
		}
	}

	fprintf(stderr, "Unknown interface: %s\n", iface);
out:
	pcap_freealldevs(devList);
	return ret;
}
