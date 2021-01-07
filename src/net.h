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

#ifndef _NSNTRACE_NET_H_
#define _NSNTRACE_NET_H

#include <linux/if.h>

#define IP_ADDR_LEN 16 // 4 sets of 3 numbers each separater by a dot + '\0'
#define NSNTRACE_RUN_DIR "/run/nsntrace"

struct nsntrace_if_info {
    char ns_if[IFNAMSIZ];
    char gw_if[IFNAMSIZ];
    char ns_ip[16];
    char gw_ip[16];
    char ns_ip_range[19];
    char gw_ip_range[19];
};

int nsntrace_net_init(pid_t ns_pid,
                      const char *device,
                      struct nsntrace_if_info *info);

int nsntrace_net_deinit(pid_t ns_pid,
                        const char *device,
                        struct nsntrace_if_info *info);

int nsntrace_net_ns_init(int use_public_dns,
                         struct nsntrace_if_info *info);

int nsntrace_net_ip_forward_enabled();

int nsntrace_net_get_if_info(pid_t pid,
                             struct nsntrace_if_info *info);

#endif
