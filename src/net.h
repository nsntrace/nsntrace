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

int nsntrace_net_init(pid_t ns_pid,
                      const char *device);

int nsntrace_net_deinit(const char *device);

int nsntrace_net_ns_init();

int nsntrace_net_ip_forward_enabled();

const char *nsntrace_net_get_capture_ip();

const char *nsntrace_net_get_capture_interface();

#endif
