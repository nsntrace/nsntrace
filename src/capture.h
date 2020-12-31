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

#ifndef _NSNTRACE_CAPTURE_H_
#define _NSNTRACE_CAPTURE_H

int nsntrace_capture_start(const char *iface,
                           const char *filter,
                           FILE *fp);

void nsntrace_capture_stop();

unsigned long nsntrace_capture_packet_count();

void nsntrace_capture_flush();

char *nsntrace_capture_default_device();

int nsntrace_capture_check_device(char *iface);
#endif
