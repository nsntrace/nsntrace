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

#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netlink/addr.h>
#include <netlink/errno.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/bonding.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "cmd.h"

/*
 * Netlink is an IPC mechanism used between the kernel and user space
 * processes. It was designed to be a more flexible successor to ioctls to
 * provide (mainly) networking related kernel configuration and monitoring
 * interfaces.
 *
 * Similarly to the Unix domain sockets, and unlike INET sockets, Netlink
 * communication cannot traverse host boundaries. However, while the Unix
 * domain sockets use the file system namespace, Netlink processes are
 * addressed by process identifiers (PIDs).
 *
 * In this application we use the Netlink Protocol Library Suite (libnl)
 * to interface with the Netlink API and perform network configuration.
 */

#define IP_BASE "172.16.42"
#define NS_IP IP_BASE ".255"
#define GW_IP IP_BASE ".254"
#define NS_IP_RANGE NS_IP "/31"
#define GW_IP_RANGE GW_IP "/31"

#define IF_BASE "nsntrace"
#define NS_IF IF_BASE "-netns"
#define GW_IF IF_BASE

static struct nl_sock *
_nsntrace_net_get_nl_socket() {
	static struct nl_sock *nl_sock_singleton = NULL;

	if (!nl_sock_singleton) {
		nl_sock_singleton = nl_socket_alloc();
		nl_connect(nl_sock_singleton, NETLINK_ROUTE);
	}

	return nl_sock_singleton;
}

static struct nl_addr *
_nsntrace_net_parse_addr(const char *ip)
{
	struct nl_addr *addr;

	if (nl_addr_parse(ip, AF_INET, &addr) < 0) {
		return NULL;
	}

	return addr;
}

/*
 * Here we want to set the default gateway of a given network interface.
 * So we set the destination as "0.0.0.0/0", which is special and specifies
 * all networks. And we set the gateway to the IP supplied.
 */
static int
_nsntrace_net_set_default_gw(struct rtnl_link *link,
			     const char *gw)
{
	int ret, ifindex;
	struct nl_sock *sock = _nsntrace_net_get_nl_socket();
	struct rtnl_route *route;
	struct rtnl_nexthop *nh;
	struct nl_addr *dst, *gw_addr;

	ifindex = rtnl_link_get_ifindex(link);
	route = rtnl_route_alloc();
	rtnl_route_set_iif(route, ifindex);

	if (!(dst = _nsntrace_net_parse_addr("0.0.0.0/0"))) {
		return -1;
	}
	rtnl_route_set_dst(route, dst);
	nl_addr_put(dst);

	nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);
	if (!(gw_addr = _nsntrace_net_parse_addr(gw))) {
		return -1;
	}
	rtnl_route_nh_set_gateway(nh, gw_addr);

	rtnl_route_add_nexthop(route, nh);
	if ((ret = rtnl_route_add(sock, route, NLM_F_EXCL)) < 0) {
		return ret;
	}

	return 0;
}

/*
 * A network interface needs to be up in order to function.
 * Here we set it up, and add an address to it. And if specified,
 * we set the default gateway.
 */
static int
_nsntrace_net_iface_up(const char *iface,
		       const char *ip,
		       const char *gw)
{
	int ret = 0;
	struct nl_sock *sock = _nsntrace_net_get_nl_socket();
	struct nl_cache *cache;
	struct rtnl_link *link, *change;
	struct rtnl_addr *rtnl_addr;
	struct nl_addr *nl_addr;

	if (!ip) {
		return 0;
	}

	if ((ret = rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache)) < 0) {
		return ret;
	}

	if (!(link = rtnl_link_get_by_name(cache, iface))) {
		goto out;
	}

	rtnl_addr = rtnl_addr_alloc();
	rtnl_addr_set_link(rtnl_addr, link);
	rtnl_link_put(link);

	if ((ret = nl_addr_parse(ip, AF_INET, &nl_addr)) < 0) {
		goto out;
	}

	if ((ret = rtnl_addr_set_local(rtnl_addr, nl_addr)) < 0) {
		goto out;
	}
	nl_addr_put(nl_addr);

	if ((ret = rtnl_addr_add(sock, rtnl_addr, NLM_F_CREATE)) < 0) {
		goto out;
	}

	change = rtnl_link_alloc();
	rtnl_link_set_flags(change, IFF_UP);

	if ((ret = rtnl_link_change(sock, link, change, 0)) < 0) {
		goto out;
	}

	if (gw) {
		if ((ret = _nsntrace_net_set_default_gw(link, gw)) < 0) {
			goto out;
		}
	}

out:
	rtnl_addr_put(rtnl_addr);
	rtnl_link_put(change);
	nl_cache_free(cache);

	return ret;
}

/*
 * Remove specified network interface.
 */
static int
_nsntrace_net_iface_delete(const char *iface)
{
	int ret = 0;
	struct nl_sock *sock = _nsntrace_net_get_nl_socket();
	struct nl_cache *cache;
	struct rtnl_link *link;

	if ((ret = rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache)) < 0) {
		return ret;
	}

	if (!(link = rtnl_link_get_by_name(cache, iface))) {
		goto out;
	}

	if ((ret = rtnl_link_delete(sock, link)) < 0) {
		goto out;
	}

out:
	rtnl_link_put(link);
	nl_cache_free(cache);
	return ret;
}

/*
 * Create a virtual Ethernet interface.
 * A virtual Ethernet device consists of two Ethernet devices, that
 * are connected to each other. If a packet is sent to one device it
 * will come out of the other. We put one of them in the root network
 * namespace, and one in the namespace denoted by the specified pid.
 */
static int
_nsntrace_net_create_veth(const char *gw_iface,
			  const char *ns_iface,
			  pid_t ns_pid)
{
	int ret;
	struct nl_sock *sock = _nsntrace_net_get_nl_socket();

	if ((ret = rtnl_link_veth_add(sock, gw_iface, ns_iface, ns_pid)) < 0) {
		return ret;
	}

	return 0;
}

/*
 * Add nat rules using iptables to make the traffic from our namespace
 * able to reach our regular networks.
 *
 * Does anyone know of a stable API to do this without calling out to
 * the iptables program? Please consider contributing!
 */
static int
_nsntrace_net_set_nat(const char *ip,
		      const char *viface,
		      const char *iface,
		      int enable)
{
	char iptables_cmd[1024];
	char modifier = (enable ? 'A' : 'D');
	int ret = 0;

	ret = nsntrace_cmd_run("iptables -t nat -%c POSTROUTING -s %s "
			       "-o %s -j MASQUERADE",
			       modifier, ip, iface);
	if (ret)
		goto out;

	ret = nsntrace_cmd_run("iptables -%c FORWARD -i %s -o %s -j ACCEPT",
			       modifier, iface, viface);
	if (ret)
		goto out;


	ret = nsntrace_cmd_run("iptables -%c FORWARD -o %s -i %s -j ACCEPT",
			       modifier, iface, viface);
out:
	return ret;
}

/*
 * Set up the environment needed from the root network namespace point
 * of view. Create virtual ethernet interface (see above) and set our side
 * of it up and set address.
 *
 * Also set up the NAT rules needed to reach regular networks.
 */
int
nsntrace_net_init(pid_t ns_pid,
		  const char *device)
{
	int ret = 0;

	if ((ret = _nsntrace_net_create_veth(GW_IF, NS_IF, ns_pid)) < 0) {
		return ret;
	}

	if ((ret = _nsntrace_net_iface_up(GW_IF, GW_IP_RANGE, NULL)) < 0) {
		return ret;
	}

	if ((ret = _nsntrace_net_set_nat(GW_IP_RANGE, GW_IF, device, 1)) < 0) {
		return ret;
	}

	return ret;
}


/*
 * Teardown the temporary network trickery we created in init.
 */
int
nsntrace_net_deinit(const char *device)
{
	int ret = 0;

	if ((ret = _nsntrace_net_set_nat(GW_IP_RANGE, GW_IF, device, 0)) < 0) {
		return ret;
	}

	if ((ret = _nsntrace_net_iface_delete(NS_IF)) < 0) {
		return ret;
	}

	if ((ret = _nsntrace_net_iface_delete(GW_IF)) < 0) {
		return ret;
	}

	return ret;
}

/*
 * Set up the namespaced net infrastructure needed.
 */
int
nsntrace_net_ns_init()
{
	int ret = 0;

	if ((ret = _nsntrace_net_iface_up("lo", NULL, NULL)) < 0) {
		return EXIT_FAILURE;
	}

	if ((ret = _nsntrace_net_iface_up(NS_IF, NS_IP_RANGE, GW_IP)) < 0) {
		return EXIT_FAILURE;
	}

	return ret;
}

/*
 * If the content of /proc/sys/net/ipv4/ip_forward is 1 then
 * ip forward is enabled on the system.
 */
int
nsntrace_net_ip_forward_enabled()
{
	int fd;
	char ch;
	const char *ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

	if ((fd = open(ip_forward_path, O_RDONLY)) < 0) {
		return 0;
	}

	if (read(fd, &ch, 1) < 0) {
		return 0;
	}

	return ch == '1';
}

const char *
nsntrace_net_get_capture_interface()
{
	return NS_IF;
}

const char *
nsntrace_net_get_capture_ip()
{
	return NS_IP;
}
