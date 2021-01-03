# nsntrace
> Perform network trace of a single process by using network namespaces.

This application uses Linux network namespaces to perform network traces of a single application. The traces are saved as pcap files. And can later be analyzed by for instance Wireshark.

The nsntrace application is heavily inspired by the askbubuntu reply [here](https://askubuntu.com/a/499850).
And uses the same approach only confined to a single C program.

What the application does is use the clone syscall to create a new
network namespace (CLONE_NEWNET) and from that namespace launch the
requested process as well as start a trace using libpcap. This will ensure that all
the packets we trace come from the process.

The problem we are left with is that the process is isolated in the
namespace and cannot reach any other network. We get around that by
creating virtual network interfaces. We keep one of them in the
root network namespace and but the other one in the newly created one where
our tracing takes place. We set the root namespaced one as the default gw
of the trace namespaced virtual device.

And then to make sure we can reach our indented net, we use ip
tables and NAT to forward all traffic from the virtual device to our
default network interface.

This will allow us to capture the packets from a single process while
it is communicating with our default network. A limitation is that our
ip address will be the NAT one of the virtual device.

Another limitation is, that since we are using iptables and since
we are tracing raw sockets. This application needs to be run as root.

On many systems today the nameserver functionality is handled by an
application such as systemd-resolved or dnsmasq and the nameserver
address is a loopback address (like 127.0.0.53) where that application
listens for incoming DNS queries.

This will not work for us in this network namespace environment, since
we have our own namespaced loopback device.

## usage
    $ nsntrace
    usage: nsntrace [options] program [arguments]
    Perform network trace of a single process by using network namespaces.

    Options:
    -o file     send trace output to file (default nsntrace.pcap), use '-' for stdout
    -d device   the network device to trace
    -f filter   an optional capture filter
    -u username run program as username/uid

## example
```
$ sudo nsntrace -d eth1 wget www.google.com
Starting network trace of 'wget' on interface eth1.
Your IP address in this trace is 172.16.42.255.
Use ctrl-c to end at any time.

--2016-07-15 12:12:17--  http://www.google.com/
Location: http://www.google.se/?gfe_rd=cr&ei=AbeIV5zZHcaq8wfTlrjgCA [following]
--2016-07-15 12:12:17--  http://www.google.se/?gfe_rd=cr&ei=AbeIV5zZHcaq8wfTlrjgCA
Length: unspecified [text/html]
Saving to: ‘index.html’

index.html                                         [ <=>                                                                                                   ]  10.72K  --.-KB/s   in 0.001s

2016-07-15 12:12:17 (15.3 MB/s) - ‘index.html’ saved [10980]

Finished capturing 42 packets.

$ tshark -r nsntrace.pcap -Y 'http.response or http.request'
16   0.998839 172.16.42.255 -> 195.249.146.104    HTTP 229 GET http://www.google.com/ HTTP/1.1
20   1.010671    195.249.146.104 -> 172.16.42.255 HTTP 324 HTTP/1.1 302 Moved Temporarily  (text/html)
22   1.010898 172.16.42.255 -> 195.249.146.104    HTTP 263 GET http://www.google.se/?gfe_rd=cr&ei=AbeIV5zZHcaq8wfTlrjgCA HTTP/1.1
31   1.051006    195.249.146.104 -> 172.16.42.255 HTTP 71 HTTP/1.1 200 OK  (text/html)
```

### live capture using tshark
```
$ sudo nsntrace -f tcp -o - wget www.google.com  2> /dev/null | tshark -r -
1   0.000000 172.16.42.255 → 142.250.74.36 TCP 74 51088 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=1362504482 TSecr=0 WS=128
2   0.014010 142.250.74.36 → 172.16.42.255 TCP 74 80 → 51088 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1430 SACK_PERM=1 TSval=2846449454 Secr=1362504482 WS=256
3   0.014078 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=1362504496 TSecr=2846449454
4   0.014221 172.16.42.255 → 142.250.74.36 HTTP 207 GET / HTTP/1.1

5   0.033935 142.250.74.36 → 172.16.42.255 TCP 66 80 → 51088 [ACK] Seq=1 Ack=142 Win=66816 Len=0 TSval=2846449475 TSecr=1362504496
6   0.093989 142.250.74.36 → 172.16.42.255 TCP 1484 HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
7   0.094022 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [ACK] Seq=142 Ack=1419 Win=63360 Len=0 TSval=1362504576 TSecr=2846449532
8   0.096447 142.250.74.36 → 172.16.42.255 TCP 2902 HTTP/1.1 200 OK  [TCP segment of a reassembled PDU]
9   0.096478 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [ACK] Seq=142 Ack=4255 Win=62208 Len=0 TSval=1362504578 TSecr=2846449532
10   0.099871 142.250.74.36 → 172.16.42.255 HTTP 9626 Continuation[Packet size limited during capture]
11   0.099936 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [ACK] Seq=142 Ack=13815 Win=56320 Len=0 TSval=1362504582 TSecr=2846449532
12   0.100743 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [FIN, ACK] Seq=142 Ack=13815 Win=64128 Len=0 TSval=1362504583 TSecr=2846449532
13   0.113167 142.250.74.36 → 172.16.42.255 TCP 66 80 → 51088 [FIN, ACK] Seq=13815 Ack=143 Win=66816 Len=0 TSval=2846449554 TSecr=1362504583
14   0.113190 172.16.42.255 → 142.250.74.36 TCP 66 51088 → 80 [ACK] Seq=143 Ack=13816 Win=64128 Len=0 TSval=1362504595 TSecr=2846449554
```
