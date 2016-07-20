#nsntrace
> Perform network trace of a single process by using network namespaces.

This application uses Linux network namespaces to perform network traces of a single application. The traces are saved as pcap files. And can later be analyzed by for instance Wireshark.

The nsntrace application is heavily inspired by the askbubuntu reply [here](http://askubuntu.com/a/499850).
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

## usage
    > nsntrace
    usage: nsntrace [-o file] [-d device] [-u username] PROG [ARGS]
    Perform network trace of a single process by using network namespaces.

    -o file		send trace output to file (default nsntrace.pcap)
    -d device	the network device to trace
    -f filter	an optional capture filter
    -u username	run PROG as username

## example
    > sudo nsntrace -d eth1 wget www.google.com
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

    > tshark -r nsntrace.pcap -Y 'http.response or http.request'
    16   0.998839 172.16.42.255 -> 195.249.146.104    HTTP 229 GET http://www.google.com/ HTTP/1.1
    20   1.010671    195.249.146.104 -> 172.16.42.255 HTTP 324 HTTP/1.1 302 Moved Temporarily  (text/html)
    22   1.010898 172.16.42.255 -> 195.249.146.104    HTTP 263 GET http://www.google.se/?gfe_rd=cr&ei=AbeIV5zZHcaq8wfTlrjgCA HTTP/1.1
    31   1.051006    195.249.146.104 -> 172.16.42.255 HTTP 71 HTTP/1.1 200 OK  (text/html)
