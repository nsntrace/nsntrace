#!/bin/sh

num_packets=10

launch_nsntrace()
{
    local id="$1"
    local filter="icmp[icmptype]==icmp-echo"

    sudo ../src/nsntrace  -f "$filter" --use-public-dns -o "$id.pcap" ping -c $num_packets google.com > /dev/null 2>&1 &
    sleep 1.0e-3
}

for i in `seq 5`; do
    launch_nsntrace "$i"
done

sleep 20

for i in `seq 5`; do
    captured=$(tshark -r "$i.pcap" | wc -l)
    [ "$captured" = "$num_packets" ] || {
        echo "failed to capture all packets"
        exit 1
    }
done

rm -f *.pcap
exit 0
