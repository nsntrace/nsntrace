#!/bin/sh

# HUP INT QUIT ABRT TERM
signals='1 2 3 6 15'
timeout=3
ip="172.16.42.254"
if=nsntrace

function check_cleanup() {
    # sleep to allow for cleanup after signal
    sleep 1

    (sudo iptables -w -t nat -L | grep $ip) && {
        echo "Rules not cleaned up after signal $signal"
        exit 1
    }

    (sudo ip link | grep $if) && {
        echo "Link not cleaned up after signal $signal"
        exit 1
    }
}

function start_and_kill() {
    local signal=$1

    sudo ../src/nsntrace -o $signal.pcap ./test_program_dummy.sh &
    sleep $timeout
    pid=$(pidof nsntrace)
    sudo kill -$signal $pid

    check_cleanup
 }

for signal in $signals; do
    start_and_kill $signal
done

exit 0
