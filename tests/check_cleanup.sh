#!/bin/sh

# HUP INT QUIT ABRT SEGV TERM
signals='1 2 3 6 11 15'
timeout=1
ip="172.16.42.254"
if=nsntrace

check_cleanup() {
    local pid="$1"
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

    ls "/run/nsntrace/$1" > /dev/null 2>&1 && {
        echo "run-time files not cleaned up after signal $signal"
        exit 1
    }

    rm -rf *.pcap
}

start_and_kill() {
    local signal=$1

    sudo ../src/nsntrace ./test_program_dummy.sh &
    sleep $timeout
    pid=$(pidof nsntrace)
    sudo kill -$signal $pid

    check_cleanup "$pid"
 }

for signal in $signals; do
    start_and_kill $signal
done

sudo ../src/nsntrace ./test_program_dummy_ends.sh
check_cleanup "$!"

exit 0
