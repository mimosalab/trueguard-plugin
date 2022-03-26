cmake_minimum_required(VERSION 3.4.1)

add_library( trueguard
             SHARED
             src/main/jni/trueguard/trueguard.c
             src/main/jni/trueguard/session.c
             src/main/jni/trueguard/ip.c
             src/main/jni/trueguard/tcp.c
             src/main/jni/trueguard/udp.c
             src/main/jni/trueguard/icmp.c
             src/main/jni/trueguard/dns.c
             src/main/jni/trueguard/dhcp.c
             src/main/jni/trueguard/pcap.c
             src/main/jni/trueguard/util.c )

include_directories( src/main/jni/trueguard/ )

find_library( log-lib log )
target_link_libraries( trueguard ${log-lib} )