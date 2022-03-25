LPSD
====

LPSD is a simple log-based port scan detector written in C.
It detects port scans by examining syslog entries produced by nftables or iptables.

Example usage
-------------

Example usage with output (IP addresses are not censored in actual output).

    $ lpsd -i kern.log -t 10 -s 3
    2022-03-22 05:18:03 45.146.xxx.xxx 3 ports
    2022-03-22 08:44:27 78.128.xxx.xxx 3 ports
    2022-03-21 19:43:31 45.155.xxx.xxx 3 ports
    2022-03-22 07:42:55 45.155.xxx.xxx 3 ports
    2022-03-22 20:15:34 185.191.xxx.xxx 3 ports
    2022-03-22 10:06:57 2.57.xxx.xxx 3 ports
    2022-03-21 18:25:25 89.163.xxx.xxx 5 ports
    2022-03-22 16:52:45 45.155.xxx.xxx 3 ports
    ....

    $ lpsd -i kern.log -t 10 -s 3 -csv -p
    scan_time,address,ports
    2022-03-22 05:18:03,45.146.xxx.xxx,"TCP/2494, TCP/2513, TCP/2502"
    2022-03-22 08:44:27,78.128.xxx.xxx,"TCP/2116, TCP/2140, TCP/2111"
    2022-03-21 19:43:31,45.155.xxx.xxx,"TCP/2689, TCP/2678, TCP/2725"
    2022-03-22 07:42:55,45.155.xxx.xxx,"TCP/2689, TCP/2678, TCP/2725"
    2022-03-22 20:15:34,185.191.xxx.xxx,"TCP/64445, TCP/26269, TCP/23389"
    2022-03-22 10:06:57,2.57.xxx.xxx,"TCP/8884, TCP/8881, TCP/8890"
    2022-03-21 18:25:25,89.163.xxx.xxx,"UDP/5360, UDP/5160, UDP/5260, UDP/5460, UDP/5560"
    2022-03-22 16:52:45,45.155.xxx.xxx,"TCP/2169, TCP/2171, TCP/2157"
    2022-03-22 16:47:27,45.134.xxx.xxx,"TCP/5068, TCP/5087, TCP/5061, TCP/5069"
    2022-03-22 17:32:01,89.248.xxx.xxx,"TCP/8101, TCP/1311, TCP/8501"
    2022-03-22 00:59:20,31.172.xxx.xxx,"TCP/22643, TCP/16592, TCP/39354"
    2022-03-22 02:17:26,31.172.xxx.xxx,"TCP/22643, TCP/16592, TCP/39354"
    2022-03-22 02:59:51,31.172.xxx.xxx,"TCP/22643, TCP/16592, TCP/39354"
    ...
    
Example of log entry which LPSD can parse:

    Mar 22 23:51:32 debian kernel: [292481.303983] IN=eth0 OUT= MAC=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx SRC=105.28.xxx.xxx DST=10.12.93.2 LEN=44 TOS=0x00 PREC=0x00 TTL=7 ID=35 DF PROTO=ICMP TYPE=8 CODE=0 ID=41542 SEQ=34

Building
--------

GNU make and GCC is required to build LPSD.
No external dependencies are required, the standard library (with GNU extensions) has everything needed.

    $ make
    
Installation
------------

Install with the "install" target:

    $ make install
    
Uninstall with the "uninstall" target:
    
    $ make uninstall

Bugs
----

Please send bug reports to https://gitlab.com/4shadoww/lpsd
