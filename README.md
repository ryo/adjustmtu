adjustmtu
=========

adjustmtu - detect MTU size and set MTU size of routing table

adjusmtu detect MTU with sending various size of ICMP ECHO-REQUEST or Padded ARP packets,
and set MTU size on routing table.
useful for setting MTU automatically on over 1500 MTU (jumboframe) network.

usage
-----
	(one shot mode; localhost=MTU9000, 10.0.0.1=MTU9000)
	# adjustmtu -P -v 10.0.0.1
	10.0.0.1: send 32768 bytes icmp: Message too long
	10.0.0.1: send 16384 bytes icmp: Message too long
	10.0.0.1: send 8192 bytes icmp: echo reply OK (0.883 ms)
	10.0.0.1: send 12288 bytes icmp: Message too long
	10.0.0.1: send 10240 bytes icmp: Message too long
	10.0.0.1: send 9216 bytes icmp: Message too long
	10.0.0.1: send 8704 bytes icmp: echo reply OK (0.739 ms)
	10.0.0.1: send 8960 bytes icmp: echo reply OK (0.707 ms)
	10.0.0.1: send 9088 bytes icmp: Message too long
	10.0.0.1: send 9024 bytes icmp: Message too long
	10.0.0.1: send 8992 bytes icmp: echo reply OK (0.759 ms)
	10.0.0.1: send 9008 bytes icmp: Message too long
	10.0.0.1: send 9000 bytes icmp: echo reply OK (0.768 ms)
	10.0.0.1: send 9004 bytes icmp: Message too long
	10.0.0.1: send 9002 bytes icmp: Message too long
	detect 10.0.0.1 MTU 9000

	(and set mtu size of routing table automatically)
	# netstat -nrfinet|fgrep 10.0.0.1
	10.0.0.1       10.0.0.1           UGH         -        -   9000  aq0
	                                                           ^^^^
	(Destination   Gateway		  Flags    Refs      Use    Mtu Interface)


	(one shot mode; localhost=MTU9000, 10.0.0.150=MTU1500)
	# adjustmtu -P -v ancient-host
	10.0.0.150: send 32768 bytes icmp: Message too long
	10.0.0.150: send 16384 bytes icmp: Message too long
	10.0.0.150: 8192 bytes ping timeout
	10.0.0.150: 8192 bytes ping timeout
	10.0.0.150: 8192 bytes ping timeout
	10.0.0.150: 4096 bytes ping timeout
	10.0.0.150: 4096 bytes ping timeout
	10.0.0.150: 4096 bytes ping timeout
	10.0.0.150: 2048 bytes ping timeout
	10.0.0.150: 2048 bytes ping timeout
	10.0.0.150: 2048 bytes ping timeout
	10.0.0.150: 1536 bytes ping timeout
	10.0.0.150: 1536 bytes ping timeout
	10.0.0.150: 1536 bytes ping timeout
	10.0.0.150: send 1408 bytes icmp: echo reply OK (0.620 ms)
	10.0.0.150: send 1472 bytes icmp: echo reply OK (0.674 ms)
	10.0.0.150: 1504 bytes ping timeout
	10.0.0.150: 1504 bytes ping timeout
	10.0.0.150: 1504 bytes ping timeout
	10.0.0.150: send 1488 bytes icmp: echo reply OK (0.516 ms)
	10.0.0.150: send 1496 bytes icmp: echo reply OK (0.694 ms)
	10.0.0.150: send 1500 bytes icmp: echo reply OK (0.743 ms)
	10.0.0.150: 1502 bytes ping timeout
	10.0.0.150: 1502 bytes ping timeout
	10.0.0.150: 1502 bytes ping timeout
	detect 10.0.0.150 MTU 1500


	(daemon mode)
	# adjustmtu -d -i wm0 -i wm1


in daemon mode, this program checks routing socket to find hosts in local segment, and detects and set mtu automatically.
