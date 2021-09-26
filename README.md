# switch_test
Experiment for testing an Ethernet switch by using per-port VLANs to direct traffic

================================

Under Windows 10 with the netgear DG834G connected as 4 port test switch ran:
sendpack.exe \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}

Which resulted in the packets as shown with a Wireshark filter of eth.addr==01:01:01:01:01:01 :
No.     Time           Source                Destination           Protocol Length Info
      2 1.717016       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     100    Bogus IPv4 version (1, must be 4)

Frame 2: 100 bytes on wire (800 bits), 100 bytes captured (800 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1015
    000. .... .... .... = Priority: Best Effort (default) (0)
    ...0 .... .... .... = DEI: Ineligible
    .... 0011 1111 0111 = ID: 1015
    Type: IPv4 (0x0800)
Internet Protocol Version 4
    0001 .... = Version: 1

No.     Time           Source                Destination           Protocol Length Info
      3 1.717130       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     96     Bogus IPv4 version (1, must be 4)

Frame 3: 96 bytes on wire (768 bits), 96 bytes captured (768 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
Internet Protocol Version 4
    0001 .... = Version: 1

No.     Time           Source                Destination           Protocol Length Info
      4 1.717130       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     96     Bogus IPv4 version (1, must be 4)

Frame 4: 96 bytes on wire (768 bits), 96 bytes captured (768 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
Internet Protocol Version 4
    0001 .... = Version: 1

No.     Time           Source                Destination           Protocol Length Info
      5 1.717130       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     96     Bogus IPv4 version (1, must be 4)

Frame 5: 96 bytes on wire (768 bits), 96 bytes captured (768 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
Internet Protocol Version 4
    0001 .... = Version: 1

This shows the VLAN headers have been stripped from the received packets.

The Ethernet device is Intel(R) 82579V Gigabit Network Connection


===============================================

https://wiki.wireshark.org/CaptureSetup/VLAN has information that Intel device can strip VLAN tags.

Using Microsoft driver v12.17.10.8 c:\Windows\system32\DRIVERS\e1i65x64.sys

https://www.intel.com/content/www/us/en/support/articles/000005498/network-and-i-o/ethernet-products.html has information
on registry settings to stop the Windows driver stripping the VLAN tags.

Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0003 is the registry
path for the installed "Intel(R) 82579V Gigabit Network Connection"

Tried setting MonitorModeEnabled = 1 but didn't stop VLAN tags being stripped

Setting MonitorMode = 1 did allow VLAN tags to be received:

No.     Time           Source                Destination           Protocol Length Info
    270 6.970821       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     100    Bogus IPv4 version (1, must be 4)

Frame 270: 100 bytes on wire (800 bits), 100 bytes captured (800 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1015
Internet Protocol Version 4

No.     Time           Source                Destination           Protocol Length Info
    271 6.971048       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     100    Bogus IPv4 version (1, must be 4)

Frame 271: 100 bytes on wire (800 bits), 100 bytes captured (800 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1013
Internet Protocol Version 4

No.     Time           Source                Destination           Protocol Length Info
    272 6.971048       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     100    Bogus IPv4 version (1, must be 4)

Frame 272: 100 bytes on wire (800 bits), 100 bytes captured (800 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1011
Internet Protocol Version 4

No.     Time           Source                Destination           Protocol Length Info
    273 6.971048       MS-NLB-PhysServer-02_02:02:02:02 Private_01:01:01      IPv4     100    Bogus IPv4 version (1, must be 4)

Frame 273: 100 bytes on wire (800 bits), 100 bytes captured (800 bits) on interface \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}, id 0
Ethernet II, Src: MS-NLB-PhysServer-02_02:02:02:02 (02:02:02:02:02:02), Dst: Private_01:01:01 (01:01:01:01:01:01)
802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 1009
Internet Protocol Version 4


==========================================

Test with all ports connected to a Netgear DG834G under test which shows a pass:
C:\Users\mr_halfword\switch_test\Debug>switch_test \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}
Saving frame results to frames_20210926T160120.csv
Elapsed time 12.090039
ps_recv=2402 ps_drop=0 ps_ifdrop=0
num_tx_test_frames=1200 num_rx_test_frames=2402 num_other_rx_frames=0

Test sent 100 frames for each combination of source and destination ports
Count of correctly received frames:
source  destination ports --->
port         0       1       2       3
     0             100     100     100
     1     100             100     100
     2     100     100             100
     3     100     100     100

Test: PASS

Prior to starting the test there was no activity shown on the switch ports under test

Removed the cable to switch port index 2 prior to starting the test, to cause a fault:
C:\Users\mr_halfword\switch_test\Debug>switch_test \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}
Saving frame results to frames_20210926T160255.csv
Elapsed time 12.090052
ps_recv=1805 ps_drop=0 ps_ifdrop=0
num_tx_test_frames=1200 num_rx_test_frames=1800 num_other_rx_frames=5

Test sent 100 frames for each combination of source and destination ports
Count of correctly received frames:
source  destination ports --->
port         0       1       2       3
     0             100       0     100
     1     100               0     100
     2       0       0               0
     3     100     100       0

Test: FAIL


Change the switch under test to be a Level One GSW-2472TGX
The LEDS on port index 0 where flashing on the injection switch and switch under test prior to starting the test,
which reported some missing frames for port index 0:
C:\Users\mr_halfword\switch_test\Debug>switch_test \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}
Saving frame results to frames_20210926T162611.csv
Elapsed time 12.090030
ps_recv=1899 ps_drop=0 ps_ifdrop=0
num_tx_test_frames=1200 num_rx_test_frames=1898 num_other_rx_frames=1

Test sent 100 frames for each combination of source and destination ports
Count of correctly received frames:
source  destination ports --->
port         0       1       2       3
     0               9      14      25
     1      13             100     100
     2      22     100             100
     3      13     100     100

Test: FAIL

However, on investigation the cable used for port index 0 was suspect as the issue:
a. Followed the cable when moved to a different port.
b. Went away when replaced the cable.


==========================

The number of ports used was inceased to 7, with the switch under test the Level One GSW-2472TGX

The VLAN configuration in the injection switch:
DES-3526:4#show vlan
Command: show vlan

VID             : 1          VLAN Name     : default
VLAN TYPE       : static     Advertisement : Enabled
Member ports    : 1-2,4,6,8,10,12,14,16-26
Static ports    : 1-2,4,6,8,10,12,14,16-26
Current Untagged ports : 1-2,4,6,8,10,12,14,16-26
Static Untagged ports  : 1-2,4,6,8,10,12,14,16-26
Forbidden ports :

VID             : 1003       VLAN Name     : port3
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 3,25
Static ports    : 3,25
Current Untagged ports : 3
Static Untagged ports  : 3
Forbidden ports :

VID             : 1005       VLAN Name     : port5
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 5,25
Static ports    : 5,25
Current Untagged ports : 5
Static Untagged ports  : 5
Forbidden ports :

VID             : 1007       VLAN Name     : port7
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 7,25
Static ports    : 7,25
Current Untagged ports : 7
Static Untagged ports  : 7
Forbidden ports :

VID             : 1009       VLAN Name     : port9
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 9,25
Static ports    : 9,25
Current Untagged ports : 9
Static Untagged ports  : 9
Forbidden ports :

VID             : 1011       VLAN Name     : port11
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 11,25
Static ports    : 11,25
Current Untagged ports : 11
Static Untagged ports  : 11
Forbidden ports :

VID             : 1013       VLAN Name     : port13
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 13,25
Static ports    : 13,25
Current Untagged ports : 13
Static Untagged ports  : 13
Forbidden ports :

VID             : 1015       VLAN Name     : port15
VLAN TYPE       : static     Advertisement : Disabled
Member ports    : 15,25
Static ports    : 15,25
Current Untagged ports : 15
Static Untagged ports  : 15
Forbidden ports :

Total Entries : 8

A test pass with all cables connected:
C:\Users\mr_halfword\switch_test\Debug>switch_test \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}
Saving frame results to frames_20210926T175550.csv
Elapsed time 42.090049
ps_recv=8405 ps_drop=0 ps_ifdrop=0
num_tx_test_frames=4200 num_rx_test_frames=8405 num_other_rx_frames=0

Test sent 100 frames for each combination of source and destination ports
Count of correctly received frames:
source  destination ports --->
port         0       1       2       3       4       5       6
     0             100     100     100     100     100     100
     1     100             100     100     100     100     100
     2     100     100             100     100     100     100
     3     100     100     100             100     100     100
     4     100     100     100     100             100     100
     5     100     100     100     100     100             100
     6     100     100     100     100     100     100

Test: PASS


An failure introduced by removing the cable for port index 3:
C:\Users\mr_halfword\switch_test\Debug>switch_test \Device\NPF_{478AF94A-7EC1-4E69-A500-E966D8ECCBDF}
Saving frame results to frames_20210926T175922.csv
Elapsed time 42.090076
ps_recv=7204 ps_drop=0 ps_ifdrop=0
num_tx_test_frames=4200 num_rx_test_frames=7200 num_other_rx_frames=4

Test sent 100 frames for each combination of source and destination ports
Count of correctly received frames:
source  destination ports --->
port         0       1       2       3       4       5       6
     0             100     100       0     100     100     100
     1     100             100       0     100     100     100
     2     100     100               0     100     100     100
     3       0       0       0               0       0       0
     4     100     100     100       0             100     100
     5     100     100     100       0     100             100
     6     100     100     100       0     100     100

Test: FAIL
