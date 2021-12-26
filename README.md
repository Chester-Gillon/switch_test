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


== Realtek PCIe GBE Family Controller not capturing VLAN tags under Windows 10 20H2 ==

Running the switch_test under Windows 10 home 20H2 with a "Realtek PCIe GBE Family Controller" reports all frames missed.

The debug capture shows the test frams reported as "Rx Other" due to their being no VLAN tag.

https://osqa-ask.wireshark.org/questions/5996/how-to-configure-realtek-pcie-gbe-family-controller-to-capture-vlan-tag-packet/
describes the issue.

Under the adapter Advanced settings changed "Priority & VLAN" from "Priority & VLAN Enabled" to
"Priority & VLAN Disabled" and then rebooted.

After that change the received VLAN tags were still stipped. Therefore, reverted the change.

Followed http://forum.gns3.net/topic7559.html :
2. Once installed, went to my regedit in: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00nn
Where nn is the physical instance of the network port where you want to capture the VLAN tags.

3. Added / Edited the following DWORDS:

MonitorModeEnabled - 1
MonitorMode - 1
*PriorityVLANTag - 0
SkDisableVlanStrip - 1

Where the actual path was Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001
i.e. instance 1.

After a reboot when VLAN tags were no longer stripped upon receipt.

On the first run only ports 1-4 were reported as working:
C:\Users\mr_halfword\switch_test\Release>switch_test.exe -i \Device\NPF_{430850D4-29A0-4350-999F-67F14C708174} -d
Using interface \Device\NPF_{430850D4-29A0-4350-999F-67F14C708174} (Realtek PCIe GBE Family Controller)
Test interval = 10 (secs)
Frame debug enabled = Yes

14:44:11.286
      Tx Test        Tx Copy        Rx Test  Rx Unexpected     Rx Flooded       Rx Other  missed frames   tx rate (Hz)
        50657          50657           1098              0          22038              0          47939         5065.7

Summary of missed frames : '.' none missed 'S' some missed 'A' all misssed
Source  Destination ports --->
  port           111111111122222
        123456789012345678901234
     1   ...AAAAAAAAAAAAAAAAAAAA
     2  . ..AAAAAAAAAAAAAAAAAAAA
     3  .. .AAAAAAAAAAAAAAAAAAAA
     4  ... AAAAAAAAAAAAAAAAAAAA
     5  AAAA AAAAAAAAAAAAAAAAAAA
     6  AAAAA AAAAAAAAAAAAAAAAAA
     7  AAAAAA AAAAAAAAAAAAAAAAA
     8  AAAAAAA AAAAAAAAAAAAAAAA
     9  AAAAAAAA AAAAAAAAAAAAAAA
    10  AAAAAAAAA AAAAAAAAAAAAAA
    11  AAAAAAAAAA AAAAAAAAAAAAA
    12  AAAAAAAAAAA AAAAAAAAAAAA
    13  AAAAAAAAAAAA AAAAAAAAAAA
    14  AAAAAAAAAAAAA AAAAAAAAAA
    15  AAAAAAAAAAAAAA AAAAAAAAA
    16  AAAAAAAAAAAAAAA AAAAAAAA
    17  AAAAAAAAAAAAAAAA AAAAAAA
    18  AAAAAAAAAAAAAAAAA AAAAAA
    19  AAAAAAAAAAAAAAAAAA AAAAA
    20  AAAAAAAAAAAAAAAAAAA AAAA
    21  AAAAAAAAAAAAAAAAAAAA AAA
    22  AAAAAAAAAAAAAAAAAAAAA AA
    23  AAAAAAAAAAAAAAAAAAAAAA A
    24  AAAAAAAAAAAAAAAAAAAAAAA
Total test intervals with failures = 1 : last failure NOW

After rebooting the LevelOne GSW-2472TGX switch under test, via its serial console, the next test was successful:
C:\Users\mr_halfword\switch_test\Release>switch_test.exe -i \Device\NPF_{430850D4-29A0-4350-999F-67F14C708174} -d
Using interface \Device\NPF_{430850D4-29A0-4350-999F-67F14C708174} (Realtek PCIe GBE Family Controller)
Test interval = 10 (secs)
Frame debug enabled = Yes

14:48:40.796
      Tx Test        Tx Copy        Rx Test  Rx Unexpected     Rx Flooded       Rx Other  missed frames   tx rate (Hz)
        46647          46647          46645              0             22              0              0         4664.6

Summary of missed frames : '.' none missed 'S' some missed 'A' all misssed
Source  Destination ports --->
  port           111111111122222
        123456789012345678901234
     1   .......................
     2  . ......................
     3  .. .....................
     4  ... ....................
     5  .... ...................
     6  ..... ..................
     7  ...... .................
     8  ....... ................
     9  ........ ...............
    10  ......... ..............
    11  .......... .............
    12  ........... ............
    13  ............ ...........
    14  ............. ..........
    15  .............. .........
    16  ............... ........
    17  ................ .......
    18  ................. ......
    19  .................. .....
    20  ................... ....
    21  .................... ...
    22  ..................... ..
    23  ...................... .
    24  .......................
Total test intervals with failures = 0

Had some more instances on only ports 1 to 4 working, and from the serial console could see that the LevelOne GSW-2472TGX switch
had been rebooting itself.


== Maximum frame length allowing for VLAN tag ==

The orignal code set the size of ethercat_frame_t to 1514, which was the maximum specified in IEEE 802.3 prior to the
definition of the optional VLAN tag.

https://en.wikipedia.org/wiki/Ethernet_frame notes that the IEEE 802.3ac specification which added the VLAN tag
increased the maximum frame size by 4 octets to allow for the encapsulated VLAN tag

When the code was re-compiled to increase ethercat_frame_t to 1518 then PC with the Intel(R) 82579V Gigabit Network adapter:
a. Running Linux (3.10 Kernel) that the code ran successfully, and Wireshark showed the increase in the frame size.
b. Running under Windows 10 failed with:
Error sending the packet: send error: PacketSendPacket failed: A device attached to the system is not functioning.  (31)

PacketSendPacket(), the function returning the error, is from the PACKET.DLL packet capture driver

Under Windows 10 the MTU is reported as 1500:
C:\Users\mr_halfword\switch_test\Release>netsh interface ipv4 show subinterface

   MTU  MediaSenseState   Bytes In  Bytes Out  Interface
------  ---------------  ---------  ---------  -------------
4294967295                1          0       8065  Loopback Pseudo-Interface 1
  1500                1   31410294    4207260  Ethernet 3
  1500                1          0      42376  vEthernet (Default Switch)

Tried increasing the MTU by 4 bytes (as administrator):
C:\WINDOWS\system32>netsh interface ipv4 set subinterface "Ethernet 3" mtu=1504 store=persistent
Ok.

Which reads back as changed:
C:\Users\mr_halfword\switch_test\Release>netsh interface ipv4 show subinterface

   MTU  MediaSenseState   Bytes In  Bytes Out  Interface
------  ---------------  ---------  ---------  -------------
4294967295                1          0       8065  Loopback Pseudo-Interface 1
  1504                1   31413790    4209263  Ethernet 3
  1500                1          0      43184  vEthernet (Default Switch)

But still fails, and a re-boot didn't help.

The same issue occurred on the Windows 10 laptop with a "Realtek PCIe GBE Family Controller"

Due to the above reverted the MTU to the original value of 1500.

What did work is enabling Jumbo Frames:
a. For the "Realtek PCIe GBE Family Controller" in the Device Manager in Advanced changed the "Jumbo Frame"
   from "Disabled" to "2KB MTU".
b. For the "Intel(R) 82579V Gigabit Network" in the Device Manager in Advanced changed the "Jumbo Packet"
   from "Disabled" to "4088 Bytes".
c. For the "Mellanox ConnectX-2 Ethernet Adapter" in the Device Manager in Advanced changed the "Jumbo Packet"
   from "1514" to "9600".


== Mellanox ConnectX-2 not capturing VLAN tags under Windows 10 21H1 ==

Running the switch_test under Windows 10 pro 21H1 with a "Mellanox ConnectX-2" reports all frames missed.

The debug capture shows the test frames reported as "Rx Other" due to their being no VLAN tag.

Can't find any documented way to stop the VLAN tags from being stripped on receipt when using the
regular network stack.

With the same computer booted into Ubuntu 18.04 the frames received from the Mellanox ConnectX-2
had the VLAN tag. I.e. appears to be a Windows driver limitation.
