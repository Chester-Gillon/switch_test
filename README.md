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
