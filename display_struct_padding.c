/*
 * Program to evalute structure padding
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef USE_PACKING
#define PACK_STRUCT __attribute__((packed))
#else
#define PACK_STRUCT
#endif

#define ETHER_MAC_ADDRESS_LEN 6

/**
 * Defines the layout of one maximum length Ethernet frame, with a single EtherCAT datagram, for the test.
 * EtherCAT has it own EtherType which can be used to filter the received frames to only those frames.
 *
 * Layout taken from:
 *   https://www.szcomark.com/info/ethercat-frame-structure-59044613.html
 *   https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_io_intro/1257993099.html
 *
 * The Address is used a sequence number incremented for each test frame transmitted.
 *
 * The value of ETHERCAT_DATAGRAM_LEN results in the maximum MTU of 1500, which is formed from the EtherCAT Datagram header
 * through Working Counter inclusive.
 *
 * https://en.wikipedia.org/wiki/Ethernet_frame notes that the IEEE 802.3ac specification which added the
 * VLAN tag increased the maximum frame size by 4 octets to allow for the encapsulated VLAN tag.
 */
#define ETHERCAT_DATAGRAM_LEN 1486
typedef struct PACK_STRUCT 
{
    /* Ethernet Header */
    uint8_t destination_mac_addr[ETHER_MAC_ADDRESS_LEN];
    uint8_t source_mac_addr[ETHER_MAC_ADDRESS_LEN];
    uint16_t ether_type; /* Set to indicate a VLAN */

    /* VLAN id */
    uint16_t vlan_tci;
    
    uint16_t vlan_ether_type;
    
    /* EtherCAT header */
    uint16_t Length:11;  /* Length of the EtherCAT datagram (without FCS) */
    uint16_t Reserved:1; /* Reserved, 0 */
    uint16_t Type:4;     /* Protocol type. EtherCAT slave controllers (ESCs) only support EtherCAT commands (type = 0x1). */
    
    /* EtherCAT Datagram header */
    uint8_t Cmd; /* EtherCAT command type */
    uint8_t Idx; /* The index is a numerical identifier used by the master to identify duplicates or lost
                  * datagrams. The EtherCAT slaves should not change the index. */
    uint32_t Address; /* Address: auto-increment, configured station address or logical address */
    uint16_t Len:11;  /* Length of the data following within this datagram */
    uint16_t R:3;     /* Reserved, 0 */
    uint16_t C:1;     /* Circulating frame:
                       * 0: Frame does not circulate
                       * 1: Frame has circulated once */
    uint16_t M:1;     /* Multiple EtherCAT datagrams
                       * 0: Last EtherCAT datagram
                       * 1: At least one further EtherCAT datagram follows */
    uint16_t IRQ;     /* EtherCAT event request register of all slave devices combined with a logical OR */
    uint8_t data[ETHERCAT_DATAGRAM_LEN]; /* Data to be read or written */
    uint16_t WKC;     /* Working Counter */
} ethercat_frame_t;

#define PRINT_STRUCT_SIZE(struct_type) \
    printf (#struct_type ",%lu\n", sizeof (struct_type))

#define PRINT_STRUCT_FIELD(struct_type,field) \
    printf (#struct_type "." #field ",%lu,%lu\n", sizeof(((struct_type *)0)->field), offsetof(struct_type,field));
    
int main (int argc, char *arv[])
{
    printf ("Structure name,Size (bytes),Offset (bytes)\n");
    PRINT_STRUCT_SIZE (ethercat_frame_t);
    PRINT_STRUCT_FIELD (ethercat_frame_t, destination_mac_addr);
    PRINT_STRUCT_FIELD (ethercat_frame_t, source_mac_addr);
    PRINT_STRUCT_FIELD (ethercat_frame_t, ether_type);
    PRINT_STRUCT_FIELD (ethercat_frame_t, vlan_tci);
    PRINT_STRUCT_FIELD (ethercat_frame_t, Cmd);
    PRINT_STRUCT_FIELD (ethercat_frame_t, Idx);
    PRINT_STRUCT_FIELD (ethercat_frame_t, Address);
    PRINT_STRUCT_FIELD (ethercat_frame_t, IRQ);
    PRINT_STRUCT_FIELD (ethercat_frame_t, data);
    PRINT_STRUCT_FIELD (ethercat_frame_t, WKC);
    
    return 0;
}
