/**
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <pcap.h>


#define NSECS_PER_SEC 1000000000LL

/* Ethernet frame types */
#define ETH_P_8021Q    0x8100
#define ETH_P_ETHERCAT 0x88a4


#define ETHER_MAC_ADDRESS_LEN 6

/** Defines the unique identity used for one switch port under test.
 *  The MAC address is used by the switch under test to route traffic to the expected port.
 *  The VLAN is used by the injection switch.
 */
typedef struct
{
    uint8_t mac_addr[ETHER_MAC_ADDRESS_LEN];
    uint16_t vlan;
} port_id_t;


/** Define a locally administated MAC address and VLAN for each switch port under test */
#define NUM_TEST_PORTS 4
static port_id_t test_ports[NUM_TEST_PORTS] =
{
    { .mac_addr = {2,0,1,0,0,9}, .vlan = 1009},
    { .mac_addr = {2,0,1,0,1,1}, .vlan = 1011},
    { .mac_addr = {2,0,1,0,1,3}, .vlan = 1013},
    { .mac_addr = {2,0,1,0,1,5}, .vlan = 1015},
};


/**
 * Defines the layout of one maximum length Ethernet frame, with a single EtherCAT datagram, for the test.
 * EtherCAT has it own EtherType which can be used to filter the received frames to only those frames.
 *
 * Layout taken from:
 *   https://www.szcomark.com/info/ethercat-frame-structure-59044613.html
 *   https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_io_intro/1257993099.html
 *
 * The Address is used a sequence number incremented for each test frame transmitted.
 */
#define ETHERCAT_DATAGRAM_LEN 1482 /* Results in maximum length Ethernet frame when VLAN tag present */
typedef struct __attribute__((packed)) 
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


/* Next transmit sequence number inserted in the Address of the EtherCAT frame */
static uint32_t next_transmit_sequence_number;


/**
 * @brief Select which network interface to use for the switch test.
 * @details Gets the list of interfaces from NPCAP and prompts the user.
 * @return Returns the name of the network interface to open.
 */
static const char *select_interface (void)
{
    const char *selected_interface_name = NULL;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc;
    int dev_num;
    int selected_dev_num;
    
    rc = pcap_findalldevs (&alldevs, errbuf);
    if (rc != 0)
    {
        fprintf (stderr,"Error in pcap_findalldevs(): %s\n", errbuf);
        exit (EXIT_FAILURE);
    }
    
    /* Print the list */
    dev_num = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        printf ("%d. %s", ++dev_num, dev->name);
        if (dev->description != NULL)
        {
            printf (" (%s)\n", dev->description);
        }
        else
        {
            printf (" (No description available)\n");
        }
    }
    
    /* Prompt for which interface to use */
    printf ("Enter the interface number (1-%d):", dev_num);
    scanf ( "%d", &selected_dev_num);
    if ((selected_dev_num < 1) || (selected_dev_num > dev_num))
    {
        printf ("\nInterface number out of range.\n");
        pcap_freealldevs (alldevs);
        exit (EXIT_FAILURE);
    }

    /* Take a copy of the selected interface name to return */
    dev_num = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        dev_num++;
        if (dev_num == selected_dev_num)
        {
            selected_interface_name = strdup (dev->name);
        }
    }

    pcap_freealldevs (alldevs);
    
    return selected_interface_name;
}


/**
 * @brief Open the network interace used to communicate with the test switch
 * @details Open the interface and configures NPCAP options for the test program.
 * @param[in] interface_name NPCAP interface name to open
 * @return Returns the NPCAP handle for the opened network interface
 */
static pcap_t *open_interface (const char *const interface_name)
{
    int rc;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *const pcap_handle = pcap_create (interface_name, errbuf);
    
    if (pcap_handle == NULL)
    {
        fprintf (stderr,"Error in pcap_create(): %s\n", errbuf);
        exit (EXIT_FAILURE);
    }
    
    /* Need to enable promiscuous mode to receive the test packets from the switch */
    const int promisc_enable = 1;
    rc = pcap_set_promisc (pcap_handle, promisc_enable);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_set_promisc(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Capture the entire length of the test packets */
    const int max_snaplen = 65536;
    rc = pcap_set_snaplen (pcap_handle, max_snaplen);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_set_snaplen(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Enable immediate receive mode as use polling to alternate between sending at a specified rate and
     * checking for the receipt of the test packets. */
    const int immediate_mode = 1;
    rc = pcap_set_immediate_mode (pcap_handle, immediate_mode);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_set_immediate_mode(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Activate the interface for use */
    rc = pcap_activate (pcap_handle);
    if (rc < 0)
    {
        fprintf (stderr, "Error in pcap_activate(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    else if (rc > 0)
    {
        printf ("Warning in pcap_activate(): %s\n", pcap_statustostr (rc));
    }
    
    /* Check the interface is Ethernet */
    const int link_layer = pcap_datalink (pcap_handle);
    if (link_layer != DLT_EN10MB)
    {
        fprintf (stderr, "This program only operates on an Ethernet link layer pcap_datalink(%s); returned %d\n",
                interface_name, link_layer);
        exit (EXIT_FAILURE);
    }
    
    return pcap_handle;
}


/**
 * @brief Create a EtherCAT test frame which can be sent.
 * @details The EtherCAT commands and datagram contents are not significant; have just used values which populate
 *          a maximum length frame and for which Wireshark reports a valid frame (for debugging).
 * @param frame[out] The populated frame which can be transmitted.
 * @param source_port_index[in] The index into test_ports[] which selects the source MAC address and outgoing VLAN.
 * @param destination_port_index[in] The index into test_ports[] which selects the destination MAC address.
 */
static void create_test_frame (ethercat_frame_t *const frame, 
                               const uint32_t source_port_index, const uint32_t destination_port_index)
{
    memset (frame, 0, sizeof (*frame));
    
    /* MAC addresses */
    memcpy (frame->destination_mac_addr, test_ports[destination_port_index].mac_addr,
            sizeof (frame->destination_mac_addr));
    memcpy (frame->source_mac_addr, test_ports[source_port_index].mac_addr,
            sizeof (frame->source_mac_addr));
    
    /* VLAN */
    frame->ether_type = htons (ETH_P_8021Q);
    frame->vlan_tci = htons (test_ports[source_port_index].vlan);

    frame->vlan_ether_type = htons (ETH_P_ETHERCAT);
    
    frame->Length = sizeof (ethercat_frame_t) - offsetof (ethercat_frame_t, Cmd);
    frame->Type = 1; /* EtherCAT commands */
    frame->Cmd = 11; /* Logical Memory Write */
    frame->Len = ETHERCAT_DATAGRAM_LEN;
    
    static uint8_t fill_value;
    for (uint32_t data_index = 0; data_index < ETHERCAT_DATAGRAM_LEN; data_index++)
    {
        frame->data[data_index] = fill_value++;
    }
    
    frame->Address = next_transmit_sequence_number;
    next_transmit_sequence_number++;
}


/*
 * @brief Return a monotonic time in integer nanoseconds
 */
static int64_t get_monotonic_time (void)
{
    int rc;
    struct timespec now;
    
    rc = clock_gettime (CLOCK_MONOTONIC, &now);
    if (rc != 0)
    {
        fprintf (stderr, "clock_getime(CLOCK_MONOTONIC) failed\n");
        exit (EXIT_FAILURE);
    }
    
    return (now.tv_sec * NSECS_PER_SEC) + now.tv_nsec;
}


int main (int argc, char *argv[])
{
    /* Check that ethercat_frame_t has the expected size */
    if (sizeof (ethercat_frame_t) != 1514)
    {
        fprintf (stderr, "sizeof (ethercat_frame_t) unexpected value of %" PRIuPTR "\n", sizeof (ethercat_frame_t));
        exit (EXIT_FAILURE);
    }
    
    /* When an interface name is provided on the command line then use that, otherwise ask the user */
    const char *const interface_name = (argc > 1) ? argv[1] : select_interface ();
    
    pcap_t *const pcap_handle = open_interface (interface_name);

    ethercat_frame_t tx_frame;
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    
    const int64_t start_time = get_monotonic_time ();
    const int64_t stop_time = start_time + (10 * NSECS_PER_SEC);
    int64_t now;
    int rc;
    
    /* Set to transmit one frame at a slow rate of every 100 ms just to visualise what is received */
    const int64_t send_interval = 100000000;
    int64_t next_frame_send_time = start_time;
    
    uint32_t source_port_index = 0;
    uint32_t destination_port_index = 1;
    
    uint64_t num_tx_test_frames = 0;
    uint64_t num_rx_test_frames = 0;
    uint64_t num_other_rx_frames = 0;
    
    /* Run test for a fix period of time, sending frames at a fixed rate and recording which are received.
       This uses a busy-polling loop to determine when is time for the next transmit frame, or to poll for
       received frames. */
    do
    {
        now = get_monotonic_time ();
        
        if (now >= next_frame_send_time)
        {
            /* Send the next frame, cycling around combinations of the source and destination ports */
            create_test_frame (&tx_frame, source_port_index, destination_port_index);
            rc = pcap_sendpacket (pcap_handle, (const u_char *) &tx_frame, sizeof (tx_frame));
            if (rc != 0)
            {
                fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(pcap_handle));
                exit (EXIT_FAILURE);
            }
            num_tx_test_frames++;
            next_frame_send_time += send_interval;
            
            do
            {
                source_port_index = (source_port_index + 1) % NUM_TEST_PORTS;
                if (source_port_index == 0)
                {
                    destination_port_index = (destination_port_index + 1) % NUM_TEST_PORTS;
                }
            } while (source_port_index == destination_port_index);
        }
        else
        {
            /* Poll for receipt of packet */
            rc = pcap_next_ex (pcap_handle, &pkt_header, &pkt_data);
            if (rc == PCAP_ERROR)
            {
                fprintf(stderr,"\nError receiving packet: %s\n", pcap_geterr(pcap_handle));
                exit (EXIT_FAILURE);
            }
            else if (rc == 1)
            {
                /* Packet received */
                bool is_test_frame = pkt_header->len >= sizeof (ethercat_frame_t);
                
                if (is_test_frame)
                {
                    const ethercat_frame_t *const rx_frame = (const ethercat_frame_t *) pkt_data;
                    
                    is_test_frame = (ntohs (rx_frame->ether_type) == ETH_P_8021Q) &&
                            (ntohs (rx_frame->vlan_ether_type) == ETH_P_ETHERCAT);
                }
                
                if (is_test_frame)
                {
                    num_rx_test_frames++;
                }
                else
                {
                    num_other_rx_frames++;
                }
            }
        }
    } while (now < stop_time);
    now = get_monotonic_time ();
    
    struct pcap_stat statistics;
    rc = pcap_stats (pcap_handle, &statistics);
    if (rc == PCAP_ERROR)
    {
        fprintf(stderr,"\npcap_stats() failed: %s\n", pcap_geterr(pcap_handle));
        exit (EXIT_FAILURE);
    }

    pcap_close (pcap_handle);

    printf ("Elapsed time %.6f\n", (now - start_time) / 1E9);
    printf ("ps_recv=%u ps_drop=%u ps_ifdrop=%u\n", statistics.ps_recv, statistics.ps_drop, statistics.ps_ifdrop);
    printf ("num_tx_test_frames=%" PRIu64 " num_rx_test_frames=%" PRIu64 " num_other_rx_frames=%" PRIu64 "\n",
            num_tx_test_frames, num_rx_test_frames, num_other_rx_frames);
    
    return EXIT_SUCCESS;
}
