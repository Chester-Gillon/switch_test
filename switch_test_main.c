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


/* Identifies one type of frame recorded by the test */
typedef enum
{
    /* A frame transmitted by the test */
    FRAME_RECORD_TX_TEST_FRAME,
    /* A frame received by the test, which matches that of the EtherCAT frame transmitted */
    FRAME_RECORD_RX_TEST_FRAME,
    /* A frame received by the test, which isn't one transmitted */
    FRAME_RECORD_RX_OTHER,
    
    FRAME_RECORD_ARRAY_SIZE
} frame_record_type_t;


/* Used to record one frame transmitted or received during the test */
typedef struct
{
    /* Identifies the type of frame */
    frame_record_type_t frame_type;
    /* The relative time from the start of the test that the frame was sent or received.
       This is using the monotonic time used by the test busy-polling loop rather than the receive time
       recorded in the pcap packet header. */
    int64_t relative_test_time;
    /* The destination and source MAC addresses from the frame */
    uint8_t destination_mac_addr[ETHER_MAC_ADDRESS_LEN];
    uint8_t source_mac_addr[ETHER_MAC_ADDRESS_LEN];
    /* The length of the frame */
    bpf_u_int32 len;
    /* The ether type of the frame, the field this is extracted from depends upon if there is a VLAN */
    uint16_t ether_type;
    /* True if the frame was for a VLAN */
    bool vlan_present;
    /* When vlan_present is true identifies the VLAN this was for */
    uint16_t vlan_id;
    /* When frame_type is FRAME_RECORD_TX_TEST_FRAME or FRAME_RECORD_RX_TEST_FRAME the sequence number of the frame.
     * Allows received frames to be matched against the transmitted frame. */
    uint32_t test_sequence_number;
} frame_record_t;


/* Used to count the frames sent/received during the test */
static uint64_t frame_counts[FRAME_RECORD_ARRAY_SIZE];


/* Used to record the frames sent/received during the test */
#define MAX_FRAME_RECORDS 1000000
static frame_record_t *frame_records;
static uint32_t num_frame_records;


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
    
    /* Disable the timeout to allow pcap_next_ex() to poll for packets.
       From the documentation this might not be supported on all systems, but has worked on Windows 10 and a Linux 3.10 Kernel. */
    const int no_timeout = -1;
    rc = pcap_set_timeout (pcap_handle, no_timeout);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_set_timeout(): %s\n", pcap_statustostr (rc));
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
    
    /* Capture only the receive frames, and not our transmit frames */
    
    /* This has been commented out since with a Intel Corporation 82579V Gigabit Network Connection:
       a. Under Windows 10 failed with PCAP_ERROR.
       b. Under CentOS 6.10 with a 3.10.33-rt32.33.el6rt.x86_64 Kernel with libpcap 1.4.0 worked.
    rc = pcap_setdirection (pcap_handle, PCAP_D_IN);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_setdirection(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    */
    
    /* Set a filter to only receive packets which have EtherCAT protocol encapsulated within a VLAN,
     * which are those sent/received by the test program.
     * I.e. filter out packets for other traffic.
     * The filter has to be compiled after the pcap handle has been activited, so that the link-layer is known. */

    /* This has been commented out since with a Intel Corporation 82579V Gigabit Network Connection:
       a. Under Windows 10 the filter worked as expected.
       b. Under CentOS 6.10 with a 3.10.33-rt32.33.el6rt.x86_64 Kernel with libpcap 1.4.0 the filter had the effect of not 
          capturing any receive EtherCAT frames, and only capturing the transmitted frames.
          The same issue occurred when using the same filter in Wireshark.

    char filter_command[80];
    struct bpf_program filter_program;
    snprintf (filter_command, sizeof (filter_command), "vlan&&ether proto 0x%x", ETH_P_ETHERCAT);
    const int optimize = 1;
    rc = pcap_compile (pcap_handle, &filter_program, filter_command, optimize, 0xffffffff);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_compile(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    rc = pcap_setfilter (pcap_handle, &filter_program);
    if (rc != 0)
    {
        fprintf (stderr, "Error in pcap_setfilter(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    */
    
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


/*
 * @brief Record information about an Ethernet frame transmitted or received during a test
 * @param[in] pkt_header When non-null the received packet header.
 *                       When NULL indicates are being called to record a transmitted test frame
 * @param[in] frame The frame to record information for
 * @param[in] start_time The start monotonic time for the test, used to record the relative time for the frame
 */
static void record_test_frame (const struct pcap_pkthdr *const pkt_header, const ethercat_frame_t *const frame,
                               const int64_t start_time)
{
    frame_record_type_t frame_type;
    bpf_u_int32 len;
    
    const uint16_t ether_type = ntohs (frame->ether_type);
    const uint16_t vlan_ether_type = ntohs (frame->vlan_ether_type);
    
    if (pkt_header != NULL)
    {
        /* Determine if the receive frame is one sent by the test program or not */
        bool is_test_frame = pkt_header->len >= sizeof (ethercat_frame_t);
        
        if (is_test_frame)
        {
            is_test_frame = (ether_type == ETH_P_8021Q) && (vlan_ether_type == ETH_P_ETHERCAT);
        }
        
        frame_type = is_test_frame ? FRAME_RECORD_RX_TEST_FRAME : FRAME_RECORD_RX_OTHER;
        len = pkt_header->len;
    }
    else
    {
        frame_type = FRAME_RECORD_TX_TEST_FRAME;
        len = sizeof (ethercat_frame_t);
    }
    
    /* Store the frame summary if space */
    if (num_frame_records < MAX_FRAME_RECORDS)
    {
        frame_record_t *const frame_record = &frame_records[num_frame_records];
        
        frame_record->frame_type = frame_type;
        frame_record->relative_test_time = get_monotonic_time () - start_time;
        memcpy (frame_record->destination_mac_addr, frame->destination_mac_addr, sizeof (frame_record->destination_mac_addr));
        memcpy (frame_record->source_mac_addr, frame->source_mac_addr, sizeof (frame_record->source_mac_addr));
        frame_record->len = len;
        frame_record->vlan_present = ether_type == ETH_P_8021Q;
        if (frame_record->vlan_present)
        {
            frame_record->ether_type = vlan_ether_type;
            frame_record->vlan_id = ntohs (frame->vlan_tci);
        }
        else
        {
            frame_record->ether_type = ether_type;
        }
        
        if (frame_type != FRAME_RECORD_RX_OTHER)
        {
            frame_record->test_sequence_number = frame->Address;
        }
            
        num_frame_records++;
    }
    
    /* Maintain the frame counts */
    frame_counts[frame_type]++;
}


/**
 * @brief Write a hexadecimal MAC address to a CSV file
 * @param[in/out] csv_file File to write to
 * @param[in] mac_addr The MAC address to write
 */
static void write_mac_addr (FILE *const csv_file, const uint8_t *const mac_addr)
{
    for (uint32_t byte_index = 0; byte_index < ETHER_MAC_ADDRESS_LEN; byte_index++)
    {
        fprintf (csv_file, "%s%02X", (byte_index == 0) ? ", " : "-", mac_addr[byte_index]);
    }
}


/**
 * @brief write a CSV file which contains information about the frames transmitted and received during the test
 */
static void write_recorded_frames (void)
{
    const time_t now = time (NULL);
    struct tm broken_down_time;
    char csv_filename[80];
    
    const char *const frame_type_names[FRAME_RECORD_ARRAY_SIZE] =
    {
        [FRAME_RECORD_TX_TEST_FRAME] = "Tx test",
        [FRAME_RECORD_RX_TEST_FRAME] = "Rx test",
        [FRAME_RECORD_RX_OTHER     ] = "Rx other"
    };
    
    /* Create a CSV filename containing the current date/time */
    localtime_r (&now, &broken_down_time);
    strftime (csv_filename, sizeof (csv_filename), "frames_%Y%m%dT%H%M%S.csv", &broken_down_time);
    printf ("Saving frame results to %s\n", csv_filename);
    
    /* Create CSV file and write headers */
    FILE *csv_file = fopen (csv_filename, "w");
    if (csv_file == NULL)
    {
        fprintf (stderr, "Failed to create %s\n", csv_filename);
        exit (EXIT_FAILURE);
    }
    fprintf (csv_file, "frame type,relative test time (secs),destination MAC addr,source MAC addr,len,ether type,VLAN,test sequence number\n");
    
    /* Write one row for each frame recorded for the test */
    for (uint32_t frame_index = 0; frame_index < num_frame_records; frame_index++)
    {
        const frame_record_t *const frame_record = &frame_records[frame_index];
        
        fprintf (csv_file, "%s,%.6f",
                frame_type_names[frame_record->frame_type], frame_record->relative_test_time / 1E9);
        write_mac_addr (csv_file, frame_record->destination_mac_addr);
        write_mac_addr (csv_file, frame_record->source_mac_addr);
        fprintf (csv_file, ",%u,'%04x", frame_record->len, frame_record->ether_type);
        if (frame_record->vlan_present)
        {
            fprintf (csv_file, ",%" PRIu32, frame_record->vlan_id);
        }
        else
        {
            fprintf (csv_file, ",");
        }
        if (frame_record->frame_type != FRAME_RECORD_RX_OTHER)
        {
            fprintf (csv_file, ",%" PRIu32, frame_record->test_sequence_number);
        }
        else
        {
            fprintf (csv_file, ",");
        }
       fprintf (csv_file, "\n");
    }
    
    fclose (csv_file);
}


/**
 * @brief Find the test port index which matches a MAC address
 * @param[in] The MAC address to find the port index for.
 *            It is assumed this is from a test transmit frame, and so always a MAC address.
 * @return The index into test_ports[] for mac_addr
 */
static uint32_t find_port_index_from_mac_addr (const uint8_t *const mac_addr)
{
    uint32_t port_index = 0;
    bool found_port_index = false;
    
    while ((!found_port_index) && (port_index < NUM_TEST_PORTS))
    {
        if (memcmp (mac_addr, test_ports[port_index].mac_addr, ETHER_MAC_ADDRESS_LEN) == 0)
        {
            found_port_index = true;
        }
        else
        {
            port_index++;
        }
    }
    
    if (!found_port_index)
    {
        fprintf (stderr, "Failed to find port_index for MAC address\n");
        exit (EXIT_FAILURE);
    }
    
    return port_index;
}


/**
 * @brief Report to standard out the summary of the test
 * @details This reports the number of frames received for each combination of source and destination ports used by the test,
 *          along with an overall PASS/FAIL according to if all expected frames were received.
 *
 *          The summary is generated by searching the recorded frames for receive frames which match the transmitted frames.
 *          As a result all frames sent/received by the test must be recorded in memory.
 *
 *          This is simpler than checking for receipt during the test itself, but is not suitable for a long running test
 *          which would required regular progress to be reported.
 * @param[in] test_duration_src_dest_combinations The number of frames expected to be received for each combination of
 *                                                source and destination ports.
 */
static void summarise_frame_loopback (const const uint32_t test_duration_src_dest_combinations)
{
    /* Used to count when the expected loopback frames have been received, indexed by the source and destination port indices */
    uint32_t num_expected_received_frames[NUM_TEST_PORTS][NUM_TEST_PORTS] = {0};
    
    /* Iterate around all transmit frames, searching forwards for the expected receive frame */
    uint32_t tx_frame_index = 0;
    while (tx_frame_index < num_frame_records)
    {
        if (frame_records[tx_frame_index].frame_type == FRAME_RECORD_TX_TEST_FRAME)
        {
            const frame_record_t *const tx_frame = &frame_records[tx_frame_index];
            const uint32_t source_port_index = find_port_index_from_mac_addr (tx_frame->source_mac_addr);
            const uint32_t destination_port_index = find_port_index_from_mac_addr (tx_frame->destination_mac_addr);
            uint32_t rx_frame_index = tx_frame_index + 1;
            bool expected_frame_found = false;
            bool later_frame_found = false;
            
            while ((!expected_frame_found) && (!later_frame_found) && (rx_frame_index < num_frame_records))
            {
                const frame_record_t *const rx_frame = &frame_records[rx_frame_index];
                
                if ((rx_frame->frame_type == FRAME_RECORD_RX_TEST_FRAME) &&
                    (rx_frame->vlan_present) &&
                    (rx_frame->vlan_id == test_ports[destination_port_index].vlan) &&
                    (memcmp (rx_frame->source_mac_addr, tx_frame->source_mac_addr, ETHER_MAC_ADDRESS_LEN) == 0) &&
                    (memcmp (rx_frame->destination_mac_addr, tx_frame->destination_mac_addr, ETHER_MAC_ADDRESS_LEN) == 0))
                {
                    if (rx_frame->test_sequence_number == tx_frame->test_sequence_number)
                    {
                        expected_frame_found = true;
                        num_expected_received_frames[source_port_index][destination_port_index]++;
                    }
                    else if (rx_frame->test_sequence_number >= tx_frame->test_sequence_number)
                    {
                        /* If find a later test sequence number the expected frame was not seen.
                         * This test assumes the test doesn't run long enough for the test sequence number to wrap */
                        later_frame_found = true;
                    }
                }
                
                rx_frame_index++;
            }
        }
        
        tx_frame_index++;
    }
    
    /* Display tabulated results */
    bool test_fail = false;
    int source_port_index;
    int destination_port_index;
    const int field_width = 6;
    printf ("\nTest sent %" PRIu32 " frames for each combination of source and destination ports\n",
            test_duration_src_dest_combinations);
    printf ("Count of correctly received frames:\n");
    printf ("%*s  destination ports --->\n", field_width, "source");
    printf ("%*s", -field_width, "port");
    for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
    {
        printf ("  %*" PRIu32, field_width,destination_port_index);
    }
    printf ("\n");
    for (source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        printf ("%*" PRIu32, field_width, source_port_index);
        for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            if (destination_port_index != source_port_index)
            {
                const uint32_t frame_count = num_expected_received_frames[source_port_index][destination_port_index];
                printf ("  %*" PRIu32, field_width, frame_count);
                if (frame_count != test_duration_src_dest_combinations)
                {
                    test_fail = true;
                }
            }
            else
            {
                printf ("  %*s", field_width, "");
            }
        }
        printf ("\n");
    }
    printf ("\nTest: %s\n", test_fail ? "FAIL" : "PASS");
}


int main (int argc, char *argv[])
{
    /* Check that ethercat_frame_t has the expected size */
    if (sizeof (ethercat_frame_t) != 1514)
    {
        fprintf (stderr, "sizeof (ethercat_frame_t) unexpected value of %" PRIuPTR "\n", sizeof (ethercat_frame_t));
        exit (EXIT_FAILURE);
    }
    
    /* Allocate space to record test frames */
    frame_records = calloc (MAX_FRAME_RECORDS, sizeof (frame_records[0]));
    num_frame_records = 0;
    
    /* When an interface name is provided on the command line then use that, otherwise ask the user */
    const char *const interface_name = (argc > 1) ? argv[1] : select_interface ();
    
    pcap_t *const pcap_handle = open_interface (interface_name);

    ethercat_frame_t tx_frame;
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    
    const int64_t start_time = get_monotonic_time ();
    int64_t stop_time = 0;
    int64_t now;
    int rc;
    
    /* Set to transmit one frame a rate of every 10 ms */
    const int64_t send_interval = 10000000;
    int64_t next_frame_send_time = start_time;
    
    uint32_t destination_port_index = 0;
    uint32_t source_port_offset = 1;
    
    const uint32_t test_duration_src_dest_combinations = 100;
    uint32_t num_src_dest_combinations = 0;
    
    /* Run test for a fixed number of transmitted frames, sending frames at a fixed rate and recording which are received.
       This uses a busy-polling loop to determine when is time for the next transmit frame, or to poll for
       received frames. */
    bool test_complete = false;
    while (!test_complete)
    {
        now = get_monotonic_time ();
        
        if ((now >= next_frame_send_time) && (num_src_dest_combinations < test_duration_src_dest_combinations))
        {
            /* Send the next frame, cycling around combinations of the source and destination ports */
            const uint32_t source_port_index = (destination_port_index + source_port_offset) % NUM_TEST_PORTS;
            create_test_frame (&tx_frame, source_port_index, destination_port_index);
            rc = pcap_sendpacket (pcap_handle, (const u_char *) &tx_frame, sizeof (tx_frame));
            if (rc != 0)
            {
                fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(pcap_handle));
                exit (EXIT_FAILURE);
            }
            record_test_frame (NULL, &tx_frame, start_time);
            next_frame_send_time += send_interval;
            
            destination_port_index = (destination_port_index + 1) % NUM_TEST_PORTS;
            if (destination_port_index == 0)
            {
                source_port_offset++;
                if (source_port_offset == NUM_TEST_PORTS)
                {
                    source_port_offset = 1;
                    num_src_dest_combinations++;
                    if (num_src_dest_combinations == test_duration_src_dest_combinations)
                    {
                        /* After have transmitted all the sequence of test frame, wait for 100ms to check for receipt */
                        const int64_t wait_for_final_receipt_delay = 100000000;
                        stop_time = now + wait_for_final_receipt_delay;
                    }
                }
            }
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
                record_test_frame (pkt_header, (const ethercat_frame_t *) pkt_data, start_time);
            }
            
            if ((num_src_dest_combinations == test_duration_src_dest_combinations) &&
                (now >= stop_time))
            {
                test_complete = true;
            }
        }
    }
    now = get_monotonic_time ();
    
    struct pcap_stat statistics;
    rc = pcap_stats (pcap_handle, &statistics);
    if (rc == PCAP_ERROR)
    {
        fprintf(stderr,"\npcap_stats() failed: %s\n", pcap_geterr(pcap_handle));
        exit (EXIT_FAILURE);
    }

    pcap_close (pcap_handle);

    write_recorded_frames ();
    printf ("Elapsed time %.6f\n", (now - start_time) / 1E9);
    printf ("ps_recv=%u ps_drop=%u ps_ifdrop=%u\n", statistics.ps_recv, statistics.ps_drop, statistics.ps_ifdrop);
    printf ("num_tx_test_frames=%" PRIu64 " num_rx_test_frames=%" PRIu64 " num_other_rx_frames=%" PRIu64 "\n",
            frame_counts[FRAME_RECORD_TX_TEST_FRAME],
            frame_counts[FRAME_RECORD_RX_TEST_FRAME],
            frame_counts[FRAME_RECORD_RX_OTHER]);
    summarise_frame_loopback (test_duration_src_dest_combinations);
    
    return EXIT_SUCCESS;
}
