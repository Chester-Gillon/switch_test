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
#include <stdarg.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <pthread.h>
#include <semaphore.h>
#include <pcap.h>


#ifdef _WIN32
/* Under Windows use the pcap_sendqueue_transmit() function to send multiple frames in one go to increase the send rate. 
   The SEND_QUEUE_LEN_FRAMES value of 200 was derived experimentally as the highest value which allows the receive thread
   to keep up and not report a test FAIL due to missing frames. */
#define ENABLE_SEND_QUEUE
#define SEND_QUEUE_LEN_FRAMES 200
#endif


#define NSECS_PER_SEC 1000000000LL

/* Ethernet frame types */
#define ETH_P_8021Q    0x8100
#define ETH_P_ETHERCAT 0x88a4


#define ETHER_MAC_ADDRESS_LEN 6

/** Defines the unique identity used for one switch port under test.
 *  The MAC address is used by the switch under test to route traffic to the expected port.
 *  The VLAN is used by the injection switch.
 *
 *  The switch_port_number is that of the switch under test, controlled by the cabling and the VLAN assignment,
 *  i.e. for information and not set by the software.
 */
typedef struct
{
    uint32_t switch_port_number;
    uint8_t mac_addr[ETHER_MAC_ADDRESS_LEN];
    uint16_t vlan;
} port_id_t;


/** Define a locally administated MAC address and VLAN for each switch port under test */
#define NUM_TEST_PORTS 24
static port_id_t test_ports[NUM_TEST_PORTS] =
{
    { .switch_port_number =  1, .mac_addr = {2,0,1,0,0,1}, .vlan = 1001},
    { .switch_port_number =  2, .mac_addr = {2,0,1,0,0,2}, .vlan = 1002},
    { .switch_port_number =  3, .mac_addr = {2,0,1,0,0,3}, .vlan = 1003},
    { .switch_port_number =  4, .mac_addr = {2,0,1,0,0,4}, .vlan = 1004},
    { .switch_port_number =  5, .mac_addr = {2,0,1,0,0,5}, .vlan = 1005},
    { .switch_port_number =  6, .mac_addr = {2,0,1,0,0,6}, .vlan = 1006},
    { .switch_port_number =  7, .mac_addr = {2,0,1,0,0,7}, .vlan = 1007},
    { .switch_port_number =  8, .mac_addr = {2,0,1,0,0,8}, .vlan = 1008},
    { .switch_port_number =  9, .mac_addr = {2,0,1,0,0,9}, .vlan = 1009},
    { .switch_port_number = 10, .mac_addr = {2,0,1,0,1,0}, .vlan = 1010},
    { .switch_port_number = 11, .mac_addr = {2,0,1,0,1,1}, .vlan = 1011},
    { .switch_port_number = 12, .mac_addr = {2,0,1,0,1,2}, .vlan = 1012},
    { .switch_port_number = 13, .mac_addr = {2,0,1,0,1,3}, .vlan = 1013},
    { .switch_port_number = 14, .mac_addr = {2,0,1,0,1,4}, .vlan = 1014},
    { .switch_port_number = 15, .mac_addr = {2,0,1,0,1,5}, .vlan = 1015},
    { .switch_port_number = 16, .mac_addr = {2,0,1,0,1,6}, .vlan = 1016},
    { .switch_port_number = 17, .mac_addr = {2,0,1,0,1,7}, .vlan = 1017},
    { .switch_port_number = 18, .mac_addr = {2,0,1,0,1,8}, .vlan = 1018},
    { .switch_port_number = 19, .mac_addr = {2,0,1,0,1,9}, .vlan = 1019},
    { .switch_port_number = 20, .mac_addr = {2,0,1,0,2,0}, .vlan = 1020},
    { .switch_port_number = 21, .mac_addr = {2,0,1,0,2,1}, .vlan = 1021},
    { .switch_port_number = 22, .mac_addr = {2,0,1,0,2,2}, .vlan = 1022},
    { .switch_port_number = 23, .mac_addr = {2,0,1,0,2,3}, .vlan = 1023},
    { .switch_port_number = 24, .mac_addr = {2,0,1,0,2,4}, .vlan = 1024},
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
static sem_t frame_records_sem;


/* Next transmit sequence number inserted in the Address of the EtherCAT frame */
static uint32_t next_transmit_sequence_number;


/* File used to store a copy of the output written to the console */
static FILE *console_file;


/* The context used for the receive thread */
typedef struct
{
    /* Used to receive from PCAP */
    pcap_t *pcap_rx_handle;
    /* The monotonic start time for the test */
    int64_t start_time;
} receive_thread_context_t;


/*
 * @brief Write formatted output to the console and a log file
 * @param[in] format printf style format string
 * @param[in] ... printf arguments
 */
static void console_printf (const char *const format, ...) __attribute__((format(printf,1,2)));
static void console_printf (const char *const format, ...)
{
    va_list args;
    
    va_start (args, format);
    vfprintf (console_file, format, args);
    va_end (args);
    
    va_start (args, format);
    vprintf (format, args);
    va_end (args);
}


/**
 * @brief Display the available PCAP interfaces
 * @details The interface names can be passed on the command line to specify which interface on the PC to use to for the tests.
 *          The description of the interfaces are given, since under Windows the interfaces names are UUID strings.      
 */
static void display_available_interfaces (void)
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc;
    
    rc = pcap_findalldevs (&alldevs, errbuf);
    if (rc != 0)
    {
        fprintf (stderr,"Error in pcap_findalldevs(): %s\n", errbuf);
        exit (EXIT_FAILURE);
    }

    printf ("Available network interfaces: name (description)\n");
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        printf ("%s", dev->name);
        if (dev->description != NULL)
        {
            printf (" (%s)\n", dev->description);
        }
        else
        {
            printf (" (No description available)\n");
        }
    }

    pcap_freealldevs (alldevs);
}


/**
 * @brief Get the description for an interface name.
 * @param[in] interface_name The PCAP interface name to get the description for
 * @return Returns the description for the interface name, or NULL if the interface name isn't found
 */
static const char *get_interface_description (const char *const interface_name)
{
    const char *interface_description = NULL;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc;
    
    rc = pcap_findalldevs (&alldevs, errbuf);
    if (rc != 0)
    {
        fprintf (stderr,"Error in pcap_findalldevs(): %s\n", errbuf);
        exit (EXIT_FAILURE);
    }
    
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        if (strcmp (dev->name, interface_name) == 0)
        {
            if (dev->description != NULL)
            {
                interface_description = strdup (dev->description);
            }
            else
            {
                interface_description = "No description available";
            }
        }
    }

    pcap_freealldevs (alldevs);
    
    return interface_description;
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
        console_printf ("Error in pcap_create(): %s\n", errbuf);
        exit (EXIT_FAILURE);
    }
    
    /* Need to enable promiscuous mode to receive the test packets from the switch */
    const int promisc_enable = 1;
    rc = pcap_set_promisc (pcap_handle, promisc_enable);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_promisc(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Capture the entire length of the test packets */
    const int max_snaplen = 65536;
    rc = pcap_set_snaplen (pcap_handle, max_snaplen);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_snaplen(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
   
#ifdef ENABLE_RECEIVE_BUFFERING
    /* Enable buffering of packets to try and minimise overheads of receive thread */
    const int disable_immediate_mode = 0;
    rc = pcap_set_immediate_mode (pcap_handle, disable_immediate_mode);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_immediate_mode(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Enable a timeout so that the receive thread returns from the pcap_next_ex() call at regular intervals to be able
     * to detect the end of the test. */
    const int timeout_ms = 20;
    rc = pcap_set_timeout (pcap_handle, timeout_ms);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_timeout(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
#else
    /* Enable immediate receive mode as use polling to alternate between sending at a specified rate and
     * checking for the receipt of the test packets. */
    const int immediate_mode = 1;
    rc = pcap_set_immediate_mode (pcap_handle, immediate_mode);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_immediate_mode(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    /* Disable the timeout to allow pcap_next_ex() to poll for packets.
       From the documentation this might not be supported on all systems, but has worked on Windows 10 and a Linux 3.10 Kernel. */
    const int no_timeout = -1;
    rc = pcap_set_timeout (pcap_handle, no_timeout);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_timeout(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
#endif
    
    /* Activate the interface for use */
    rc = pcap_activate (pcap_handle);
    if (rc < 0)
    {
        console_printf ("Error in pcap_activate(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    else if (rc > 0)
    {
        console_printf ("Warning in pcap_activate(): %s\n", pcap_statustostr (rc));
    }
    
    /* Capture only the receive frames, and not our transmit frames */
    
    /* This has been commented out since with a Intel Corporation 82579V Gigabit Network Connection:
       a. Under Windows 10 failed with PCAP_ERROR.
       b. Under CentOS 6.10 with a 3.10.33-rt32.33.el6rt.x86_64 Kernel with libpcap 1.4.0:
          - When pcap_next_ex() is called from the same thread as that which calls pcap_sendpacket() then didn't capture
            a copy of the transmit frames regardless of if pcap_setdirection() was called.
          - When pcap_next_ex() is called from a different as that which calls pcap_sendpacket() then captured
            a copy of the transmit frames regardless of if pcap_setdirection() was called.
    rc = pcap_setdirection (pcap_handle, PCAP_D_IN);
    if (rc != 0)
    {
        console_printf ("Error in pcap_setdirection(): %s\n", pcap_statustostr (rc));
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
        console_printf ("Error in pcap_compile(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    
    rc = pcap_setfilter (pcap_handle, &filter_program);
    if (rc != 0)
    {
        console_printf ("Error in pcap_setfilter(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }
    */
    
    /* Check the interface is Ethernet */
    const int link_layer = pcap_datalink (pcap_handle);
    if (link_layer != DLT_EN10MB)
    {
        console_printf ("This program only operates on an Ethernet link layer pcap_datalink(%s); returned %d\n",
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
        console_printf ("clock_getime(CLOCK_MONOTONIC) failed\n");
        exit (EXIT_FAILURE);
    }
    
    return (now.tv_sec * NSECS_PER_SEC) + now.tv_nsec;
}


/*
 * @brief Record information about an Ethernet frame transmitted or received during a test
 * @details This uses a sempahore to protect the global frame_records[] against access by the main transmit thread and
 *          receive thread. To ensure receive frames are only stored after the transmit frame, 
 *          required by summarise_frame_loopback() to report a pass, means this function must be called by the trasnmit thread
 *          prior to actually transmitting the packet.
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
    int rc;
    
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
    
    rc = sem_wait (&frame_records_sem);
    if (rc != 0)
    {
        console_printf ("sem_wait() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
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
    
    rc = sem_post (&frame_records_sem);
    if (rc != 0)
    {
        console_printf ("sem_wait() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }
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
 * @param[in] csv_filename Name of the CSV file to create.
 */
static void write_recorded_frames (const char *const csv_filename)
{
    const char *const frame_type_names[FRAME_RECORD_ARRAY_SIZE] =
    {
        [FRAME_RECORD_TX_TEST_FRAME] = "Tx test",
        [FRAME_RECORD_RX_TEST_FRAME] = "Rx test",
        [FRAME_RECORD_RX_OTHER     ] = "Rx other"
    };
    
    /* Create CSV file and write headers */
    console_printf ("Saving frame results to %s\n", csv_filename);
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
        console_printf ("Failed to find port_index for MAC address\n");
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
    console_printf ("\nTest sent %" PRIu32 " frames for each combination of source and destination ports\n",
            test_duration_src_dest_combinations);
    console_printf ("Count of correctly received frames:\n");
    console_printf ("%*s  destination ports --->\n", field_width, "source");
    console_printf ("%*s", -field_width, "port");
    for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
    {
        console_printf ("  %*" PRIu32, field_width, test_ports[destination_port_index].switch_port_number);
    }
    console_printf ("\n");
    for (source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        console_printf ("%*" PRIu32, field_width, test_ports[source_port_index].switch_port_number);
        for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            if (destination_port_index != source_port_index)
            {
                const uint32_t frame_count = num_expected_received_frames[source_port_index][destination_port_index];
                console_printf ("  %*" PRIu32, field_width, frame_count);
                if (frame_count != test_duration_src_dest_combinations)
                {
                    test_fail = true;
                }
            }
            else
            {
                console_printf ("  %*s", field_width, "");
            }
        }
        console_printf ("\n");
    }
    console_printf ("\nTest: %s\n", test_fail ? "FAIL" : "PASS");
}


/**
 * @brief The receive thread which just polls for frames, and stores information about them
 * @param[in] arg The receive thread context
 * @return Not used.
 */
static void *receive_thread (void *arg)
{
    receive_thread_context_t *const context = arg;
    bool exit_requested = false;
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    int rc;
    
    while (!exit_requested)
    {
        /* Poll for receipt of packet */
        rc = pcap_next_ex (context->pcap_rx_handle, &pkt_header, &pkt_data);
        if (rc == PCAP_ERROR)
        {
            console_printf ("\nError receiving packet: %s\n", pcap_geterr(context->pcap_rx_handle));
            exit (EXIT_FAILURE);
        }
        else if (rc == PCAP_ERROR_BREAK)
        {
            exit_requested = true;
        }
        else if (rc == 1)
        {
            /* Process received packet */
            record_test_frame (pkt_header, (const ethercat_frame_t *) pkt_data, context->start_time);
        }
    }
    return NULL;
}


int main (int argc, char *argv[])
{
    /* Check that ethercat_frame_t has the expected size */
    if (sizeof (ethercat_frame_t) != 1514)
    {
        fprintf (stderr, "sizeof (ethercat_frame_t) unexpected value of %" PRIuPTR "\n", sizeof (ethercat_frame_t));
        exit (EXIT_FAILURE);
    }
    
    /* Process command line arguments */
    if (argc < 3)
    {
        printf ("Usage: %s <interface_name> <frame_rate_hz>\n\n", argv[0]);
        display_available_interfaces ();
        exit (EXIT_FAILURE);
    }
    
    const char *const interface_name = argv[1];
    const int frame_rate_hz = atoi (argv[2]);
    const char *const interface_description = get_interface_description (interface_name);
    
    if (interface_description == NULL)
    {
        fprintf (stderr, "Interface name %s not found\n", interface_name);
        exit (EXIT_FAILURE);
    }
    
    /* Allocate space to record test frames */
    frame_records = calloc (MAX_FRAME_RECORDS, sizeof (frame_records[0]));
    num_frame_records = 0;

    /* Set filenames which contain the output files containing the date/time, OS used and frame rate */
    const time_t tod_now = time (NULL);
    struct tm broken_down_time;
#ifdef _WIN32
    #define OS_NAME "windows"
#else
    #define OS_NAME "linux"
#endif
    char date_time_str[80];
    char csv_filename[80];
    char console_filename[80];
    
    localtime_r (&tod_now, &broken_down_time);
    strftime (date_time_str, sizeof (date_time_str), "%Y%m%dT%H%M%S", &broken_down_time);
    snprintf (csv_filename, sizeof (csv_filename), "%s_frames_%s_%dhz.csv", date_time_str, OS_NAME, frame_rate_hz);
    snprintf (console_filename, sizeof (console_filename), "%s_console_%s_%dhz.txt", date_time_str, OS_NAME, frame_rate_hz);
    
    console_file = fopen (console_filename, "wt");
    if (console_file == NULL)
    {
        fprintf (stderr, "Failed to create %s\n", console_filename);
        exit (EXIT_FAILURE);
    }
    
    /* Report the command line arguments used */
    console_printf ("Using interface %s (%s)\n", interface_name, interface_description);
    console_printf ("requested frame rate = %d Hz\n", frame_rate_hz);
    
#ifdef ENABLE_SEND_QUEUE
    struct pcap_pkthdr send_pkt_header = {0};
    uint32_t num_frames_queued = 0;
    pcap_send_queue *const send_queue =
            pcap_sendqueue_alloc (SEND_QUEUE_LEN_FRAMES * (sizeof (struct pcap_pkthdr) + sizeof(ethercat_frame_t)));
    if (send_queue == NULL)
    {
        console_printf ("pcap_sendqueue_alloc() failed\n");
        exit (EXIT_FAILURE);
    }
#endif
    
    pcap_t *const pcap_tx_handle = open_interface (interface_name);
    pcap_t *const pcap_rx_handle = open_interface (interface_name);

    ethercat_frame_t tx_frame;
    
    /* Start the receive thread */
    int rc;
    pthread_t rx_thread_handle;
    receive_thread_context_t rx_thread_context =
    {
        .pcap_rx_handle = pcap_rx_handle
    };
    rc = sem_init (&frame_records_sem, 0, 1);
    if (rc != 0)
    {
        console_printf ("sem_init() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }
    rc = pthread_create (&rx_thread_handle, NULL, receive_thread, &rx_thread_context);
    if (rc != 0)
    {
        console_printf ("pthread_create() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }
    
    const int64_t start_time = get_monotonic_time ();
    int64_t stop_time = 0;
    int64_t now;
    
    /* Set to transmit one frame a rate given by the command line argument */
    const int64_t send_interval = (int64_t) (1E9 / (double) frame_rate_hz);
    int64_t next_frame_send_time = start_time;
    rx_thread_context.start_time = start_time;
    
    uint32_t destination_port_index = 0;
    uint32_t source_port_offset = 1;
    
    const uint32_t test_duration_src_dest_combinations = 100;
    uint32_t num_src_dest_combinations = 0;
    
    uint32_t num_tx_frames = 0;
    double actual_frame_rate = 0.0;
    
    /* Run test for a fixed number of transmitted frames, sending frames at a fixed rate and recording which are received.
       This uses a busy-polling loop to determine when is time for the next transmit frame. */
    bool test_complete = false;
    while (!test_complete)
    {
        now = get_monotonic_time ();

        if ((now >= next_frame_send_time) && (num_src_dest_combinations < test_duration_src_dest_combinations))
        {
            /* Send the next frame, cycling around combinations of the source and destination ports */
            const uint32_t source_port_index = (destination_port_index + source_port_offset) % NUM_TEST_PORTS;
            create_test_frame (&tx_frame, source_port_index, destination_port_index);
            record_test_frame (NULL, &tx_frame, start_time);
#ifdef ENABLE_SEND_QUEUE
            send_pkt_header.caplen = sizeof (tx_frame);
            rc = pcap_sendqueue_queue (send_queue, &send_pkt_header, (const u_char *) &tx_frame);
            if (rc != 0)
            {
                console_printf ("pcap_sendqueue_queue() failed\n");
                exit (EXIT_FAILURE);
            }
            num_frames_queued++;
            if (num_frames_queued == SEND_QUEUE_LEN_FRAMES)
            {
                u_int bytes_sent = pcap_sendqueue_transmit (pcap_tx_handle, send_queue, 0);
                if (bytes_sent != send_queue->len)
                {
                console_printf ("pcacp_sendqueue_transmit() sent %u out of %u bytes\n",
                        bytes_sent, send_queue->len);
                exit (EXIT_FAILURE);
                }
                send_queue->len = 0;
                num_frames_queued = 0;
            }
#else
            /* Send a single frame */
            rc = pcap_sendpacket (pcap_tx_handle, (const u_char *) &tx_frame, sizeof (tx_frame));
            if (rc != 0)
            {
                console_printf ("\nError sending the packet: %s\n", pcap_geterr(pcap_tx_handle));
                exit (EXIT_FAILURE);
            }
#endif
            next_frame_send_time += send_interval;
            num_tx_frames++;
            
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
                        /* After have transmitted all the sequence of test frame, wait for 100ms to check for receipt.
                           This should more than the timeout used for pcap_next_ex() to allow the receive thread to see the final
                           test frames. */
                        const int64_t wait_for_final_receipt_delay = 100000000;
                        stop_time = now + wait_for_final_receipt_delay;
                        actual_frame_rate = (double) num_tx_frames / ((double) (now - start_time) / 1E9);
                    }
                }
            }
        }
            
        if ((num_src_dest_combinations == test_duration_src_dest_combinations) &&
                (now >= stop_time))
        {
            test_complete = true;
        }
    }
    now = get_monotonic_time ();
    
    /* Request the receive thread exit, and wait until has exited */
    pcap_breakloop (pcap_rx_handle);
    
    rc = pthread_join (rx_thread_handle, NULL);
    if (rc != 0)
    {
        console_printf ("pthread_join() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }
    
    struct pcap_stat statistics;
    rc = pcap_stats (pcap_rx_handle, &statistics);
    if (rc == PCAP_ERROR)
    {
        console_printf ("\npcap_stats() failed: %s\n", pcap_geterr(pcap_rx_handle));
        exit (EXIT_FAILURE);
    }

    pcap_close (pcap_tx_handle);
    pcap_close (pcap_rx_handle);
#ifdef ENABLE_SEND_QUEUE
    pcap_sendqueue_destroy (send_queue);
#endif

    write_recorded_frames (csv_filename);
    console_printf ("Elapsed time %.6f\n", (now - start_time) / 1E9);
    console_printf ("Actual frame rate = %.1f Hz\n", actual_frame_rate);
    console_printf ("ps_recv=%u ps_drop=%u ps_ifdrop=%u\n", statistics.ps_recv, statistics.ps_drop, statistics.ps_ifdrop);
    console_printf ("num_tx_test_frames=%" PRIu64 " num_rx_test_frames=%" PRIu64 " num_other_rx_frames=%" PRIu64 "\n",
            frame_counts[FRAME_RECORD_TX_TEST_FRAME],
            frame_counts[FRAME_RECORD_RX_TEST_FRAME],
            frame_counts[FRAME_RECORD_RX_OTHER]);
    summarise_frame_loopback (test_duration_src_dest_combinations);
    
    fclose (console_file);
    
    return EXIT_SUCCESS;
}
