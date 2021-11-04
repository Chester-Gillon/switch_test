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
#include <limits.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>


/* Define a string to report the Operating System just to report in result filenames,
 * when comparing results from multiple runs in the same directory in a PC which can be dual-booted. */
#ifdef _WIN32
#define OS_NAME "windows"
#else
#define OS_NAME "linux"
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


/** Define a locally administated MAC address and VLAN for each switch port under test.
    The last octet of the MAC address is the index into the array, which is used an optimisation when looking
    up the port number of a received frame (to avoid having to search the table). */
#define NUM_TEST_PORTS 24
static port_id_t test_ports[NUM_TEST_PORTS] =
{
    { .switch_port_number =  1, .mac_addr = {2,0,1,0,0, 0}, .vlan = 1001},
    { .switch_port_number =  2, .mac_addr = {2,0,1,0,0, 1}, .vlan = 1002},
    { .switch_port_number =  3, .mac_addr = {2,0,1,0,0, 2}, .vlan = 1003},
    { .switch_port_number =  4, .mac_addr = {2,0,1,0,0, 3}, .vlan = 1004},
    { .switch_port_number =  5, .mac_addr = {2,0,1,0,0, 4}, .vlan = 1005},
    { .switch_port_number =  6, .mac_addr = {2,0,1,0,0, 5}, .vlan = 1006},
    { .switch_port_number =  7, .mac_addr = {2,0,1,0,0, 6}, .vlan = 1007},
    { .switch_port_number =  8, .mac_addr = {2,0,1,0,0, 7}, .vlan = 1008},
    { .switch_port_number =  9, .mac_addr = {2,0,1,0,0, 8}, .vlan = 1009},
    { .switch_port_number = 10, .mac_addr = {2,0,1,0,0, 9}, .vlan = 1010},
    { .switch_port_number = 11, .mac_addr = {2,0,1,0,0,10}, .vlan = 1011},
    { .switch_port_number = 12, .mac_addr = {2,0,1,0,0,11}, .vlan = 1012},
    { .switch_port_number = 13, .mac_addr = {2,0,1,0,0,12}, .vlan = 1013},
    { .switch_port_number = 14, .mac_addr = {2,0,1,0,0,13}, .vlan = 1014},
    { .switch_port_number = 15, .mac_addr = {2,0,1,0,0,14}, .vlan = 1015},
    { .switch_port_number = 16, .mac_addr = {2,0,1,0,0,15}, .vlan = 1016},
    { .switch_port_number = 17, .mac_addr = {2,0,1,0,0,16}, .vlan = 1017},
    { .switch_port_number = 18, .mac_addr = {2,0,1,0,0,17}, .vlan = 1018},
    { .switch_port_number = 19, .mac_addr = {2,0,1,0,0,18}, .vlan = 1019},
    { .switch_port_number = 20, .mac_addr = {2,0,1,0,0,19}, .vlan = 1020},
    { .switch_port_number = 21, .mac_addr = {2,0,1,0,0,20}, .vlan = 1021},
    { .switch_port_number = 22, .mac_addr = {2,0,1,0,0,21}, .vlan = 1022},
    { .switch_port_number = 23, .mac_addr = {2,0,1,0,0,22}, .vlan = 1023},
    { .switch_port_number = 24, .mac_addr = {2,0,1,0,0,23}, .vlan = 1024},
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
    /* A copy of a transmitted frame which has been received by PCAP.
     * There can be OS specific differences:
     * a. Under Linux using the same pcap_t handle for transmit and receive means receive doesn't get a copy
     *    of the transmitted frames.
     * b. Whereas under Windows the receive does get a copy of the transmitted frames. */
    FRAME_RECORD_TX_COPY_FRAME,
    /* An EtherCAT test frame in the format which is transmitted, and which was received by the test on the
     * VLAN for the expected destination port. This frame contains an expected pending sequence number. */
    FRAME_RECORD_RX_TEST_FRAME,
    /* As per FRAME_RECORD_RX_TEST_FRAME except the received sequence number was not expected.
     * This may happen if frames get delayed such that there is no recording of the pending sequence number. */
    FRAME_RECORD_RX_UNEXPECTED_FRAME,
    /* An EtherCAT test frame in the format which is transmitted, and which was received by the test on a
     * VLAN other than that expected for the destination port.
     * This means the frame was flooded because the switch under test didn't know which port the destination MAC address
     * was for. */
    FRAME_RECORD_RX_FLOODED_FRAME,
    /* A frame received by the test, which isn't one transmitted.
       I.e. any frames which are not generated by the test program. */
    FRAME_RECORD_RX_OTHER,
    
    FRAME_RECORD_ARRAY_SIZE
} frame_record_type_t;


/* Look up table which gives the description of each frame_record_type_t */
static const char *const frame_record_types[FRAME_RECORD_ARRAY_SIZE] =
{
    [FRAME_RECORD_TX_TEST_FRAME      ] = "Tx Test",
    [FRAME_RECORD_TX_COPY_FRAME      ] = "Tx Copy",
    [FRAME_RECORD_RX_TEST_FRAME      ] = "Rx Test",
    [FRAME_RECORD_RX_UNEXPECTED_FRAME] = "Rx Unexpected",
    [FRAME_RECORD_RX_FLOODED_FRAME   ] = "Rx Flooded",
    [FRAME_RECORD_RX_OTHER           ] = "Rx Other"
};


/* Used to record one frame transmitted or received during the test, for debugging purposes */
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
    /* When frame_type is other than FRAME_RECORD_RX_OTHER the sequence number of the frame.
     * Allows received frames to be matched against the transmitted frame. */
    uint32_t test_sequence_number;
    /* When frame_type is other than FRAME_RECORD_RX_OTHER the source and destination port numbers of the frame,
     * based upon matching the source_mac_addr and destination_mac_addr */
    uint32_t source_port_index;
    uint32_t destination_port_index;
    /* Set true for a FRAME_RECORD_TX_TEST_FRAME for which there is no matching FRAME_RECORD_RX_TEST_FRAME */
    bool frame_missed;
} frame_record_t;


/* File used to store a copy of the output written to the console */
static FILE *console_file;


/* Command line argument which specifies the name of the PCAP interface name used to send/receive test frames */
static char arg_pcap_interface_name[PATH_MAX];

/* Command line argument which specifies the test interval in seconds, which is the interval over which statistics are
 * accumulated and then reported. */
static int64_t arg_test_interval_secs = 10;


/* Command line argument which controls how the test runs:
 * - When false the test runs until requested to stop, and only reports summary information for each test interval.
 * - When true the test runs for a single test interval, recording the transmitted/received frames in memory which are written 
 *   to s CSV file at the end of the test interval. */
static bool arg_frame_debug_enabled = false;


/* Used to store pending receive frames for one source / destination port combination.
 * As frames are transmitted they are stored in, and then removed once received.
 *
 * MAX_PENDING_RX_FRAMES is set to a small value as there is one copy of this store for each source / destination port
 * combination and frames are not expected to queue in the network hardware.
 *
 * Missing frames get detected either:
 * a. If a single frame is missing, the missing frame is detected when the next expected frame has a later sequence number.
 * b. If multiple frames are missing, a missing frame is detected when the next transmit occurs and the 
 *    pending_rx_sequence_numbers[] array is full. */
#define MAX_PENDING_RX_FRAMES 3
typedef struct
{
    /* The number of frames which have been transmitted and are pending for receipt */
    uint32_t num_pending_rx_frames;
    /* Index in pending_rx_sequence_numbers[] where a frame is stored after has been transmitted */
    uint32_t tx_index;
    /* Index in pending_rx_sequence_numbers[] which contains the next expected receive frame */
    uint32_t rx_index;
    /* Circular buffer used to record pending sequence numbers for receive frames */
    uint32_t pending_rx_sequence_numbers[MAX_PENDING_RX_FRAMES];
    /* When frame debug is enabled points at the frame record for the FRAME_RECORD_TX_TEST_FRAME for each pending receive frame,
     * so that if a frame is not received the transmit frame record can be marked as such.
     *
     * Done this way round to avoid marking any transmits frames at the end of a test sequence are not marked as missing. */
    frame_record_t *tx_frame_records[MAX_PENDING_RX_FRAMES];
} pending_rx_frames_t;


/* Contains the statistics for test frames for one combination of source / destination ports for one test interval */
typedef struct
{
    /* The number of expected receive frames during the test interval */
    uint32_t num_valid_rx_frames;
    /* The number of missing receive frames during the test interval */
    uint32_t num_missing_rx_frames;
    /* The number of frames transmitted during the test interval */
    uint32_t num_tx_frames;
} port_frame_statistics_t;


/* Contains the statistics for test frames transmitted and received over one test interval in which the statistics
 * are accumulated. The transmit and receive counts may not match, if there are frames which are pending being received
 * at the end of the interval. */
typedef struct
{
    /* The monotonic start and end time of the test interval, to give the duration over which the statistics were accumulated */
    int64_t interval_start_time;
    int64_t interval_end_time;
    /* The counts of different types of frames during the test interval, across all ports tested */
    uint32_t frame_counts[FRAME_RECORD_ARRAY_SIZE];
    /* Receive frame counts, indexed by each [source_port][destination_port] combination */
    port_frame_statistics_t port_frame_statistics[NUM_TEST_PORTS][NUM_TEST_PORTS];
    /* Counts the total number of missing frames during the test interval */
    uint32_t total_missing_frames;
    /* The PCAP statistics, which are only sampled at the end of a test iteration if total_missing_frames is non-zero.
     * They are used to report diagnostic information about if missed frames could be due to dropped packets in the software,
     * rather than the switch under test. */
    struct pcap_stat pcap_statistics;
    /* Set true in the final statistics before the transmit/receive thread exits */
    bool final_statistics;
} frame_test_statistics_t;


/* Used to record frames transmitted or received for debug purposes */
typedef struct
{
    /* The allocated length of the frame_records[] array. When zero frames are not recorded */
    uint32_t allocated_length;
    /* The number of entries in the frame_records[] array which are currently populated */
    uint32_t num_frame_records;
    /* Array used to record frames */
    frame_record_t *frame_records;
} frame_records_t;


/* The context used for the thread which sends/receive the test frames */
typedef struct
{
    /* Used to send/receive frames using PCAP */
    pcap_t *pcap_handle;
    /* The next sexquence number to be transmitted */
    uint32_t next_tx_sequence_number;
    /* The next destination ports index to use for a transmitted frame */
    uint32_t destination_port_index;
    /* The next modulo offset from destination_port_index to use as the source port index for a transmitted frame */
    uint32_t source_port_offset;
    /* Contains the pending receive frames, indexed by [source_port][destination_port] */
    pending_rx_frames_t pending_rx_frames[NUM_TEST_PORTS][NUM_TEST_PORTS];
    /* Used to accumulate the statistics for the current test interval */
    frame_test_statistics_t statistics;
    /* Monotonic time at which the current test interval ends, which is when the statistics are published and then reset */
    int64_t test_interval_end_time;
    /* Optionally used to record frames for debug */
    frame_records_t frame_recording;
    /* Used to populate the next frame to be transmitted */
    ethercat_frame_t tx_frame;
} frame_tx_rx_thread_context_t;


/* Contains the information for the results summary over multiple test intervals */
typedef struct
{
    /* Filename used for the per-port counts */
    char per_port_counts_csv_filename[PATH_MAX];
    /* File to which the per-port counts are written */
    FILE *per_port_counts_csv_file;
    /* The number of test intervals which have had failures, due to missed frames */
    uint32_t num_test_intervals_with_failures;
    /* The string containing the time of the last test interval which had a failure */
    char time_of_last_failure[80];
} results_summary_t;


/* test_statistics contains the statistics from the most recent completed test interval.
 * It is written by the transmit_receive_thread, and read by the main thread to report the test progress.
 *
 * The semphores control the access by:
 * a. The free semaphore is initialised to 1, and the populated semaphore to 0.
 * b. The main thread blocks in sem_wait (test_statistics_populated) waiting for results.
 * c. At the end of a test interval the transmit_receive_thread:
 *    - sem_wait (test_statistics_free) which should not block unless the main thread isn't keeping up with reporting
 *      the test progress.
 *    - Stores the results for the completed test interval in test_statistics
 *    - sem_post (test_statistics_populated) to wake up the main thread.
 * d. When the main thread is woken up from sem_wait(test_statistics_populated):
 *    - Reports the contents of test_statistics
 *    - sem_post (test_statistics_free) to indicate has processed test_statistics
 * e. The sequence starts again from b.
 */
static frame_test_statistics_t test_statistics;
static sem_t test_statistics_free;
static sem_t test_statistics_populated;


/* Set true in a signal handler when Ctrl-C is used to request a running test stops */
static volatile bool test_stop_requested;


/**
 * @brief Signal handler to request a running test stops
 * @param[in] sig Not used
 */
static void stop_test_handler (const int sig)
{
    test_stop_requested = true;
}


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

    printf ("     Available network interfaces: name (description)\n");
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        printf ("       %s", dev->name);
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
 * @brief Display the program usage and then exit
 * @param[in] program_name Name of the program from argv[0]
 */
static void display_usage (const char *const program_name)
{
    printf ("Usage %s: -i <pcap_interface_name> [-t <duration_secs>] [-d]\n", program_name);
    printf ("\n");
    printf ("  -i specifies the name of the PCAP interface to send/receive frames on\n");
    display_available_interfaces ();
    printf ("\n");
    printf ("  -d enables debug mode, where runs just for a single test interval and creates\n");
    printf ("     a CSV file containing the frames sent/received.\n");
    printf ("\n");
    printf ("  -t defines the duration of a test interval in seconds, over which the number\n");
    printf ("     errors is accumulated and reported.\n");
    
    exit (EXIT_FAILURE);
}


/**
 * @brief Read the command line arguments, exiting if an error in the arguments
 * @param[in] argc, argv Command line arguments passed to main
 */
static void read_command_line_arguments (const int argc, char *argv[])
{
    const char *const program_name = argv[0];
    const char *const optstring = "i:dt:";
    bool pcap_interface_specified = false;
    int option;
    char junk;
    
    option = getopt (argc, argv, optstring);
    while (option != -1)
    {
        switch (option)
        {
        case 'i':
            snprintf (arg_pcap_interface_name, sizeof (arg_pcap_interface_name), "%s", optarg);
            pcap_interface_specified = true;
            break;
            
        case 'd':
            arg_frame_debug_enabled = true;
            break;
            
        case 't':
            if ((sscanf (optarg, "%" SCNi64 "%c", &arg_test_interval_secs, &junk) != 1) ||
                (arg_test_interval_secs <= 0))
            {
                printf ("Error: Invalid <duration_secs> %s\n", optarg);
            }
            break;
            
        case '?':
        default:
            display_usage (program_name);
            break;
        }
    
        option = getopt (argc, argv, optstring);
    }
    
    if (!pcap_interface_specified)
    {
        printf ("Error: The PCAP interface must be specified\n\n");
        display_usage (program_name);
    }
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
    
    /* Capture the minimum length of the test packets, of which the last field checked is Address which contains the 
     * sequence number. Uses the offset for the first non-bit field after Address.
     *
     * While the transmitted frames contain a test pattern in the data[] this program doesn't verify the test pattern,
     * on the assumption that any corruption at the link-level will invalidate the CRC and the switches and/or network
     * adapter will drop the frames with an invalid CRC which the test will then reported as "missed". */
    const int max_snaplen = offsetof (ethercat_frame_t, IRQ);
    rc = pcap_set_snaplen (pcap_handle, max_snaplen);
    if (rc != 0)
    {
        console_printf ("Error in pcap_set_snaplen(): %s\n", pcap_statustostr (rc));
        exit (EXIT_FAILURE);
    }

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
 * @param sequence_number[in] The sequence number to place in the transmitted frame
 */
static void create_test_frame (ethercat_frame_t *const frame, 
                               const uint32_t source_port_index, const uint32_t destination_port_index,
                               const uint32_t sequence_number)
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
    
    frame->Address = sequence_number;
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


/*
 * @brief Reset the statistics which are accumulated over one test interval
 * @param[in/out] statistics The statistics to reset
 */
static void reset_frame_test_statistics (frame_test_statistics_t *const statistics)
{
    for (frame_record_type_t frame_type = 0; frame_type < FRAME_RECORD_ARRAY_SIZE; frame_type++)
    {
        statistics->frame_counts[frame_type] = 0;
    }
    statistics->total_missing_frames = 0;
    for (uint32_t source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        for (uint32_t destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            port_frame_statistics_t *const port_stats =
                    &statistics->port_frame_statistics[source_port_index][destination_port_index];
            
            port_stats->num_valid_rx_frames = 0;
            port_stats->num_missing_rx_frames = 0;
            port_stats->num_tx_frames = 0;
        }
    }
}


/**
 * @brief Initialise the context for the transmit/receive thread, for the start of the test
 * @param[out] context The initialised context
 */
static void transmit_receive_initialise (frame_tx_rx_thread_context_t *const context)
{
    context->pcap_handle = open_interface (arg_pcap_interface_name);
    context->next_tx_sequence_number = 1;
    context->destination_port_index = 0;
    context->source_port_offset = 1;
    for (uint32_t source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        for (uint32_t destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            pending_rx_frames_t *const pending = &context->pending_rx_frames[source_port_index][destination_port_index];
            
            pending->num_pending_rx_frames = 0;
            pending->tx_index = 0;
            pending->rx_index = 0;
        }
    }
    reset_frame_test_statistics (&context->statistics);
    context->statistics.final_statistics = false;
    
    if (arg_frame_debug_enabled)
    {
        /* Allocate space to record all expected frames within one test duration */
        const size_t nominal_records_per_test = 3; /* tx frame, copy of tx frame, rx frame */
        const size_t max_frame_rate = 82000; /* Slightly more than max non-jumbo frames can be sent on a 1 Gb link */
        context->frame_recording.allocated_length = max_frame_rate * nominal_records_per_test * (uint32_t) arg_test_interval_secs;
        context->frame_recording.frame_records = calloc 
                (context->frame_recording.allocated_length, sizeof (context->frame_recording.frame_records[0]));
    }
    else
    {
        context->frame_recording.allocated_length = 0;
        context->frame_recording.frame_records = NULL;
    }
    context->frame_recording.num_frame_records = 0;
    
    const int64_t now = get_monotonic_time ();
    context->statistics.interval_start_time = now;
    context->test_interval_end_time = now + (arg_test_interval_secs * NSECS_PER_SEC);
}


/*
 * @brief Get the port index from a MAC address
 * @details This assumes that the last octet of the test frame MAC addresses is the index into the test_ports[] array.
 * @param[in] mac_addr The MAC address in a frame to get the port index for
 * @param[out] port_index The index obtained from the MAC address
 * @return Returns true if the MAC address is one used for the test and the port_index has been obtained, or false otherwise.
 */
static bool get_port_index_from_mac_addr (const uint8_t *const mac_addr, uint32_t *const port_index)
{
    bool port_index_valid;
    
    *port_index = mac_addr[5];
    port_index_valid = (*port_index < NUM_TEST_PORTS);
    
    if (port_index_valid)
    {
        port_index_valid = memcmp (mac_addr, test_ports[*port_index].mac_addr, ETHER_MAC_ADDRESS_LEN) == 0;
    }
    
    return port_index_valid;
}


/*
 * @brief When enabled by a command line option, record a transmit/receive frame for debug
 * @param[in/out] context Context to record the frame in
 * @param[in] frame_record The frame to record.
 * @return Returns a pointer to the recorded frame entry, or NULL if not recorded.
 *         Allows the caller to refer to the recorded frame for later updating the frame_missed field.
 */
static frame_record_t *record_frame_for_debug (frame_tx_rx_thread_context_t *const context,
                                               const frame_record_t *const frame_record)
{
    frame_record_t *recorded_frame = NULL;
    
    if (context->frame_recording.num_frame_records < context->frame_recording.allocated_length)
    {
        recorded_frame = &context->frame_recording.frame_records[context->frame_recording.num_frame_records];
        *recorded_frame = *frame_record;
        recorded_frame->frame_missed = false;
        context->frame_recording.num_frame_records++;
    }
    
    return recorded_frame;
}


/*
 * @brief Identify if an Ethernet frame is one used by the test.
 * @details If the Ethernet frame is one used by the test also extracts the source/destination port indices
 *          and the sequence number.
 * @param[in] context Used to obtain the start time of the test interval, to populate a relative time.
 * @param[in] pkt_header When non-null the received packet header.
 *                       When NULL indicates are being called to record a transmitted test frame
 * @param[in] frame The frame to identify
 * @param[out] frame_record Contains information for the identified frame.
 *                          For a receive frame haven't yet performed the checks against the pending receive frames.
 */
static void identify_frame (const frame_tx_rx_thread_context_t *const context,
                            const struct pcap_pkthdr *const pkt_header, const ethercat_frame_t *const frame,
                            frame_record_t *const frame_record)
{
    if (pkt_header != NULL)
    {
        /* Use the len from the received frame */
        frame_record->len = pkt_header->len;
    }
    else
    {
        /* Set the len for the transmitted frame */
        frame_record->len = sizeof (ethercat_frame_t);
    }
    
    /* Extract MAC addresses, Ethernet type and VLAN ID from the frame, independent of the test frame format */
    const uint16_t ether_type = ntohs (frame->ether_type);
    const uint16_t vlan_ether_type = ntohs (frame->vlan_ether_type);

    frame_record->relative_test_time = get_monotonic_time () - context->statistics.interval_start_time;
    memcpy (frame_record->destination_mac_addr, frame->destination_mac_addr, sizeof (frame_record->destination_mac_addr));
    memcpy (frame_record->source_mac_addr, frame->source_mac_addr, sizeof (frame_record->source_mac_addr));
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

    /* Determine if the frame is one generated by the test program */
    bool is_test_frame = frame_record->len >= sizeof (ethercat_frame_t);
    
    if (is_test_frame)
    {
        is_test_frame = (ether_type == ETH_P_8021Q) && (vlan_ether_type == ETH_P_ETHERCAT) &&
                get_port_index_from_mac_addr (frame_record->source_mac_addr, &frame_record->source_port_index) &&
                get_port_index_from_mac_addr (frame_record->destination_mac_addr, &frame_record->destination_port_index);
    }

    /* Set the initial identified frame type. FRAME_RECORD_RX_TEST_FRAME may be modified following
     * subsequent checks against the pending receive frames */
    if (is_test_frame)
    {
        frame_record->test_sequence_number = frame->Address;
        frame_record->frame_type = (pkt_header != NULL) ? FRAME_RECORD_RX_TEST_FRAME : FRAME_RECORD_TX_TEST_FRAME;
    }
    else
    {
        frame_record->frame_type = FRAME_RECORD_RX_OTHER;
    }
}


/*
 * @brief Called when a received frame has been identified as a test frame, to update the list of pending frames
 * @param[in/out] context Context to update the pending frames for
 * @param[in/out] frame_record The received frame to compare against the list of pending frames.
 *                             On output the frame_type has been updated to identify which sub-type of receive frame it is.
 */
static void handle_pending_rx_frame (frame_tx_rx_thread_context_t *const context, frame_record_t *const frame_record)
{
    pending_rx_frames_t *const pending =
            &context->pending_rx_frames[frame_record->source_port_index][frame_record->destination_port_index];
    port_frame_statistics_t *const port_stats = 
            &context->statistics.port_frame_statistics[frame_record->source_port_index][frame_record->destination_port_index];
    
    if (frame_record->vlan_id == test_ports[frame_record->source_port_index].vlan)
    {
        /* If the VLAN ID is that of the source port, the PCAP receive has passed a copy of the transmitted frame */
        frame_record->frame_type = FRAME_RECORD_TX_COPY_FRAME;
    }
    else if (frame_record->vlan_id == test_ports[frame_record->destination_port_index].vlan)
    {
        /* The frame was received with the VLAN ID for the expected destination port, compare against the pending frames */
        bool pending_match_found = false;
        while ((!pending_match_found) && (pending->num_pending_rx_frames > 0))
        {
            if (frame_record->test_sequence_number == pending->pending_rx_sequence_numbers[pending->rx_index])
            {
                /* This is an expected pending receive frame */
                port_stats->num_valid_rx_frames++;
                frame_record->frame_type = FRAME_RECORD_RX_TEST_FRAME;
                pending_match_found = true;
            }
            else
            {
                /* The sequence number is not the next expected pending, which means a preceeding frame has been missed */
                port_stats->num_missing_rx_frames++;
                context->statistics.total_missing_frames++;
                if (pending->tx_frame_records[pending->rx_index] != NULL)
                {
                    pending->tx_frame_records[pending->rx_index]->frame_missed = true;
                }
            }
            
            pending->num_pending_rx_frames--;
            pending->tx_frame_records[pending->rx_index] = NULL;
            pending->rx_index = (pending->rx_index + 1) % MAX_PENDING_RX_FRAMES;
        }
        
        if (!pending_match_found)
        {
            frame_record->frame_type = FRAME_RECORD_RX_UNEXPECTED_FRAME;
        }
    }
    else
    {
        /* Must be a frame flooded to a port other than the intended destination */
        frame_record->frame_type = FRAME_RECORD_RX_FLOODED_FRAME;
    }
}


/*
 * @brief Sequence transmitting the next test frame, cycling around combinations of the source and destination ports
 * @details This also records the frame as pending receipt, identified with the combination of source/destination port
 *          and sequence nunmber.
 * @param[in/out] context Context used transmitting frames.
 */
static void transmit_next_test_frame (frame_tx_rx_thread_context_t *const context)
{
    int rc;
    const uint32_t source_port_index = (context->destination_port_index + context->source_port_offset) % NUM_TEST_PORTS;
    pending_rx_frames_t *const pending = &context->pending_rx_frames[source_port_index][context->destination_port_index];
    port_frame_statistics_t *const port_stats =
            &context->statistics.port_frame_statistics[source_port_index][context->destination_port_index];

    /* Create the test frame and transmit it */
    create_test_frame (&context->tx_frame, source_port_index, context->destination_port_index, context->next_tx_sequence_number);
    rc = pcap_sendpacket (context->pcap_handle, (const u_char *) &context->tx_frame, sizeof (context->tx_frame));
    if (rc != 0)
    {
        console_printf ("\nError sending the packet: %s\n", pcap_geterr(context->pcap_handle));
        exit (EXIT_FAILURE);
    }

    /* When debug is enabled identify the transmit frame and record it */
    frame_record_t *recorded_frame = NULL;
    if (arg_frame_debug_enabled)
    {
        frame_record_t frame_record;
        
        identify_frame (context, NULL, &context->tx_frame, &frame_record);
        recorded_frame = record_frame_for_debug (context, &frame_record);
    }

    /* Update transmit frame counts */
    context->statistics.frame_counts[FRAME_RECORD_TX_TEST_FRAME]++;
    port_stats->num_tx_frames++;

    /* If the maximum number of receive frames are pending, then mark the oldest as missing */
    if (pending->num_pending_rx_frames == MAX_PENDING_RX_FRAMES)
    {
        port_stats->num_missing_rx_frames++;
        context->statistics.total_missing_frames++;
        pending->num_pending_rx_frames--;
        if (pending->tx_frame_records[pending->rx_index] != NULL)
        {
            pending->tx_frame_records[pending->rx_index]->frame_missed = true;
        }
        pending->rx_index = (pending->rx_index + 1) % MAX_PENDING_RX_FRAMES;
    }
    
    /* Record the transmitted frame as pending receipt */
    pending->pending_rx_sequence_numbers[pending->tx_index] = context->next_tx_sequence_number;
    pending->tx_frame_records[pending->tx_index] = recorded_frame;
    pending->tx_index = (pending->tx_index + 1) % MAX_PENDING_RX_FRAMES;
    pending->num_pending_rx_frames++;

    /* Advance to the next frame which will be transmitted */
    context->next_tx_sequence_number++;
    context->destination_port_index = (context->destination_port_index + 1) % NUM_TEST_PORTS;
    if (context->destination_port_index == 0)
    {
        context->source_port_offset++;
        if (context->source_port_offset == NUM_TEST_PORTS)
        {
            context->source_port_offset = 1;
        }
    }
}


/*
 * @brief Thread which transmits test frames and checks for receipt of the frames from the switch under test
 * @param[out] arg The context for the thread.
 */
static void *transmit_receive_thread (void *arg)
{
    frame_tx_rx_thread_context_t *const context = arg;
    bool exit_requested = false;
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    int64_t now;
    int rc;
    frame_record_t frame_record;

    transmit_receive_initialise (context);
    
    /* Run test until requested to exit.
     * This gives preference to polling for receipt of test frames, and when no available frame transmits the next test frame.
     * This tries to send frames at the maximum possible rate, and relies upon the poll for frame receipt not causing any
     * frames to be discarded by the network stack. */
    while (!exit_requested)
    {
        now = get_monotonic_time ();

        /* Poll for receipt of packet */
        rc = pcap_next_ex (context->pcap_handle, &pkt_header, &pkt_data);
        if (rc == PCAP_ERROR)
        {
            console_printf ("\nError receiving packet: %s\n", pcap_geterr(context->pcap_handle));
            exit (EXIT_FAILURE);
        }
        else if (rc == 1)
        {
            /* Process received packet */
            identify_frame (context, pkt_header, (const ethercat_frame_t *) pkt_data, &frame_record);
            if (frame_record.frame_type != FRAME_RECORD_RX_OTHER)
            {
                handle_pending_rx_frame (context, &frame_record);
            }
            context->statistics.frame_counts[frame_record.frame_type]++;
            record_frame_for_debug (context, &frame_record);
        }
        else
        {
            transmit_next_test_frame (context);
        }
        
        if (now > context->test_interval_end_time)
        {
            /* The end of test interval has been reached */
            context->statistics.interval_end_time = now;
            if (context->statistics.total_missing_frames > 0)
            {
                rc = pcap_stats (context->pcap_handle, &context->statistics.pcap_statistics);
                if (rc == PCAP_ERROR)
                {
                    console_printf ("\npcap_stats() failed: %s\n", pcap_geterr(context->pcap_handle));
                    exit (EXIT_FAILURE);
                }
            }
            if (arg_frame_debug_enabled)
            {
                exit_requested = true;
            }
            else if (test_stop_requested)
            {
                exit_requested = true;
            }
            
            /* Publish and then reset statistics for the next test interval */
            rc = sem_wait (&test_statistics_free);
            if (rc != 0)
            {
                console_printf ("sem_wait (&test_statistics) failed\n");
                exit (EXIT_FAILURE);
            }
            context->statistics.final_statistics = exit_requested;
            test_statistics = context->statistics;
            rc = sem_post (&test_statistics_populated);
            if (rc != 0)
            {
                console_printf ("sem_post (&test_statistics_populated) failed\n");
                exit (EXIT_FAILURE);
            }
            reset_frame_test_statistics (&context->statistics);
            context->statistics.interval_start_time = context->statistics.interval_end_time;
            context->test_interval_end_time += (arg_test_interval_secs * NSECS_PER_SEC);
        }
    }

    pcap_close (context->pcap_handle);
    
    return NULL;
}


/**
 * @brief Write a CSV file which contains a record of the frames sent/received during a test.
 * @details This is used to debug a single test interval.
 * @param[in] frame_debug_csv_filename Name of CSV file to create
 * @param[in] frame_recording The frames which were sent/received during the test
 */
static void write_frame_debug_csv_file (const char *const frame_debug_csv_filename, const frame_records_t *const frame_recording)
{
    /* Create CSV file and write headers */
    FILE *const csv_file = fopen (frame_debug_csv_filename, "w");
    if (csv_file == NULL)
    {
        console_printf ("Failed to create %s\n", frame_debug_csv_filename);
        exit (EXIT_FAILURE);
    }
    fprintf (csv_file, "frame type,relative test time (secs),missed,source switch port,destination switch port,destination MAC addr,source MAC addr,len,ether type,VLAN,test sequence number\n");

    /* Write one row per recorded frame */
    for (uint32_t frame_index = 0; frame_index < frame_recording->num_frame_records; frame_index++)
    {
        const frame_record_t *const frame_record = &frame_recording->frame_records[frame_index];
        
        fprintf (csv_file, "%s,%.6f,%s",
                frame_record_types[frame_record->frame_type],
                frame_record->relative_test_time / 1E9,
                frame_record->frame_missed ? "Frame missed" : "");
        if (frame_record->frame_type != FRAME_RECORD_RX_OTHER)
        {
            fprintf (csv_file, ",%" PRIu32 ",%" PRIu32,
                    test_ports[frame_record->source_port_index].switch_port_number,
                    test_ports[frame_record->destination_port_index].switch_port_number);
        }
        else
        {
            fprintf (csv_file, ",,");
        }
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


/*
 * @brief Write the frame test statistics from the most recent test interval.
 * @details This is written as:
 *          - The console with a overall summary of which combinations of source/destination ports have missed frames.
 *          - A CSV file which has the per-port count of frames.
 * @param[in/out] results_summary Used to maintain a summary of which test intervals have had test failures.
 * @param[in] statistics The statistics crom the most recent interval
 */
static void write_frame_test_statistics (results_summary_t *const results_summary,
                                         const frame_test_statistics_t *const statistics)
{
    uint32_t source_port_index;
    uint32_t destination_port_index;
    char time_str[80];
    struct tm broken_down_time;
    struct timeval tod;
    frame_record_type_t frame_type;

    /* Display time when these statistics are reported */
    gettimeofday (&tod, NULL);
    const time_t tod_sec = tod.tv_sec;
    const int64_t tod_msec = tod.tv_usec / 1000;
    localtime_r (&tod_sec, &broken_down_time);
    strftime (time_str, sizeof (time_str), "%H:%M:%S", &broken_down_time);
    size_t str_len = strlen (time_str);
    snprintf (&time_str[str_len], sizeof (time_str) - str_len, ".%03" PRIi64, tod_msec);
    
    console_printf ("\n%s\n", time_str);

    /* Print header for counts */
    const int count_field_width = 13;
    for (frame_type = 0; frame_type < FRAME_RECORD_ARRAY_SIZE; frame_type++)
    {
        console_printf ("%*s  ", count_field_width, frame_record_types[frame_type]); 
    }
    console_printf ("%*s  %*s\n", count_field_width, "missed frames", count_field_width, "tx rate (Hz)");
    
    /* Display the count of the different frame types during the test interval.
     * Even when no missing frames the count of the transmit and receive frames may be different due to frames
     * still in flight at the end of the test interval. */
    for (frame_type = 0; frame_type < FRAME_RECORD_ARRAY_SIZE; frame_type++)
    {
        console_printf ("%*" PRIu32 "  ", count_field_width, statistics->frame_counts[frame_type]);
    }

    /* Report the total number of missing frames during the test interval */
    console_printf ("%*" PRIu32 "  ", count_field_width, statistics->total_missing_frames);
    
    /* Report the average frame rate achieved over the statistics interval */
    const double statistics_interval_secs = (double) (statistics->interval_end_time - statistics->interval_start_time) / 1E9;
    console_printf ("%*.1f\n", count_field_width,
            (double) statistics->frame_counts[FRAME_RECORD_TX_TEST_FRAME] / statistics_interval_secs);
    
    /* Display summary of missed frames over combination of source / destination ports */
    console_printf ("\nSummary of missed frames : '.' none missed 'S' some missed 'A' all misssed\n");
    console_printf ("Source  Destination ports --->\n");
    for (uint32_t header_row = 0; header_row < 2; header_row++)
    {
        console_printf ("%s", (header_row == 0) ? "  port  " : "        ");
        for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            char port_num_text[3];
            
            snprintf (port_num_text, sizeof (port_num_text), "%2" PRIu32, test_ports[destination_port_index].switch_port_number);
            console_printf ("%c", port_num_text[header_row]);
        }
        console_printf ("\n");
    }

    for (source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        console_printf ("    %2" PRIu32 "  ", test_ports[source_port_index].switch_port_number);
        for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            const port_frame_statistics_t *const port_statistics =
                    &statistics->port_frame_statistics[source_port_index][destination_port_index];
            char port_status;
            
            if (source_port_index == destination_port_index)
            {
                port_status = ' ';
            }
            else if (port_statistics->num_missing_rx_frames == 0)
            {
                port_status = '.';
            }
            else if (port_statistics->num_valid_rx_frames > 0)
            {
                port_status = 'S';
            }
            else
            {
                port_status = 'A';
            }
            console_printf ("%c", port_status);
        }
        console_printf ("\n");
    }
    
    /* Any missed frames counts as a test failure */
    if (statistics->total_missing_frames > 0)
    {
        results_summary->num_test_intervals_with_failures++;
        snprintf (results_summary->time_of_last_failure, sizeof (results_summary->time_of_last_failure), "%s", time_str);
        console_printf ("PCAP statistics : ps_recv=%" PRIu32 " ps_drop=%" PRIu32 " ps_ifdrop=%" PRIu32 "\n",
                statistics->pcap_statistics.ps_recv, statistics->pcap_statistics.ps_drop, statistics->pcap_statistics.ps_ifdrop);
    }
    
    /* Create per-port counts CSV file on first call, and write column headers */
    if (results_summary->per_port_counts_csv_file == NULL)
    {
        results_summary->per_port_counts_csv_file = fopen (results_summary->per_port_counts_csv_filename, "w");
        if (results_summary->per_port_counts_csv_file == NULL)
        {
            console_printf ("Failed to create %s\n", results_summary->per_port_counts_csv_filename);
            exit (EXIT_FAILURE);
        }
        fprintf (results_summary->per_port_counts_csv_file,
                "Time,Source switch port,Destination switch port,Num tx frames,Num valid rx frames,Num missing rx frames\n");
    }
    
    /* Write one row containing the number of frames per combination of source and destination switch ports tested */
    for (source_port_index = 0; source_port_index < NUM_TEST_PORTS; source_port_index++)
    {
        for (destination_port_index = 0; destination_port_index < NUM_TEST_PORTS; destination_port_index++)
        {
            if (source_port_index != destination_port_index)
            {
                const port_frame_statistics_t *const port_statistics =
                        &statistics->port_frame_statistics[source_port_index][destination_port_index];
                
                fprintf (results_summary->per_port_counts_csv_file,
                        " %s,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 "\n",
                        time_str, 
                        test_ports[source_port_index].switch_port_number,
                        test_ports[destination_port_index].switch_port_number,
                        port_statistics->num_tx_frames,
                        port_statistics->num_valid_rx_frames,
                        port_statistics->num_missing_rx_frames);
            }
        }
    }
    
    /* Display overall summary of test failures */
    console_printf ("Total test intervals with failures = %" PRIu32, results_summary->num_test_intervals_with_failures);
    if (results_summary->num_test_intervals_with_failures)
    {
        console_printf (" : last failure %s\n", (statistics->total_missing_frames > 0) ? "NOW" : results_summary->time_of_last_failure);
    }
    else
    {
        console_printf ("\n");
    }
}


int main (int argc, char *argv[])
{
    int rc;
    
    /* Check that ethercat_frame_t has the expected size */
    if (sizeof (ethercat_frame_t) != 1514)
    {
        fprintf (stderr, "sizeof (ethercat_frame_t) unexpected value of %" PRIuPTR "\n", sizeof (ethercat_frame_t));
        exit (EXIT_FAILURE);
    }

    /* Read the commandline arguments, and get the interface description which validates the interface */
    read_command_line_arguments (argc, argv);
    const char *const interface_description = get_interface_description (arg_pcap_interface_name);
    
    if (interface_description == NULL)
    {
        fprintf (stderr, "Interface name %s not found\n", arg_pcap_interface_name);
        exit (EXIT_FAILURE);
    }
    
    /* Initialise the semaphores used to control access to the test interval statistics */
    rc = sem_init (&test_statistics_free, 0, 1);
    if (rc != 0)
    {
        fprintf (stderr, "sem_init() failed\n");
        exit (EXIT_FAILURE);
    }
    rc = sem_init (&test_statistics_populated, 0, 0);
    if (rc != 0)
    {
        fprintf (stderr, "sem_init() failed\n");
        exit (EXIT_FAILURE);
    }

    /* Set filenames which contain the output files containing the date/time and OS used  */
    results_summary_t results_summary = {{0}};
    const time_t tod_now = time (NULL);
    struct tm broken_down_time;
    char date_time_str[80];
    char frame_debug_csv_filename[80];
    char console_filename[80];
    
    localtime_r (&tod_now, &broken_down_time);
    strftime (date_time_str, sizeof (date_time_str), "%Y%m%dT%H%M%S", &broken_down_time);
    snprintf (frame_debug_csv_filename, sizeof (frame_debug_csv_filename), "%s_frames_debug_%s.csv", date_time_str, OS_NAME);
    snprintf (console_filename, sizeof (console_filename), "%s_console_%s.txt", date_time_str, OS_NAME);
    snprintf (results_summary.per_port_counts_csv_filename, sizeof (results_summary.per_port_counts_csv_filename),
            "%s_per_port_counts_%s.csv", date_time_str, OS_NAME);
    
    console_file = fopen (console_filename, "wt");
    if (console_file == NULL)
    {
        fprintf (stderr, "Failed to create %s\n", console_filename);
        exit (EXIT_FAILURE);
    }
    
    /* Report the command line arguments used */
    console_printf ("Writing per-port counts to %s\n", results_summary.per_port_counts_csv_filename);
    console_printf ("Using interface %s (%s)\n", arg_pcap_interface_name, interface_description);
    console_printf ("Test interval = %" PRIi64 " (secs)\n", arg_test_interval_secs);
    console_printf ("Frame debug enabled = %s\n", arg_frame_debug_enabled ? "Yes" : "No");
    
    /* Create the transmit_receive_thread */
    frame_tx_rx_thread_context_t *const tx_rx_thread_context = calloc (1, sizeof (*tx_rx_thread_context));
    pthread_t tx_rx_thread_handle;

    rc = pthread_create (&tx_rx_thread_handle, NULL, transmit_receive_thread, tx_rx_thread_context);
    if (rc != 0)
    {
        console_printf ("pthread_create() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }
    
    /* Report that the test has started */
    if (arg_frame_debug_enabled)
    {
        console_printf ("Running for a single test interval to collect debug information\n");
    }
    else
    {
#ifdef _WIN32
        signal (SIGINT, stop_test_handler);
#else
        struct sigaction action;
        
        memset (&action, 0, sizeof (action));
        action.sa_handler = stop_test_handler;
        action.sa_flags = SA_RESTART;
        rc = sigaction (SIGINT, &action, NULL);
        if (rc != 0)
        {
            console_printf ("sigaction() failed rc=%d\n", rc);
            exit (EXIT_FAILURE);
        }
#endif
        console_printf ("Press Ctrl-C to stop test at end of next test interval\n");
    }
    
    /* Report the statistics for each test interval, stopping when get the final statistics */
    bool exit_requested = false;
    while (!exit_requested)
    {
        /* Wait for the statistics upon completion of a test interval */
        rc = sem_wait (&test_statistics_populated);
        if (rc != 0)
        {
            console_printf ("sem_wait (&test_statistics_populated) failed rc=%d\n", rc);
            exit (EXIT_FAILURE);
        }            

        /* Report the statistics */
        write_frame_test_statistics (&results_summary, &test_statistics);
        exit_requested = test_statistics.final_statistics;
        
        /* Indicate the main thread has completed using the test_statistics */
        rc = sem_post (&test_statistics_free);
        if (rc != 0)
        {
            console_printf ("sem_wait (&test_statistics_populated) failed rc=%d\n", rc);
            exit (EXIT_FAILURE);
        }            
    }

    /* Wait for the transmit_receive_thread to exit */
    rc = pthread_join (tx_rx_thread_handle, NULL);
    if (rc != 0)
    {
        console_printf ("pthread_join() failed rc=%d\n", rc);
        exit (EXIT_FAILURE);
    }

    /* Write the debug frame recording information if enabled */
    if (arg_frame_debug_enabled)
    {
        write_frame_debug_csv_file (frame_debug_csv_filename, &tx_rx_thread_context->frame_recording);
    }

    fclose (results_summary.per_port_counts_csv_file);
    fclose (console_file);
    
    return EXIT_SUCCESS;
}
