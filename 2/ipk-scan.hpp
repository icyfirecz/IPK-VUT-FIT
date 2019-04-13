#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <regex.h>
#include <sstream>
#include <netdb.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <thread>
#include <net/if.h>
#include "pseudo_headers.hpp"
#include "ipv6.hpp"

#define PU_ARGUMENT 1337
#define PT_ARGUMENT 420
#define I_ARGUMENT 666
#define WU_ARGUMENT 42
#define WT_ARGUMENT 69

#define MAX_PORT_NUMBER 65535

#define TCP_CLOSED 0
#define TCP_OPEN 1
#define TCP_FILTERED 2

using namespace std;

void callback_udp(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_rst(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_syn_ack(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Class represents scanner
class Scanner
{
    public:
        // Method for error handling.
        // errorMessage - Message error, which is going to get printed.
        // errCode - Number of code that is going to be returned.
        void print_error_exit(string errorMessage, int errCode);

        // Method is implementation explode from PHP.
        // String is splitted into vector by delimeter.
        // content - string that will be splitted
        // delimeter - delimeter
        vector<string> explode(string content, char delimeter);

        // Method parses the ports from unformated string from command
        // line, to the vector of number of ports.
        // unformatedPorts - unformated string of ports
        vector<int> parse_ports_range(string unformatedPorts);

        // Method parses given interface from command line.
        void parse_interface(string interface);

        // Method parses arguments from command line and sets up
        // Scanner attributes.
        void parse_arguments(int argc, char* argv[]);

        void fetch_local_ip();

        // Method fetches the IP address of the user's target.
        void fetch_target_IP();
        char* create_udp_packet(int port);
        pcap_t* create_udp_snifffer();
        void send_udp_packets();
        void start_udp_scan();
        void prepare_and_start_udp_scan();
        unsigned short csum(unsigned short *ptr, int length);
        char* create_tcp_syn_packet(int port);
        pcap_t* create_tcp_rst_sniffer();
        pcap_t* create_tcp_syn_ack_sniffer();
        void send_tcp_packets();
        void start_rst_pcap_loop();
        void start_syn_ack_pcap_loop();
        void start_tcp_scan();
        void prepare_and_start_tcp_scan();
        Scanner();

      private:
        // Holds the UDP ports that are going to be scanned
        vector<int> udpTargetPorts;
        // Holds the TCP ports that are going to be scanned
        vector<int> tcpTargetPorts;
        // Holds up IP of target
        string targetIp;
        // Holds the family of IP (4/6)
        int targetIpFamily;
        // Holds the unformatted target to scan (argument input)
        string targetByInput;
        // Holds the udp sniffer
        pcap_t *updIcmpFilterHolder;
        // Flag which indicates if user requested interface
        bool wasInterface;
        // requested interface name
        string interfaceName;
        // Interface IP
        char localIp[100];
        // Local ip family (4/6)
        int localIpFamily;
        // User specified time, how much time to wait for ICMP packet (UDP response) 
        float icmpWaitTime;
        // Holds the tcp RST packet sniffer filter
        pcap_t *tcpRstFilterHolder;
        // Holds the SYN-ACK/SYN packet sniffer filter
        pcap_t *tcpSynAckFilterHolder;
        // User specified time, how much time to wait for TCP packet (TCP reponse)
        float tcpWaitTime;
};