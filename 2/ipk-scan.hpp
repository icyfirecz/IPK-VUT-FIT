// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include <iostream> // cout
#include <string> // string
#include <vector> // vectors
#include <sstream> // stringstream
#include <thread> // thread
#include <cstdlib> // stof, stoi
#include <mutex> // mutex
#include <getopt.h> // getopt_long_only
#include <sys/socket.h> // socket
#include <arpa/inet.h> // inet_ntop, inet_pton
#include <regex.h> // regex
#include <netdb.h> // getnameinfo
#include <string.h> // strcmp
#include <netinet/ip.h> // ip header
#include <netinet/udp.h> // udp header
#include <netinet/tcp.h> // tcp header  
#include <unistd.h> // sleep, close
#include <pcap.h> // libpcap, sniffing
#include <ifaddrs.h> // getifaddrs
#include <net/if.h> // IFF_UP macro for interfaces
#include "pseudo_headers.hpp" // TCP pseudoheader

// ARGUMENT MACROS FOR GETOPT_LONG_ONLY
#define PU_ARGUMENT 1337
#define PT_ARGUMENT 420
#define I_ARGUMENT 666
#define WU_ARGUMENT 42
#define WT_ARGUMENT 281
#define RU_ARGUMENT 330
#define RT_ARGUMENT 8004

// MAXIMAL PORT NUMBER
#define MAX_PORT_NUMBER 65535

// MACROS FOR STATES OF tcpPortStates
#define TCP_CLOSED 0
#define TCP_OPEN 1
#define TCP_FILTERED 2

#define TCP_CHECKSUM_OFFSET 16
#define UDP_CHECKSUM_OFFSET 6

using namespace std;

// Callback functions for UDP/TCP sniffers (pcap_loop)
void callback_udp(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_rst(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_syn_ack(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_syn_ack_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void callback_tcp_rst_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Class represents scanner
class Scanner
{
    public:
        // Method for error handling.
        // @param errorMessage Message error, which is going to get printed.
        // @param errCode Number of code that is going to be returned.
        void print_error_exit(string errorMessage, int errCode);

        // Method is implementation explode from PHP.
        // String is splitted into vector by delimeter.
        // @param content - string that will be splitted
        // @param delimeter - delimeter
        vector<string> explode(string content, char delimeter);

        // Method parses the ports from unformated string from command
        // line, to the vector of number of ports.
        // @param unformatedPorts - unformated string of ports
        vector<int> parse_ports_range(string unformatedPorts);

        // Method parses given interface from command line.
        // And saves its IP, NAME, IP FAMILY.
        void parse_interface(string interface);

        // Method parses arguments from command line and sets up
        // Scanner attributes.
        void parse_arguments(int argc, char* argv[]);

        // Method fetches the IP address of the local interface
        // This method does nothing, if user gave interface in command line
        // (parse_interface).
        // Helping source: http://man7.org/linux/man-pages/man3/getifaddrs.3.html
        void fetch_local_ip();

        // Method fetches the IP address of the user's target.
        // Using getaddinfo and saves the IP and FAMILY to the Scanner instance.
        void fetch_target_IP();

        // Method creates IP + UDP packet and returns pointer to it
        // @param port Number of port which is scanned. 
        // This port will be inserted into header
        char* create_udp_packet(int port);

        // Method creates UDP ICMP code 3 sniffer and returns,
        // handle pointer to it
        pcap_t* create_udp_snifffer();

        // Method sends udp packets to ports from udpTargetPorts
        // in for cycle and waits
        // udpWaitTime seconds for answer, after that
        // method checks up the variable wasClosed, if the
        // response was true or false.
        // After that the method prints out the result of the port.
        // This method is sender thread.
        void send_udp_packets();

        // Start of the UDP scanning, means creating
        // threads for sniffing and sending.
        void start_udp_scan();

        // Preparation before the UDP scanning, means
        // creating the sniffer filters and and starting start_udp_scan
        void prepare_and_start_udp_scan();

        // Method for calculating the TCP checksum. 
        // @param ptr Pointer to the tcp pseudoheader.
        // @param length Size of the pseudoheader structure.
        // Helping source: https://github.com/inet-framework/inet-quagga/blob/master/src/quaggasrc/quagga-0.99.12/lib/checksum.c
        unsigned short csum(unsigned short *ptr, int length);

        // Method creates TCP SYN packet and returns pointer to it.
        // @param port Number of port which is scanned.
        char* create_tcp_syn_packet(int port);

        // Method creates the sniffer for TCP RST packets
        // and returns handle to  it.
        pcap_t* create_tcp_rst_sniffer();

        // Method creates the sniffer for TCP SYN ACK packets
        // and returns handle to it.
        pcap_t* create_tcp_syn_ack_sniffer();

        // Method sends TCP packets to ports from tcpTargetPorts
        // in for cycle and waits tcpWaitTime seconds for answer,
        // after that method checks up the variable tcpPortStates,
        // if the response was TCP_FILTERED, TCP_CLOSED or TCP_OPEN.
        // After that the method prints out the result of the port.
        // This method is sender thread.
        void send_tcp_packets();

        // TCP IPV4
        // Method starts the sniffer RST packet sniffing.
        // This is sniffing thread.
        void start_rst_pcap_loop();

        // TCP IPV4
        // Method starts the sniffer SYN ACK packet sniffing.
        // This is sniffing thread.
        void start_syn_ack_pcap_loop();

        // TCP IPV6
        // Method starts the sniffer RST packet sniffing.
        // This is sniffing thread.
        void start_rst_ipv6_pcap_loop();

        // TCP IPV6
        // Method starts the sniffer SYN ACK packet sniffing.
        // This is sniffing thread.
        void start_syn_ack_ipv6_pcap_loop();

        // Start of the TCP scanning, means creating
        // threads for sniffing and sending.
        void start_tcp_scan();
        
        // Preparation before the TCP scanning, means
        // creating the sniffer filters and starting start_tcp_scan 
        void prepare_and_start_tcp_scan();

        // Constructor of the scanner
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
        // Holds the number of times, how many repeated retries is packet sent if udp port does
        // not repond with ICMP packet.
        int timesRepeatUdp;
        // Holds the number of times, how many repeated retires is packet sent again if tcp port
        // is filtered.
        int timesRepeatTcp;
};