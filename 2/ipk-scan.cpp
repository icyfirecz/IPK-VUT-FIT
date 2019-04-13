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

#include "pseudo_headers.h"
#include "ipv6.h"

#define PU_ARGUMENT 1337
#define PT_ARGUMENT 420
#define I_ARGUMENT 666
#define WU_ARGUMENT 42
#define MAX_PORT_NUMBER 65535

#define TCP_CLOSED 0
#define TCP_OPEN 1
#define TCP_FILTERED 2

using namespace std;

bool wasClosed;

int tcpPortStates = TCP_FILTERED;

void callback_udp(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    wasClosed = true;
}

void callback_tcp_rst(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    tcpPortStates = TCP_CLOSED;
}

void callback_tcp_syn_ack(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    tcpPortStates = TCP_OPEN;
}




// Class represents scanner
class Scanner
{
    public:
        // Method for error handling.
        // errorMessage - Message error, which is going to get printed.
        // errCode - Number of code that is going to be returned.
        void print_error_exit(string errorMessage, int errCode)
        {
            cerr << errorMessage;
            exit(errCode);
        }

        // Method is implementation explode from PHP.
        // String is splitted into vector by delimeter.
        // content - string that will be splitted
        // delimeter - delimeter
        vector<string> explode(string content, char delimeter)
        {
            vector<string> tokens;
            stringstream data(content);

            string line;

            while(getline(data, line, delimeter))
            {
                tokens.push_back(line);
            }

            return tokens;
        }

        // Method parses the ports from unformated string from command
        // line, to the vector of number of ports.
        // unformatedPorts - unformated string of ports
        vector<int> parse_ports_range(string unformatedPorts)
        {
            // Regex for ports: 1-65535
            regex_t regex;

            if(regcomp(&regex, "^[0-9]{1,5}+-[0-9]{1,5}+$", REG_EXTENDED) != 0)
            {
                cout << "rip regex\n";
                exit(1);
            }


            if(regexec(&regex, unformatedPorts.c_str(), 0, NULL, 0) == 0)
            {
                vector<string> portsString = this->explode(unformatedPorts, '-');

                int startingPort = atoi(portsString[0].c_str());
                int endingPort = atoi(portsString[1].c_str());

                if(startingPort > endingPort || startingPort > MAX_PORT_NUMBER || endingPort > MAX_PORT_NUMBER)
                {
                    this->print_error_exit("Error, wrong order/number of requested ports!\n", 1);
                }

                vector<int> ports;
                for(; startingPort <= endingPort; startingPort++)
                {
                    ports.push_back(startingPort);
                }

                regfree(&regex);
                return ports;
            }

            regfree(&regex);

            regex_t regex2;
            if(regcomp(&regex2, "^[0-9]{1,5}(,[0-9]{1,5})*$", REG_EXTENDED) != 0)
            {
                cout << "rip regex\n";
                exit(1);
            }
            // Regex for ports: 1,2,420,1337,65535
            if(regexec(&regex2, unformatedPorts.c_str(), 0, NULL, 0) == 0)
            {
                vector<string> portsString = this->explode(unformatedPorts, ',');

                vector<int> ports;
                for(unsigned index = 0; index < portsString.size(); index++)
                {
                    ports.push_back(atoi(portsString[index].c_str()));
                }
                
                return ports;
                regfree(&regex2);
            }
            else
            {
                regfree(&regex2);
                this->print_error_exit("Error, wrong UDP/TCP ports format!\n", 1);
                
                vector<int> ThisIsDeadCode;
                return ThisIsDeadCode;
            }
            
            // pedantic is fun :)
            vector<int> ThisIsDeadCode;
            return ThisIsDeadCode;
        }

        // Method parses given interface from command line.
        void parse_interface(string interface)
        {
            struct ifaddrs *interfaces;
            struct ifaddrs *backup;

            getifaddrs(&interfaces);

            backup = interfaces;

            while(interfaces != NULL)
            {
                if(strcasecmp(interfaces->ifa_name, interface.c_str()) == 0)
                    break;
                
                interfaces = interfaces->ifa_next;
            }

            if(interfaces == NULL)
            {
                this->print_error_exit("Error, given interface was not found!\n", 1);
            }

            this->localIpFamily = interfaces->ifa_addr->sa_family;
            this->wasInterface = true;
            this->interfaceName = interface;

            if(this->localIpFamily == AF_INET)
            {
                void *tmpAddress = &((struct sockaddr_in*)interfaces->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, &tmpAddress, this->localIp, sizeof(this->localIp));
            }
            else if(this->localIpFamily == AF_INET6)
            {
                void *tmpAddress = &((struct sockaddr_in6*)interfaces->ifa_addr)->sin6_addr;
                inet_ntop(AF_INET6, &tmpAddress, this->localIp, sizeof(this->localIp));
            }
            else
            {
                this->print_error_exit("Error, given interface is not ipv4 or ipv6", 1);
            }

            freeifaddrs(backup);
        }

        // Method parses arguments from command line and sets up
        // Scanner attributes.
        void parse_arguments(int argc, char* argv[])
        {
            int option;

            static struct option long_options[] = 
            {
                {"pt", required_argument, &option, PT_ARGUMENT},
                {"pu", required_argument, &option, PU_ARGUMENT},
                {"i", required_argument, &option, I_ARGUMENT},
                {"wu", required_argument, &option, WU_ARGUMENT}
            };


            while((getopt_long_only(argc, argv, "", long_options, &option) != -1))
            {
                switch(option)
                {
                    case PT_ARGUMENT:
                        this->tcpTargetPorts = this->parse_ports_range(optarg);
                        break;
                    case PU_ARGUMENT:
                        this->udpTargetPorts = this->parse_ports_range(optarg);
                        break;
                    case I_ARGUMENT:
                        this->parse_interface(optarg);
                        break;
                    case WU_ARGUMENT:
                        this->icmpWaitTime = stof(optarg);
                        break;
                    default:
                        this->print_error_exit("Error, wrong argument switch!\n", 1);
                }
            }

            if((optind + 1) != argc)
            {
                this->print_error_exit("Error, wrong number of arguments!\n", 1);
            }

            this->targetByInput = argv[optind];
        }

        void fetch_local_ip()
        {
            ifaddrs *devices, *device;
            getifaddrs(&devices);

            device = devices;

            while(device != NULL)
            {
                if((device->ifa_flags & IFF_UP) != 0 and strcasecmp(device->ifa_name, "lo") != 0 and device->ifa_addr->sa_family == this->targetIpFamily)
                {
                    this->localIpFamily = this->targetIpFamily;
                    if (this->localIpFamily == AF_INET || this->localIpFamily == AF_INET6)
                    {
                        int tests = getnameinfo(device->ifa_addr,
                                        (this->localIpFamily == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                        this->localIp, NI_MAXHOST,
                                        NULL, 0, NI_NUMERICHOST);
                        if (tests != 0)
                        {
                            this->print_error_exit("Error, cannot fetch local IP!\n", 1);
                        }
                        break;
                    }
                }
                device = device->ifa_next;
            }

            if(device == NULL)
            {
                this->print_error_exit("Error, no interface found!\n", 1);
            }
        }
        // Method fetches the IP address of the user's target.
        void fetch_target_IP()
        {
            struct addrinfo *result = NULL;

            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM; 
            hints.ai_protocol = 0;

            if(getaddrinfo(this->targetByInput.c_str(), NULL, &hints, &result) != 0)
            {
                this->print_error_exit("Error, cannot fetch target service!\n Check if your interface IP family corresponds with target ip family!\n", 1);
            }

            void *addressPointer;
            char IPaddress[100];

            switch (result->ai_family)
            {
                case AF_INET:
                    addressPointer = &((struct sockaddr_in *)result->ai_addr)->sin_addr;
                    this->targetIpFamily = AF_INET;
                    break;
                case AF_INET6:
                    addressPointer = &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr;
                    this->targetIpFamily = AF_INET6;
                    break;
                default:
                    this->print_error_exit("Unknown error in getting IP.\n",1);
            }

            inet_ntop(result->ai_family, addressPointer, IPaddress, 100);
            this->targetIp = IPaddress;

            cout << "Interesting ports on " << this->targetByInput << " (" << this->targetIp << "): \n"; 

            freeaddrinfo(result);
        }

        char* create_udp_packet(int port)
        {
            char *datagram = (char *)malloc(4096);
            memset(datagram, 0, 4096);

            if(this->targetIpFamily == AF_INET)
            {
                udphdr *udpHeader = (udphdr *)(datagram + sizeof(iphdr));

                iphdr *ipHeader = (iphdr *)(datagram);

                ipHeader->version = 4; // IPV4
                ipHeader->ihl = 5; // sizeof ip packet / 4
                ipHeader->tos = 0; // no service
                ipHeader->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr)); // sending tcp packet
                ipHeader->id = htons(8); // random number
                ipHeader->frag_off = htons(0); // 0 fragmentation first packet
                ipHeader->ttl = 64; // 64 hops to live
                ipHeader->protocol = IPPROTO_TCP; // udp header is after this
                ipHeader->check = 0; // let kernel calculate the checksum 

                if(inet_pton(AF_INET, this->targetIp.c_str(), &ipHeader->daddr) != 1)
                {
                    this->print_error_exit("Error, cannot create IP packet!\n", 1);
                }

                if(inet_pton(AF_INET, this->wasInterface ? this->localIp : "8.8.8.8", &ipHeader->saddr) != 1)
                {
                    this->print_error_exit("Error, cannot create IP (SPOOFED)\n", 1);
                }

                pseudo_header_ipv4 pseudoIp;
                pseudoIp.destinationAddress = ipHeader->daddr;
                pseudoIp.length = htons(sizeof(iphdr));
                pseudoIp.protocolType = IPPROTO_IP;
                pseudoIp.reserved = 0;

                char source_ip[20];
                //get_local_ip( source_ip );
                pseudoIp.sourceAddress = inet_addr(source_ip);

                ipHeader->check = csum((unsigned short*)&pseudoIp, sizeof(pseudoIp));

                udpHeader->source = htons(getpid()); // random number
                udpHeader->len = sizeof(udphdr); // sending just header
                udpHeader->dest = htons(port); // scanned port
                udpHeader->check = 0; // csum will fill in

                // Checksum calculation preparation
                pseudo_header_csum_udp pseudoUdp;

                pseudoUdp.destinationAddress = ipHeader->daddr;
                pseudoUdp.length = htons(sizeof(udphdr));
                pseudoUdp.protocolType = IPPROTO_UDP;
                pseudoUdp.reserved = 0;

                pseudoUdp.sourceAddress = inet_addr(source_ip);

                memcpy(&pseudoUdp.udp, &udpHeader, sizeof(udpHeader));
                udpHeader->check = csum((unsigned short *)&pseudoUdp, sizeof(pseudoUdp));
            }

            else if(this->targetIpFamily == AF_INET6)
            {
                udphdr *udpHeader = (udphdr *)(datagram + sizeof(ipv6hdr));
                ipv6hdr *ipHeader = (ipv6hdr *)(datagram);

                ipHeader->ver = 6; // IPV6
                ipHeader->traf_cl = 0; // no service
                ipHeader->flow = htons(8); 
                ipHeader->len = htons(sizeof(ipv6hdr) + sizeof(udphdr)); // sending udp packet
                ipHeader->nxt_hdr = IPPROTO_UDP; // udp header is after this
                ipHeader->hop_lim = 64; // 64 hops to live
                
                if(inet_pton(AF_INET6, this->targetIp.c_str(), &ipHeader->a_dst) != 1)
                {
                    this->print_error_exit("Error, cannot create IP packet!\n", 1);
                }

                if(inet_pton(AF_INET6, "dead:dead:dead:dead:dead:dead:dead:dead", &ipHeader->a_src) != 1)
                {
                    this->print_error_exit("Error, cannot create IP (SPOOFED)\n", 1);
                }

                udpHeader->source = htons(getpid()); // random number
                udpHeader->len = htons(sizeof(udphdr)); // sending just header
                udpHeader->dest = htons(port); // scanned port
                udpHeader->check = 0; // kernel will fill in
            }

            return datagram;
        }

        pcap_t* create_udp_snifffer()
        {
            char *device, errorBuffer[PCAP_ERRBUF_SIZE];
            device = pcap_lookupdev(errorBuffer);

            if(device == NULL)
            {
                this->print_error_exit("Error, no ethernet device!\n", 1);
            }

            bpf_u_int32 subnetMask;
            bpf_u_int32 ip;

            pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);
            
            pcap_t *sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
            if(sniffHandler == NULL)
            {
                cout << errorBuffer;
                this->print_error_exit("Error, cannot open listening device!\n", 1);
            }

            struct bpf_program packetFilter;

            string packetFilterString = "icmp[icmpcode]=3 and src " + this->targetIp;
            
            if(pcap_compile(sniffHandler, &packetFilter, packetFilterString.c_str(), 0, ip) == -1)
            {
                this->print_error_exit("Error, wrong filter expression (pcap).\n", 1);
            }

            if(pcap_setfilter(sniffHandler, &packetFilter) == -1)
            {
                this->print_error_exit("Error, cannot apply filter.\n", 1);
            }

            return sniffHandler;
        }

        void send_udp_packets()
        {
            int udpSocket;
            // Socket binding to IPV4
            if(this->targetIpFamily == AF_INET)
            {
                udpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
            }
            // IPV6
            else if(this->targetIpFamily == AF_INET6)
            {
                udpSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
            }

            if(udpSocket == -1)
            {
                this->print_error_exit("Error, cannot create socket!\n", 1);
            }

            if(this->wasInterface)
            {
                setsockopt(udpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
            }

            for(unsigned index = 0; index < this->udpTargetPorts.size(); index++)
            {
                wasClosed = false;

                char *udpPacket = this->create_udp_packet(udpTargetPorts[index]);
                    
                cout << udpTargetPorts[index] << "/udp      ";

                // IPV4
                if(this->targetIpFamily == AF_INET)
                {
                    struct sockaddr_in socketAddress;
                    
                    socketAddress.sin_family = this->targetIpFamily;
                    socketAddress.sin_port = htons(udpTargetPorts[index]);
                    
                    inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr.s_addr);

                    if(sendto(udpSocket, udpPacket, sizeof(udpPacket), 0, (struct sockaddr*)&socketAddress, this->targetIpFamily == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)) == -1)
                    {
                        printf ("Error sending syn packet. Error number : %d . Error message : %s \n" ,errno , strerror(errno));
                        this->print_error_exit("Error, cannot send UDP packet!\n", 1);
                        exit(0);
                    }
                }
                // IPV6
                else
                {
                    struct sockaddr_in6 socketAddress;

                    socketAddress.sin6_port = htons(udpTargetPorts[index]);
                    socketAddress.sin6_family = this->targetIpFamily;

                    inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin6_addr);
                    
                    socketAddress.sin6_flowinfo = htons(111);
                    socketAddress.sin6_scope_id = 0;

                    if(sendto(udpSocket, udpPacket, sizeof(udphdr) + sizeof(iphdr), 0, (struct sockaddr*)&socketAddress, sizeof(socketAddress)) == -1)
                    {
                        this->print_error_exit("Error, cannot send UDP packet!\n", 1);
                    }
                }

                // Giving the port time to response
                sleep(this->icmpWaitTime);

                // Printing out the result of port
                if(wasClosed)
                {
                    cout << "close\n";
                }
                else
                {
                    cout << "open\n";
                }
                

                // Free packet
                free(udpPacket);
            }

            // Close UDP socket
            close(udpSocket);

            // Finish snooping
            pcap_breakloop(this->updIcmpFilterHolder);
        }

        void start_udp_scan()
        {
            thread packetSender(&Scanner::send_udp_packets, this);
            
            pcap_loop(this->updIcmpFilterHolder, -1, callback_udp, NULL);

            packetSender.join();
        }

        void prepare_and_start_udp_scan()
        {
            if(this->udpTargetPorts.size() == 0)
            {
                return;
            }

            this->updIcmpFilterHolder = this->create_udp_snifffer();

            this->start_udp_scan();
        }

        // tcppppppppppppp

        unsigned short csum(unsigned short *ptr,int length)
        {
 	        long int summary = 0;
 	        unsigned short oddbyte;
 	        unsigned short answer;


 	        while(length > 1) 
            {
 	            summary += *(ptr)++;
 	            length -= 2;
 	        }

 	        if(length == 1) 
            {
 	            oddbyte = 0;
 	            *((u_char*)&oddbyte) = *(u_char*)ptr;
 	            summary += oddbyte;
 	        }
    
 	        summary = (summary >> 16) + (summary & 0xffff);
 	        summary = summary + (summary >> 16);
 	        answer = (short)~summary;
    
 	        return(answer);
        }

        char* create_tcp_syn_packet(int port)
        {
            char *datagram = (char *)malloc(4096);
            memset(datagram, 0, 4096);

            if(this->targetIpFamily == AF_INET)
            {
 	            iphdr *ipHeader = (iphdr *) datagram;
 	            tcphdr *tcpHeader = (tcphdr *) (datagram + sizeof (iphdr));

 	            //char source_ip[20];
 	            //get_local_ip( source_ip );
        
        
 	            memset (datagram, 0, 4096); /* zero out the buffer */
        
 	            ipHeader->ihl = 5;
 	            ipHeader->version = 4;
 	            ipHeader->tos = 0;
 	            ipHeader->tot_len = sizeof(iphdr) + sizeof(tcphdr);
 	            ipHeader->id = htons(getpid()); //
 	            ipHeader->frag_off = 0;
 	            ipHeader->ttl = 64;
 	            ipHeader->protocol = IPPROTO_TCP;
 	            ipHeader->check = 0;
 	            //ipHeader->saddr = inet_addr(source_ip);
                
                if(inet_pton(AF_INET, "191.85.0.0", &ipHeader->saddr) != 1)
                {
                    this->print_error_exit("Error, cannot translate the (destination) IP address to packet!\n", 1);
                }
                if(inet_pton(AF_INET, this->targetIp.c_str(), &ipHeader->daddr) != 1)
                {
                    this->print_error_exit("Error, cannot translate the (destination) IP address to packet!\n", 1);
                }

 	            //TCP Header
 	            tcpHeader->source = htons(getpid());
 	            tcpHeader->dest = htons(port);
 	            tcpHeader->seq = htonl(1);
 	            tcpHeader->ack_seq = 0;
 	            tcpHeader->doff = 5;
 	            tcpHeader->syn = 1;
 	            tcpHeader->window = htons(1337);  // maximum allowed window size
 	            tcpHeader->check = 0; 
 	            tcpHeader->urg_ptr = 0;

                pseudo_header_csum_tcp psh;
                psh.sourceAddress = ipHeader->saddr;
 	            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &psh.destinationAddress);
 	            psh.reserved = 0;
 	            psh.protocolType = IPPROTO_TCP;
 	            psh.length = htons( sizeof(struct tcphdr) );
 	         
 	            memcpy(&psh.tcp , tcpHeader , sizeof (struct tcphdr));
 	         
 	            tcpHeader->check = csum((unsigned short*)&psh , sizeof (pseudo_header_csum_tcp));
            }
            else if(this->targetIpFamily == AF_INET6)
            {
                ipv6hdr *ipHeader = (ipv6hdr *)(datagram);
                tcphdr *tcpHeader = (tcphdr *)(datagram + sizeof(ipv6hdr));
                
                ipHeader->ver = 6; // IPV6
                ipHeader->traf_cl = 0; // no service
                ipHeader->flow = htons(111); // random number
                ipHeader->len = htons(sizeof(ipv6hdr) + sizeof(tcphdr)); // sending udp packet
                ipHeader->nxt_hdr = IPPROTO_TCP; // udp header is after this
                ipHeader->hop_lim = 64; // 64 hops to live
                
                if(inet_pton(AF_INET6, this->targetIp.c_str(), &ipHeader->a_dst) != 1)
                {
                    this->print_error_exit("Error, cannot create IP packet!\n", 1);
                }

                if(inet_pton(AF_INET6, "dead:dead:dead:dead:dead:dead:dead:dead", &ipHeader->a_src) != 1)
                {
                    this->print_error_exit("Error, cannot create IP (SPOOFED)\n", 1);
                }

                tcpHeader->source = getpid();
 	            tcpHeader->dest = htons (port); // Target
 	            tcpHeader->seq = htonl(3);
 	            tcpHeader->ack_seq = 0;
 	            tcpHeader->doff = sizeof(tcphdr) / 4; //Size of tcp in 32b words
 	            tcpHeader->syn = 1;
 	            tcpHeader->window = htons(1323); 
 	            tcpHeader->check = 0;
 	            tcpHeader->urg_ptr = 0;
            }
            return datagram;
        }

        void send_tcp_syn_packet(int port)
        {
            
/*             if(this->targetIpFamily == AF_INET)
            {
                struct sockaddr_in destination;

                memset(&destination, 0, sizeof(destination));
                destination.sin_family = this->targetIpFamily;
                destination.sin_port = htons(port);

                if(inet_pton(this->targetIpFamily, this->targetIp.c_str(), &destination.sin_addr) != 1)
                {
                    this->print_error_exit("Error, cannot translate IP\n", 1);
                }
                
                if((sendto(tcpSocket, tcpPacketSyn, sizeof(iphdr) + sizeof(tcphdr), 0, (struct sockaddr*)&destination, sizeof(destination))) < 0)
                {
                    this->print_error_exit("error, cannot send packet!\n", 1);
                } 
            }

            else
            {
               struct sockaddr_in6 dest;
                dest.sin6_family = this->targetIpFamily;
                dest.sin6_port = htons(port);
                dest.sin6_flowinfo = htons(111);
                dest.sin6_scope_id = 0;
                
                if(inet_pton(AF_INET6, this->targetIp.c_str(), &dest.sin6_addr) != 1)
                {
                    this->print_error_exit("Error, cannot create IP packet!\n", 1);
                }
                
                const int option = 1;
                if (setsockopt(tcpSocket, IPPROTO_IPV6, IPV6_HDRINCL, &option, sizeof (option)) < 0)
                {
                    printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno, strerror(errno));
                    exit(0);
                }

                if (sendto(tcpSocket, tcpPacketSyn , sizeof(ipv6hdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof(sockaddr_in6)) < 0)
                {
                    printf ("Error sending syn packet. Error number : %d . Error message : %s \n" ,errno , strerror(errno));
                    exit(0);
                } 
            } */
        }

        pcap_t* create_tcp_rst_sniffer()
        {
            char *device, errorBuffer[PCAP_ERRBUF_SIZE];
            device = pcap_lookupdev(errorBuffer);

            if(device == NULL)
            {
                this->print_error_exit("Error, no ethernet device!\n", 1);
            }

            bpf_u_int32 subnetMask;
            bpf_u_int32 ip;

            pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);
            
            pcap_t *sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
            if(sniffHandler == NULL)
            {
                cout << errorBuffer;
                this->print_error_exit("Error, cannot open listening device!\n", 1);
            }

            struct bpf_program packetFilter;

            string packetFilterString = "tcp[tcpflags] & (tcp-rst) != 0 and src " + this->targetIp;
            
            if(pcap_compile(sniffHandler, &packetFilter, packetFilterString.c_str(), 0, ip) == -1)
            {
                this->print_error_exit("Error, wrong filter expression (pcap).\n", 1);
            }

            if(pcap_setfilter(sniffHandler, &packetFilter) == -1)
            {
                this->print_error_exit("Error, cannot apply filter.\n", 1);
            }

            return sniffHandler;
        }

        pcap_t* create_tcp_syn_ack_sniffer()
        {
            char *device, errorBuffer[PCAP_ERRBUF_SIZE];
            device = pcap_lookupdev(errorBuffer);

            if(device == NULL)
            {
                this->print_error_exit("Error, no ethernet device!\n", 1);
            }

            bpf_u_int32 subnetMask;
            bpf_u_int32 ip;

            pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);
            
            pcap_t *sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
            if(sniffHandler == NULL)
            {
                cout << errorBuffer;
                this->print_error_exit("Error, cannot open listening device!\n", 1);
            }

            struct bpf_program packetFilter;

            string packetFilterString = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 or tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-rst) = 0 and src " + this->targetIp;
            
            if(pcap_compile(sniffHandler, &packetFilter, packetFilterString.c_str(), 0, ip) == -1)
            {
                this->print_error_exit("Error, wrong filter expression (pcap).\n", 1);
            }

            if(pcap_setfilter(sniffHandler, &packetFilter) == -1)
            {
                this->print_error_exit("Error, cannot apply filter.\n", 1);
            }

            return sniffHandler;
        }

        void send_tcp_packets()
        {
            int tcpSocket;
            // Socket binding to IPV4
            if(this->targetIpFamily == AF_INET)
            {
                tcpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            }
            // IPV6
            else if(this->targetIpFamily == AF_INET6)
            {
                tcpSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
            }
            if(tcpSocket == -1)
            {
                this->print_error_exit("Error, cannot create socket!\n", 1);
            }

            if(this->wasInterface)
            {
                setsockopt(tcpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
            }

            char *tcpPacket;
            for(unsigned index = 0; index < this->tcpTargetPorts.size(); index++)
            {
                tcpPortStates = TCP_FILTERED;

                cout << tcpTargetPorts[index] << "/tcp      ";

                // IPV4
                if(this->targetIpFamily == AF_INET)
                {
                    tcpPacket = this->create_tcp_syn_packet(tcpTargetPorts[index]);

                    struct sockaddr_in socketAddress;
                    
                    socketAddress.sin_family = this->targetIpFamily;
                    socketAddress.sin_port = htons(tcpTargetPorts[index]);
                    
                    inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr.s_addr);
                    if((sendto(tcpSocket, tcpPacket, sizeof(iphdr) + sizeof(tcphdr), 0, (struct sockaddr*)&socketAddress, sizeof(sockaddr_in))) < -1)
                    {
                        this->print_error_exit("Error, cannot send TCP packet!\n", 1);
                        exit(0);
                    }
                }
                // IPV6
                else
                {

                }

                // Giving the port time to response
                sleep(1);

                // Printing out the result of port
                if(tcpPortStates == TCP_CLOSED)
                {
                    cout << "close\n";
                }
                else if(tcpPortStates == TCP_OPEN)
                {
                    cout << "open\n";
                }
                else
                {
                    cout << "filtered\n";
                }
                
                // Free packet
                free(tcpPacket);

            }
            close(tcpSocket);

            pcap_breakloop(this->tcpRstFilterHolder);
            pcap_breakloop(this->tcpSynAckFilterHolder);
        }

        void start_rst_pcap_loop()
        {
            pcap_loop(this->tcpRstFilterHolder, -1, callback_tcp_rst, NULL);
        }

        void start_syn_ack_pcap_loop()
        {
            pcap_loop(this->tcpSynAckFilterHolder, -1, callback_tcp_syn_ack, NULL);
        }

        void start_tcp_scan()
        {
            thread packetRstSniffer(&Scanner::start_rst_pcap_loop, this);
            thread packetSynAckSniffer(&Scanner::start_syn_ack_pcap_loop, this);
            
            this->send_tcp_packets();

            packetRstSniffer.join();
            packetSynAckSniffer.join();
        }

        void start_tcp_sniff()
        {
            if(this->tcpTargetPorts.size() == 0)
            {
                return;
            }

            this->tcpRstFilterHolder = create_tcp_rst_sniffer();
            this->tcpSynAckFilterHolder = create_tcp_syn_ack_sniffer();

            this->start_tcp_scan();
        }

        // Scanner contructor 
        Scanner()
        {
            this->wasInterface = false;
            memset(&this->localIp, 0, sizeof(this->localIp));
            this->icmpWaitTime = 1;
        }

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
};

int main(int argc, char *argv[])
{
    Scanner *scanner = new Scanner;
    scanner->parse_arguments(argc, argv);
    scanner->fetch_target_IP();
    scanner->fetch_local_ip();
    cout << "PORT         STATE\n";


    scanner->prepare_and_start_udp_scan();
    scanner->start_tcp_sniff();
    return 0;
}