// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include "ipk-scan.hpp"

int tcpPortStates;

mutex tcpLock;

void callback_tcp_rst(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // RST packet caught, set state to CLOSED
    tcpLock.lock();
    tcpPortStates = TCP_CLOSED;
    tcpLock.unlock();
}

void callback_tcp_syn_ack(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // SYN ACK packet caught, set state to OPEN
    tcpLock.lock();
    tcpPortStates = TCP_OPEN;
    tcpLock.unlock();
}


void callback_tcp_syn_ack_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // RST packet caught, set state to CLOSED
    tcpLock.lock();
    tcpPortStates = TCP_OPEN;
    tcpLock.unlock();
}

void callback_tcp_rst_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // SYN ACK packet caught, set state to OPEN
    tcpLock.lock();
    tcpPortStates = TCP_CLOSED;
    tcpLock.unlock();
}

unsigned short Scanner::csum(unsigned short *ptr, int length)
{
    long int summary = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (length > 1)
    {
        summary += *(ptr)++;
        length -= 2;
    }

    if (length == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        summary += oddbyte;
    }

    summary = (summary >> 16) + (summary & 0xffff);
    summary = summary + (summary >> 16);
    answer = (short)~summary;

    return (answer);
}

char *Scanner::create_tcp_syn_packet(int port)
{
    // Allocate datagram
    char *datagram = (char *)malloc(4096);
    memset(datagram, 0, 4096);

    // IPV4
    if (this->targetIpFamily == AF_INET)
    {
        // Create IP header
        iphdr *ipHeader = (iphdr *)datagram;

        // Create TCP header
        tcphdr *tcpHeader = (tcphdr *)(datagram + sizeof(iphdr));

        memset(datagram, 0, 4096);

        // IP Header
        ipHeader->ihl = 5; // Sizeof(ipheader) / 8
        ipHeader->version = 4; // IPV4
        ipHeader->tos = 0; // No special service
        ipHeader->tot_len = sizeof(iphdr) + sizeof(tcphdr); // Size of the whole packet
        ipHeader->id = htons(getpid()); // Random number
        ipHeader->frag_off = 0; // No fragmentation
        ipHeader->ttl = 64; // Time to live 64
        ipHeader->protocol = IPPROTO_TCP; // Next protocol is TCP
        ipHeader->check = 0; // Kernel will fill

        // Translate the source address to the header
        if (inet_pton(AF_INET, this->localIp, &ipHeader->saddr) != 1)
        {
            this->print_error_exit("Error, cannot translate the (source) IP address to packet!\n", 1);
        }

        // Translate the destination address to the header
        if (inet_pton(AF_INET, this->targetIp.c_str(), &ipHeader->daddr) != 1)
        {
            this->print_error_exit("Error, cannot translate the (destination) IP address to packet!\n", 1);
        }

        //TCP Header
        tcpHeader->source = htons(1337); // random port number
        tcpHeader->dest = htons(port); // Destination port
        tcpHeader->seq = htonl(rand()); // Random number
        tcpHeader->ack_seq = 0; // SYN packet, new communication, previous seq is 0
        tcpHeader->doff = 5; // Offset 5
        tcpHeader->syn = 1; // Syn packet
        tcpHeader->window = htons(1337); // Random window size
        tcpHeader->check = 0; // Will calculate checksum later
        tcpHeader->urg_ptr = 0; // No urgent flag

        pseudo_header_csum_tcp psh;
        psh.sourceAddress = ipHeader->saddr;
        inet_pton(this->targetIpFamily, this->targetIp.c_str(), &psh.destinationAddress);
        psh.reserved = 0;
        psh.protocolType = IPPROTO_TCP;
        psh.length = htons(sizeof(struct tcphdr));

        memcpy(&psh.tcp, tcpHeader, sizeof(struct tcphdr));

        // calculate the checksum
        tcpHeader->check = csum((unsigned short *)&psh, sizeof(pseudo_header_csum_tcp));
    }
    else if (this->targetIpFamily == AF_INET6)
    {
        // Create UDP header
        tcphdr *tcpHeader = (tcphdr *)(datagram);

        tcpHeader->source = htons(1337); // Random port number
        tcpHeader->dest = htons(port); // Destination port
        tcpHeader->seq = htonl(rand()); // Random sequence number
        tcpHeader->ack_seq = 0; // SYN packet, new communication, previous seq is 0
        tcpHeader->doff = sizeof(tcphdr) / 4; //Size of tcp in 32b words
        tcpHeader->syn = 1; // SYN packet
        tcpHeader->window = htons(1337); // Random window size
        tcpHeader->check = 0; // THanks to the IPV6_CHECKSUM setsockopt flag, the kernel will calculate it
        tcpHeader->urg_ptr = 0; // No urgent flag
    }

    return datagram;
}

pcap_t *Scanner::create_tcp_rst_sniffer()
{
    char *device, errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *sniffHandler;
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;
    
    // If was given interface attach the sniffer to that device
    if(this->wasInterface)
    {
        pcap_lookupnet(this->interfaceName.c_str(), &ip, &subnetMask, errorBuffer);

        sniffHandler = pcap_open_live(this->interfaceName.c_str(), BUFSIZ, 1, -1, errorBuffer);
        if (sniffHandler == NULL)
        {
            cerr << errorBuffer << endl;
            this->print_error_exit("Error, cannot open listening device!\n", 1);
        }

    }
    // Find yourself interface
    else
    {
        device = pcap_lookupdev(errorBuffer);

        if (device == NULL)
        {
            this->print_error_exit("Error, no ethernet device!\n", 1);
        }


        pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);

        sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
        if (sniffHandler == NULL)
        {
            cout << errorBuffer;
            this->print_error_exit("Error, cannot open listening device!\n", 1);
        }
    }
    
    struct bpf_program packetFilter;

    string packetFilterString;

    // IPV4 RST filter
    if(this->targetIpFamily == AF_INET)
    {
        packetFilterString = "tcp[tcpflags] & (tcp-rst) != 0 and src " + this->targetIp;
    }
    // IPV6 RST filter
    else
    {
        packetFilterString = "((ip6[6] == 6 && ip6[53] & 0x04 == 0x04) || (ip6[6] == 6 && tcp[13] & 0x04 == 0x04)) and src " + this->targetIp;   
    }
    

    if (pcap_compile(sniffHandler, &packetFilter, packetFilterString.c_str(), 0, ip) == -1)
    {
        this->print_error_exit("Error, wrong filter expression (pcap).\n", 1);
    }

    if (pcap_setfilter(sniffHandler, &packetFilter) == -1)
    {
        this->print_error_exit("Error, cannot apply filter.\n", 1);
    }

    return sniffHandler;
}

pcap_t *Scanner::create_tcp_syn_ack_sniffer()
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *sniffHandler;

    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    // If interface was given attach to that interface
    if(this->wasInterface)
    {
        pcap_lookupnet(this->interfaceName.c_str(), &ip, &subnetMask, errorBuffer);

        sniffHandler = pcap_open_live(this->interfaceName.c_str(), BUFSIZ, 1, -1, errorBuffer);
        
        if (sniffHandler == NULL)
        {
            cerr << errorBuffer << endl;
            this->print_error_exit("Error, cannot open listening device!\n", 1);
        }
    }
    // Find interface yourself
    else
    {
        char *device;
        device = pcap_lookupdev(errorBuffer);

        if (device == NULL)
        {
            this->print_error_exit("Error, no ethernet device!\n", 1);
        }

        pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);

        sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
        if (sniffHandler == NULL)
        {
            cout << errorBuffer;
            this->print_error_exit("Error, cannot open listening device!\n", 1);
        }
    }
    
    struct bpf_program packetFilter;

    string packetFilterString;

    // IPV4 syn ack filter
    if(this->targetIpFamily == AF_INET)
    {
        packetFilterString = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 or tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-rst) = 0 and src " + this->targetIp;
    }
    // IPV6 syn ack filter
    else
    {
        packetFilterString = packetFilterString = "((tcp[13] & 0x12 == 0x12) || (ip6[6] == 6 && ip6[53] & 0x12 == 0x12)) || ((tcp[13] & 0x02 == 0x02) || (ip6[6] == 6 && ip6[53] & 0x02 == 0x02)) and src " + this->targetIp;
    }
    
    if (pcap_compile(sniffHandler, &packetFilter, packetFilterString.c_str(), 0, ip) == -1)
    {
        this->print_error_exit("Error, wrong filter expression (pcap).\n", 1);
    }

    if (pcap_setfilter(sniffHandler, &packetFilter) == -1)
    {
        this->print_error_exit("Error, cannot apply filter.\n", 1);
    }

    return sniffHandler;
}

void Scanner::send_tcp_packets()
{
    // Initialize the tcp port STATE to filtered
    tcpPortStates = TCP_FILTERED;
    int tcpSocket;

    // Socket binding to IPV4
    if (this->targetIpFamily == AF_INET)
    {
        tcpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    }
    // IPV6
    else if (this->targetIpFamily == AF_INET6)
    {
        tcpSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    }

    // Socket is unsuccessful
    if (tcpSocket == -1)
    {
        this->print_error_exit("Error, cannot create socket!\n", 1);
    }

    // If interface was given, bind that interface to that socket
    if (this->wasInterface)
    {
        setsockopt(tcpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
    }

    char *tcpPacket;

    // Initialize number of times that packet was sent
    int timesSent = 0;

    // IPV4 socket, set that the scanner will provide ipv4 header
    if(this->targetIpFamily == AF_INET)
    {
        const int option = 1;
        if(setsockopt(tcpSocket, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option)) < 0)
        {
            this->print_error_exit("Error, cannot set the socket!\n", 1);
        }
    }

    // IPV6 socket, set the ipv6 checksum option, so the kernel will calculate tcp checksum itself
    else
    {
        const int option = TCP_CHECKSUM_OFFSET; // Offset to the checksum variable in the header
        if (setsockopt(tcpSocket, IPPROTO_IPV6, IPV6_CHECKSUM, &option, sizeof(option)) < 0)
        {
            this->print_error_exit("Error, cannot calculate the checksum for IPV6(TCP)!\n", 1);
        }
    }
    
    // Start sending packets
    for (unsigned index = 0; index < this->tcpTargetPorts.size(); index++)
    {
        // Restart the TCP port state variable
        tcpPortStates = TCP_FILTERED;

        // IPV4 sending
        if (this->targetIpFamily == AF_INET)
        {
            // Create packet
            tcpPacket = this->create_tcp_syn_packet(tcpTargetPorts[index]);

            struct sockaddr_in socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            // Set destination and port and family
            socketAddress.sin_family = this->targetIpFamily;
            socketAddress.sin_port = htons(tcpTargetPorts[index]);

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr);

            // send packet
            if ((sendto(tcpSocket, tcpPacket, sizeof(iphdr) + sizeof(tcphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress))) < 0)
            {
                this->print_error_exit("Error, cannot send TCP packet!\n", 1);
            }

            // add number of times that packet was sent to that port
            timesSent++;
        }
        // IPV6
        else
        {
            // Create packet
            tcpPacket = this->create_tcp_syn_packet(tcpTargetPorts[index]);

            struct sockaddr_in6 socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            // Set destination and family, port must be 0 for IPV6
            socketAddress.sin6_port = 0;
            socketAddress.sin6_family = this->targetIpFamily;

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin6_addr);

            // send packet
            if((sendto(tcpSocket, tcpPacket, sizeof(tcphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress))) < 0)
            {
                this->print_error_exit("Error, cannot send TCP packet!\n", 1);
            }

            // add number of times that packet was sent to that port
            timesSent++;
        }

        // Giving the port, time to response
        sleep(this->tcpWaitTime);

        // Critical section
        tcpLock.lock();
        // Printing out the result of port
        if (tcpPortStates == TCP_CLOSED)
        {
            cout << tcpTargetPorts[index] << "/tcp      ";
            cout << "close\n";
            timesSent = 0; // Restart counter
        }
        else if (tcpPortStates == TCP_OPEN)
        {
            cout << tcpTargetPorts[index] << "/tcp      ";
            cout << "open\n";
            timesSent = 0; // Restart counter
        }
        else
        {
            // Port is filtered but the packet was still not sent requested timesRepeatTcp
            if(timesSent != this->timesRepeatTcp)
            {
                index--; // Return back to the same port
                tcpLock.unlock(); // Unlock mutex
                free(tcpPacket); // Free out memory
                continue; // Go agane
            }

            cout << tcpTargetPorts[index] << "/tcp      ";
            cout << "filtered\n";
            timesSent = 0; // Restart counter
        }
        tcpLock.unlock();

        // Free packet
        free(tcpPacket);
    }
    // Close socket
    close(tcpSocket);

    // End looping threads
    pcap_breakloop(this->tcpRstFilterHolder);
    pcap_breakloop(this->tcpSynAckFilterHolder);
}

void Scanner::start_rst_pcap_loop()
{
    pcap_loop(this->tcpRstFilterHolder, -1, callback_tcp_rst, NULL);
}

void Scanner::start_syn_ack_pcap_loop()
{
    pcap_loop(this->tcpSynAckFilterHolder, -1, callback_tcp_syn_ack, NULL);
}

void Scanner::start_rst_ipv6_pcap_loop()
{
    pcap_loop(this->tcpRstFilterHolder, -1, callback_tcp_rst_ipv6, NULL);
}

void Scanner::start_syn_ack_ipv6_pcap_loop()
{
    pcap_loop(this->tcpSynAckFilterHolder, -1, callback_tcp_syn_ack_ipv6, NULL);
}


void Scanner::start_tcp_scan()
{
    // IPV4
    if(this->targetIpFamily == AF_INET)
    {
        // Start sniffing threads
        thread packetRstSniffer(&Scanner::start_rst_pcap_loop, this);
        thread packetSynAckSniffer(&Scanner::start_syn_ack_pcap_loop, this);
    
        // Start sending packets
        this->send_tcp_packets();

        packetRstSniffer.join();
        packetSynAckSniffer.join();
    }
    else
    {
        // Start sniffing threads
        thread packetRstSniffer(&Scanner::start_rst_ipv6_pcap_loop, this);
        thread packetSynAckSniffer(&Scanner::start_syn_ack_ipv6_pcap_loop, this);

        // Start sending packets
        this->send_tcp_packets();

        packetRstSniffer.join();
        packetSynAckSniffer.join();
    }
}

void Scanner::prepare_and_start_tcp_scan()
{
    // Nothing wants to be scanned
    if (this->tcpTargetPorts.size() == 0)
    {
        return;
    }

    // Create filter sniffers
    this->tcpRstFilterHolder = create_tcp_rst_sniffer();
    this->tcpSynAckFilterHolder = create_tcp_syn_ack_sniffer();

    // Start scanning tcp
    this->start_tcp_scan();
}