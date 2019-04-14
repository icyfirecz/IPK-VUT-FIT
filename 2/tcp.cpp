#include "ipk-scan.hpp"

int tcpPortStates;

mutex tcpLock;

void callback_tcp_rst(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    tcpPortStates = TCP_CLOSED;
}

void callback_tcp_syn_ack(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    tcpPortStates = TCP_OPEN;
}


void callback_tcp_syn_ack_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    tcpLock.lock();
    tcpPortStates = TCP_OPEN;
    tcpLock.unlock();
}

void callback_tcp_rst_ipv6(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
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

// Method creates TCP (SYN) packet and returns pointer to it.
// The IP packet is created based on 6/4 protocol.
// port - Port number, to which packet is sent
char *Scanner::create_tcp_syn_packet(int port)
{
    char *datagram = (char *)malloc(4096);
    memset(datagram, 0, 4096);

    if (this->targetIpFamily == AF_INET)
    {
        iphdr *ipHeader = (iphdr *)datagram;
        tcphdr *tcpHeader = (tcphdr *)(datagram + sizeof(iphdr));

        memset(datagram, 0, 4096);

        ipHeader->ihl = 5;
        ipHeader->version = 4;
        ipHeader->tos = 0;
        ipHeader->tot_len = sizeof(iphdr) + sizeof(tcphdr);
        ipHeader->id = htons(getpid()); //
        ipHeader->frag_off = 0;
        ipHeader->ttl = 64;
        ipHeader->protocol = IPPROTO_TCP;
        ipHeader->check = 0;

        if (inet_pton(AF_INET, this->localIp, &ipHeader->saddr) != 1)
        {
            this->print_error_exit("Error, cannot translate the (source) IP address to packet!\n", 1);
        }
        if (inet_pton(AF_INET, this->targetIp.c_str(), &ipHeader->daddr) != 1)
        {
            this->print_error_exit("Error, cannot translate the (destination) IP address to packet!\n", 1);
        }

        //TCP Header
        tcpHeader->source = htons(1337);
        tcpHeader->dest = htons(port);
        tcpHeader->seq = htonl(rand());
        tcpHeader->ack_seq = 0;
        tcpHeader->doff = 5;
        tcpHeader->syn = 1;
        tcpHeader->window = htons(1337);
        tcpHeader->check = 0;
        tcpHeader->urg_ptr = 0;

        pseudo_header_csum_tcp psh;
        psh.sourceAddress = ipHeader->saddr;
        inet_pton(this->targetIpFamily, this->targetIp.c_str(), &psh.destinationAddress);
        psh.reserved = 0;
        psh.protocolType = IPPROTO_TCP;
        psh.length = htons(sizeof(struct tcphdr));

        memcpy(&psh.tcp, tcpHeader, sizeof(struct tcphdr));

        tcpHeader->check = csum((unsigned short *)&psh, sizeof(pseudo_header_csum_tcp));
    }
    else if (this->targetIpFamily == AF_INET6)
    {
        tcphdr *tcpHeader = (tcphdr *)(datagram);

        tcpHeader->source = htons(1337);
        tcpHeader->dest = htons(port);
        tcpHeader->seq = htonl(rand());
        tcpHeader->ack_seq = 0;
        tcpHeader->doff = sizeof(tcphdr) / 4; //Size of tcp in 32b words
        tcpHeader->syn = 1;
        tcpHeader->window = htons(1337);
        tcpHeader->check = 0;
        tcpHeader->urg_ptr = 0;
    }
    return datagram;
}

// Method creates the TCP (RST) filter for pcap.
//
pcap_t *Scanner::create_tcp_rst_sniffer()
{
    char *device, errorBuffer[PCAP_ERRBUF_SIZE];
    device = pcap_lookupdev(errorBuffer);

    if (device == NULL)
    {
        this->print_error_exit("Error, no ethernet device!\n", 1);
    }

    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);

    pcap_t *sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
    if (sniffHandler == NULL)
    {
        cout << errorBuffer;
        this->print_error_exit("Error, cannot open listening device!\n", 1);
    }

    struct bpf_program packetFilter;

    string packetFilterString;

    if(this->targetIpFamily == AF_INET)
    {
        packetFilterString = "tcp[tcpflags] & (tcp-rst) != 0 and src " + this->targetIp;
    }
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
    char *device, errorBuffer[PCAP_ERRBUF_SIZE];
    device = pcap_lookupdev(errorBuffer);

    if (device == NULL)
    {
        this->print_error_exit("Error, no ethernet device!\n", 1);
    }

    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    pcap_lookupnet(device, &ip, &subnetMask, errorBuffer);

    pcap_t *sniffHandler = pcap_open_live(device, BUFSIZ, 1, -1, errorBuffer);
    if (sniffHandler == NULL)
    {
        cout << errorBuffer;
        this->print_error_exit("Error, cannot open listening device!\n", 1);
    }

    struct bpf_program packetFilter;

    string packetFilterString;

    if(this->targetIpFamily == AF_INET)
    {
        packetFilterString = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 or tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-rst) = 0 and src " + this->targetIp;
    }
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

// Method sends tcp packets to server
void Scanner::send_tcp_packets()
{
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
    if (tcpSocket == -1)
    {
        this->print_error_exit("Error, cannot create socket!\n", 1);
    }

    if (this->wasInterface)
    {
        setsockopt(tcpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
    }

    char *tcpPacket;
    for (unsigned index = 0; index < this->tcpTargetPorts.size(); index++)
    {
        tcpPortStates = TCP_FILTERED;

        cout << tcpTargetPorts[index] << "/tcp      ";

        // IPV4
        if (this->targetIpFamily == AF_INET)
        {
            tcpPacket = this->create_tcp_syn_packet(tcpTargetPorts[index]);

            struct sockaddr_in socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            socketAddress.sin_family = this->targetIpFamily;
            socketAddress.sin_port = htons(tcpTargetPorts[index]);

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr);
            if ((sendto(tcpSocket, tcpPacket, sizeof(iphdr) + sizeof(tcphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress))) < 0)
            {
                this->print_error_exit("Error, cannot send TCP packet!\n", 1);
            }
        }
        // IPV6
        else
        {
            int opt = 16;
            if (setsockopt(tcpSocket, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)) < 0)
            {
                this->print_error_exit("Error, cannot calculate the checksum for IPV6(TCP)!\n", 1);
            }

            tcpPacket = this->create_tcp_syn_packet(tcpTargetPorts[index]);

            struct sockaddr_in6 socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            socketAddress.sin6_port = 0;
            socketAddress.sin6_family = this->targetIpFamily;

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin6_addr);
            if((sendto(tcpSocket, tcpPacket, sizeof(tcphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress))) < 0)
            {
                this->print_error_exit("Error, cannot send TCP packet!\n", 1);
            }
        }

        // Giving the port time to response
        sleep(this->tcpWaitTime);

        tcpLock.lock();
        // Printing out the result of port
        if (tcpPortStates == TCP_CLOSED)
        {
            cout << "close\n";
        }
        else if (tcpPortStates == TCP_OPEN)
        {
            cout << "open\n";
        }
        else
        {
            cout << "filtered\n";
        }
        tcpLock.unlock();

        // Free packet
        free(tcpPacket);
    }
    close(tcpSocket);

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

    if(this->targetIpFamily == AF_INET)
    {
        thread packetRstSniffer(&Scanner::start_rst_pcap_loop, this);
        thread packetSynAckSniffer(&Scanner::start_syn_ack_pcap_loop, this);
    
        this->send_tcp_packets();
        packetRstSniffer.join();
        packetSynAckSniffer.join();
    }
    else
    {
        thread packetRstSniffer(&Scanner::start_rst_ipv6_pcap_loop, this);
        thread packetSynAckSniffer(&Scanner::start_syn_ack_ipv6_pcap_loop, this);

        this->send_tcp_packets();
        packetRstSniffer.join();
        packetSynAckSniffer.join();
    }
}

void Scanner::prepare_and_start_tcp_scan()
{
    if (this->tcpTargetPorts.size() == 0)
    {
        return;
    }

    this->tcpRstFilterHolder = create_tcp_rst_sniffer();
    this->tcpSynAckFilterHolder = create_tcp_syn_ack_sniffer();
    this->start_tcp_scan();
}