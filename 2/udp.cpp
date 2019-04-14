#include "ipk-scan.hpp"

bool wasClosed;

void callback_udp(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    wasClosed = true;
}

char* Scanner::create_udp_packet(int port)
{
    char *datagram = (char *)malloc(4096);
    memset(datagram, 0, 4096);

    if (this->targetIpFamily == AF_INET)
    {
        udphdr *udpHeader = (udphdr *)(datagram + sizeof(iphdr));

        iphdr *ipHeader = (iphdr *)(datagram);

        ipHeader->version = 4;                              // IPV4
        ipHeader->ihl = 5;                                  // sizeof ip packet / 4
        ipHeader->tos = 0;                                  // no service
        ipHeader->tot_len = sizeof(iphdr) + sizeof(udphdr); // sending udp packet
        ipHeader->id = htons(8);                            // random number
        ipHeader->frag_off = 0;                             // 0 fragmentation first packet
        ipHeader->ttl = 64;                                 // 64 hops to live
        ipHeader->protocol = IPPROTO_UDP;                   // udp header is after this
        ipHeader->check = 0;                                // let kernel calculate the checksum

        if (inet_pton(AF_INET, this->targetIp.c_str(), &ipHeader->daddr) != 1)
        {
            this->print_error_exit("Error, cannot create IP packet (destination address)!\n", 1);
        }

        if (inet_pton(AF_INET, this->localIp, &ipHeader->saddr) != 1)
        {
            this->print_error_exit("Error, cannot create IP packet (source address)!\n", 1);
        }

        pseudo_header_ipv4 pseudoIp;
        pseudoIp.destinationAddress = ipHeader->daddr;
        pseudoIp.protocolType = IPPROTO_UDP;
        pseudoIp.length = sizeof(iphdr);
        pseudoIp.reserved = 0;
        pseudoIp.sourceAddress = ipHeader->saddr;

        ipHeader->check = csum((unsigned short *)&pseudoIp, sizeof(pseudo_header_ipv4));

        udpHeader->source = htons(2132);        // random number
        udpHeader->len = htons(sizeof(udphdr)); // sending just header
        udpHeader->dest = htons(port);          // scanned port
        udpHeader->check = 0;                   // kernel will fill
    }

    else if (this->targetIpFamily == AF_INET6)
    {
        udphdr *udpHeader = (udphdr *)(datagram);

        udpHeader->source = htons(1337);    // random number
        udpHeader->len = htons(sizeof(udphdr)); // sending just header
        udpHeader->dest = htons(port);          // scanned port
        udpHeader->check = 0;                   // kernel will fill in
    }

    return datagram;
}

pcap_t* Scanner::create_udp_snifffer()
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

    string packetFilterString = "icmp[icmpcode]=3 and src " + this->targetIp;

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

void Scanner::send_udp_packets()
{
    int udpSocket;
    // Socket binding to IPV4
    if (this->targetIpFamily == AF_INET)
    {
        udpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    // IPV6
    else if (this->targetIpFamily == AF_INET6)
    {
        udpSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    }

    if (udpSocket == -1)
    {
        this->print_error_exit("Error, cannot create socket!\n", 1);
    }

    if (this->wasInterface)
    {
        setsockopt(udpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
    }


    for (unsigned index = 0; index < this->udpTargetPorts.size(); index++)
    {
        wasClosed = false;

        char *udpPacket = this->create_udp_packet(udpTargetPorts[index]);

        cout << udpTargetPorts[index] << "/udp      ";

        // IPV4
        if (this->targetIpFamily == AF_INET)
        {
            const int option = 1;
            if(setsockopt(udpSocket, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option)) < 0)
            {
                this->print_error_exit("Error, cannot set the socket!\n", 1);
            }

            struct sockaddr_in socketAddress;

            socketAddress.sin_family = this->targetIpFamily;
            socketAddress.sin_port = htons(udpTargetPorts[index]);

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr);

            if(sendto(udpSocket, udpPacket, sizeof(udphdr) + sizeof(iphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0)
            {
                this->print_error_exit("Error, cannot send UDP packet!\n", 1);
            }
        }
        // IPV6
        else
        {
            int opt = 6;
            if (setsockopt(udpSocket, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)) < 0)
            {
                this->print_error_exit("Error, cannot calculate the checksum for IPV6(UDP)!\n", 1);
            }

            struct sockaddr_in6 socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            socketAddress.sin6_port = 0;
            socketAddress.sin6_family = this->targetIpFamily;

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin6_addr);

            if(sendto(udpSocket, udpPacket, sizeof(udphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) == -1)
            {
                printf("%d", errno);
                this->print_error_exit("Error, cannot send UDP packet!\n", 1);
            }
        }

        // Giving the port time to response
        sleep(this->icmpWaitTime);

        // Printing out the result of port
        if (wasClosed)
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

void Scanner::start_udp_scan()
{
    thread packetSender(&Scanner::send_udp_packets, this);

    pcap_loop(this->updIcmpFilterHolder, -1, callback_udp, NULL);

    packetSender.join();
}

void Scanner::prepare_and_start_udp_scan()
{
    if (this->udpTargetPorts.size() == 0)
    {
        return;
    }

    this->updIcmpFilterHolder = this->create_udp_snifffer();

    this->start_udp_scan();
}
