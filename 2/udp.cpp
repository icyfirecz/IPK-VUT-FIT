// Project for subject Computer Communications and Networks
// TCP/UDP port scanner
// Author: Tomáš Sasák
// BUT FIT 2019

#include "ipk-scan.hpp"

bool wasClosed;

mutex udpLock;

void callback_udp(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Prevent Data race
    udpLock.lock();
    // ICMP 3 packet came, so port is closed
    wasClosed = true;
    udpLock.unlock();
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

        udpHeader->source = htons(1337);        // random number
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
    pcap_t *sniffHandler = NULL;
    char errorBuffer[PCAP_ERRBUF_SIZE];
        
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

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
            cerr << errorBuffer << endl;
            this->print_error_exit("Error, cannot open listening device!\n", 1);
        }
    }

    struct bpf_program packetFilter;

    string packetFilterString;
    if(this->targetIpFamily == AF_INET)
    {
        packetFilterString = "icmp[icmpcode]=3 and src " + this->targetIp;
    }
    else
    {
        packetFilterString = "icmp6 && ip6[40] == 1 and src " + this->targetIp;
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

    // If interface was given bind the socket to it
    if (this->wasInterface)
    {
        setsockopt(udpSocket, SOL_SOCKET, SO_BINDTODEVICE, this->interfaceName.c_str(), strlen(this->interfaceName.c_str()));
    }

    if(this->targetIpFamily == AF_INET)
    {
        const int option = 1;
        if(setsockopt(udpSocket, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option)) < 0)
        {
            this->print_error_exit("Error, cannot set the socket!\n", 1);
        }
    }
    else
    {
        const int option = UDP_CHECKSUM_OFFSET;
        if (setsockopt(udpSocket, IPPROTO_IPV6, IPV6_CHECKSUM, &option, sizeof(option)) < 0)
        {
            this->print_error_exit("Error, cannot calculate the checksum for IPV6(UDP)!\n", 1);
        }
    }
    
    // Restart the counter 
    int timesSent = 0;

    for (unsigned index = 0; index < this->udpTargetPorts.size(); index++)
    {
        // Restart the UDP state variable
        wasClosed = false;

        char *udpPacket = this->create_udp_packet(udpTargetPorts[index]);

        // IPV4
        if (this->targetIpFamily == AF_INET)
        {
            struct sockaddr_in socketAddress;

            // Set the destination, port and family 
            socketAddress.sin_family = this->targetIpFamily;
            socketAddress.sin_port = htons(udpTargetPorts[index]);

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin_addr);

            // Send packet
            if(sendto(udpSocket, udpPacket, sizeof(udphdr) + sizeof(iphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0)
            {
                this->print_error_exit("Error, cannot send UDP packet!\n", 1);
            }

            // Add timesSent counter
            timesSent++;
        }
        // IPV6
        else
        {
            struct sockaddr_in6 socketAddress;
            memset(&socketAddress, 0, sizeof(socketAddress));

            // Set the destination and family 
            socketAddress.sin6_port = 0;
            socketAddress.sin6_family = this->targetIpFamily;

            inet_pton(this->targetIpFamily, this->targetIp.c_str(), &socketAddress.sin6_addr);

            // Send packet
            if(sendto(udpSocket, udpPacket, sizeof(udphdr), 0, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) == -1)
            {
                printf("%d", errno);
                this->print_error_exit("Error, cannot send UDP packet!\n", 1);
            }

            timesSent++;
        }

        // Giving the port time to response
        sleep(this->icmpWaitTime);

        udpLock.lock();
        // Printing out the result of port
        if (wasClosed)
        {
            cout << udpTargetPorts[index] << "/udp      ";
            cout << "close\n";
            // Restart counter
            timesSent = 0;
        }
        else
        {
            if(timesSent != this->timesRepeatUdp)
            {
                index--; // Go back to the same port
                free(udpPacket); // Memory free
                udpLock.unlock(); // No deadlock
                continue; // Go agane
            }
            cout << udpTargetPorts[index] << "/udp      ";
            cout << "open\n";
            // Restart counter
            timesSent = 0;
        }
        udpLock.unlock();

        // Free packet
        free(udpPacket);
    }

    // Close UDP socket
    close(udpSocket);

    // Finish sniffing thread loop
    pcap_breakloop(this->updIcmpFilterHolder);
}

void Scanner::start_udp_scan()
{
    // Start sending thread
    thread packetSender(&Scanner::send_udp_packets, this);

    // Start sniffing
    pcap_loop(this->updIcmpFilterHolder, -1, callback_udp, NULL);

    packetSender.join();
}

void Scanner::prepare_and_start_udp_scan()
{
    // Nothing wants to be scanned
    if (this->udpTargetPorts.size() == 0)
    {
        return;
    }

    // Create the ICMP 3 filter
    this->updIcmpFilterHolder = this->create_udp_snifffer();

    // Start the scanning
    this->start_udp_scan();
}
