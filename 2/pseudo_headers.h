// props to: https://www.slashroot.in/how-is-tcp-and-udp-checksum-calculated
// https://github.com/renatoaloi/EtherEncLib/blob/master/checksum.c
struct pseudo_header_csum_tcp
{
    unsigned int sourceAddress;
    unsigned int destinationAddress;
    unsigned char reserved;
    unsigned char protocolType;
    unsigned short length;
     
    tcphdr tcp;
};

struct pseudo_header_csum_udp
{
    unsigned int sourceAddress;
    unsigned int destinationAddress;
    unsigned char reserved;
    unsigned char protocolType;
    unsigned short length;
     
    udphdr udp;
};

struct pseudo_header_ipv4
{
    unsigned int sourceAddress;
    unsigned int destinationAddress;
    unsigned char reserved;
    unsigned char protocolType;
    unsigned short length;
};