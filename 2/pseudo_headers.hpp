// TCP pseudoheader structure for calculating the checksum
struct pseudo_header_csum_tcp
{
    unsigned int sourceAddress;
    unsigned int destinationAddress;
    unsigned char reserved;
    unsigned char protocolType;
    unsigned short length;
     
    tcphdr tcp;
};