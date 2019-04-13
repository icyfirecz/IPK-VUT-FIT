
typedef struct ipv_6hdr {
    unsigned int ver:4;
    unsigned int traf_cl:8;
    unsigned int flow:20;
    unsigned int len:16;
    unsigned int nxt_hdr:8;
    unsigned int hop_lim:8;
    unsigned char a_src[16];
    unsigned char a_dst[16];
}ipv6hdr;