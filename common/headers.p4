header ticket_h {
    bit<8> opcode;
    bit<32> usr_id;
    bit<16> counter;
    bit<8>  ticket_req_num;
    bit<8>  ticket_type;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    arp_h arp;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    icmp_h icmp;
    ticket_h ticket;

    // Add more headers here.
}

struct empty_header_t {}

struct empty_metadata_t {}
