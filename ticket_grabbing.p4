/*******************************************************************************
 * P4 SOURCE CODE FOR TICKET GRABBING 
 * version 2022.10.25.22.01
 ******************************************************************************/
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "common/headers.p4"

#define ID_WIDTH 32
#define BF_INDEX_HASH_LEN 14
#define BF_SIZE 65536
#define MAX_TICKET 1000
#define BF_INDEX_WIDTH 16

typedef bit<16> ticket_port_t;
const ticket_port_t TICKET_PORT = 123;

#define USER_KEY  hdr.ticket.usr_id

const bit<3> RESUB = 3w1;

header resubmit{
    bit<16>  counter;
    bit<48>  padding;
}
struct bloomfilter_chain_metadata_t {
    bit<8> nextnode_flag;
    bit<8> valid_user_flag1;
    bit<8> valid_user_flag2;
    bit<8> valid_user_flag3;
    bit<8> nextnode_flag2;

    bit<8> valid_user_flag2_1;
    bit<8> valid_user_flag2_2;
    bit<8> valid_user_flag2_3;
    bit<8> nextnode_flag3;

    bit<8> valid_user_flag3_1;
    bit<8> valid_user_flag3_2;
    bit<8> valid_user_flag3_3;

    bit<8> bypass_flag;
    bit<8> bypass_flag2;
    bit<32> user_id;

    bit<ID_WIDTH> bf_result11;
    bit<ID_WIDTH> bf_result12;
    bit<ID_WIDTH> bf_result21;
    bit<ID_WIDTH> bf_result22;
    bit<ID_WIDTH> bf_result31;
    bit<ID_WIDTH> bf_result32;
    bit<BF_INDEX_WIDTH> hash_field11;
    bit<BF_INDEX_WIDTH> hash_field12;
    bit<BF_INDEX_WIDTH> hash_field21;
    bit<BF_INDEX_WIDTH> hash_field22;
    bit<BF_INDEX_WIDTH> hash_field31;
    bit<BF_INDEX_WIDTH> hash_field32;
}
struct metadata_t {
    bloomfilter_chain_metadata_t md_fc;
    resubmit r;
}



// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser TofinoIngressParser(
        packet_in pkt,
        inout metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        pkt.extract(ig_md.r);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select (hdr.udp.dst_port){
            TICKET_PORT : parse_ticket;
            default : reject;
        }

    }
    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
    state parse_ticket {
        pkt.extract(hdr.ticket);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Resubmit() resubmit;
    apply {
        if (ig_dprsr_md.resubmit_type == RESUB) {
            resubmit.emit(ig_md.r);
        }
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Register<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>>(BF_SIZE,0) bf_11;
    RegisterAction<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>,bit<ID_WIDTH>>(bf_11) bf_11_op = {
        void apply(inout bit<ID_WIDTH> val, out bit<ID_WIDTH> rv) {
            rv = val;//return 0:no conflict; this ID:privous flow; another ID: conflict
            if(val == 0){
                val = hdr.ticket.usr_id;
            }else{}
        }
    };

    Register<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>>(BF_SIZE,0) bf_21;
    RegisterAction<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>,bit<ID_WIDTH>>(bf_21) bf_21_op = {
        void apply(inout bit<ID_WIDTH> val, out bit<ID_WIDTH> rv) {
            rv = val;//return 0:no conflict; this ID:privous flow; another ID: conflict
            if(val == 0){
                val = hdr.ticket.usr_id;
            }else{}
        }
    };
    
    Register<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>>(BF_SIZE,0) bf_31;
    RegisterAction<bit<ID_WIDTH>,bit<BF_INDEX_WIDTH>,bit<ID_WIDTH>>(bf_31) bf_31_op = {
        void apply(inout bit<ID_WIDTH> val, out bit<ID_WIDTH> rv) {
            rv = val;//return 0:no conflict; this ID:privous flow; another ID: conflict
            if(val == 0){
                val = hdr.ticket.usr_id;
            }else{}
        }
    };


    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.IDENTITY) hash11;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.RANDOM) hash12;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CRC64) hash21;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CRC16) hash22;
    
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CRC64) hash13;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CRC16) hash14;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.IDENTITY) hash23;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.RANDOM) hash24;

    
    CRCPolynomial<bit<32>>(32w0xad0424f3,
                           true,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly3;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CUSTOM, poly3) hash31;

    CRCPolynomial<bit<32>>(32w0x973afb51,
                           false,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly4;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CUSTOM, poly4) hash32;

    CRCPolynomial<bit<32>>(32w0xad0454f3,
                           true,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly5;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CUSTOM, poly5) hash33;

    CRCPolynomial<bit<32>>(32w0x04C11DB7,
                           false,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly6;
    Hash<bit<BF_INDEX_WIDTH>>(HashAlgorithm_t.CUSTOM, poly6) hash34;


    action compute_hash11(){
        ig_md.md_fc.hash_field11 = hash11.get(USER_KEY);
    }
    action compute_hash12(){
        ig_md.md_fc.hash_field12 = hash12.get(USER_KEY);
    }
    action compute_hash21(){
        ig_md.md_fc.hash_field21 = hash21.get(USER_KEY);
    }
    action compute_hash22(){
        ig_md.md_fc.hash_field22 = hash22.get(USER_KEY);
    }
    action compute_hash31(){
        ig_md.md_fc.hash_field31 = hash31.get(USER_KEY);
    }
    action compute_hash32(){
        ig_md.md_fc.hash_field32 = hash32.get(USER_KEY);
    }

    action compute_hash11_r(){
        ig_md.md_fc.hash_field11 = hash13.get(USER_KEY);
    }
    action compute_hash12_r(){
        ig_md.md_fc.hash_field12 = hash14.get(USER_KEY);
    }
    action compute_hash21_r(){
        ig_md.md_fc.hash_field21 = hash23.get(USER_KEY);
    }
    action compute_hash22_r(){
        ig_md.md_fc.hash_field22 = hash24.get(USER_KEY);
    }
    action compute_hash31_r(){
        ig_md.md_fc.hash_field31 = hash33.get(USER_KEY);
    }
    action compute_hash32_r(){
        ig_md.md_fc.hash_field32 = hash34.get(USER_KEY);
    }


    Register<bit<16>,bit<8>>(256,0) flow_num_counter;
    RegisterAction<bit<16>, _, bit<16>>(flow_num_counter) flow_num_counter_op = {
        void apply(inout bit<16> val, out bit<16> rv) {
            if(val<=MAX_TICKET){
                val = val + 1;
            }
            rv=val;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(flow_num_counter) flow_num_read_op = {
        void apply(inout bit<16> val, out bit<16> rv) {
            rv=val;
        }
    };

    apply {
        if(ig_intr_md.resubmit_flag == 0){
            compute_hash11();
            compute_hash12();
            compute_hash21();
            compute_hash22();
            compute_hash31();
            compute_hash32();
        }
        if(ig_intr_md.resubmit_flag == 1){//change hash group for resubmit packet
            compute_hash11_r();
            compute_hash12_r();
            compute_hash21_r();
            compute_hash22_r();
            compute_hash31_r();
            compute_hash32_r();
        }

        //multi task support
        ig_md.md_fc.hash_field11[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];
        ig_md.md_fc.hash_field12[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];
        ig_md.md_fc.hash_field21[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];
        ig_md.md_fc.hash_field22[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];
        ig_md.md_fc.hash_field31[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];
        ig_md.md_fc.hash_field32[15:BF_INDEX_HASH_LEN] = hdr.ticket.ticket_type[15-BF_INDEX_HASH_LEN:0];

        //port-forward
        if(ig_intr_md.ingress_port == 142){
            ig_tm_md.ucast_egress_port = 141;
            ig_tm_md.bypass_egress = 1;
        }
        if(ig_intr_md.ingress_port == 141){
            ig_tm_md.ucast_egress_port = 142;
            ig_tm_md.bypass_egress = 1;
        }

        ig_md.md_fc.bf_result11 = bf_11_op.execute(ig_md.md_fc.hash_field11);
        ig_md.md_fc.bf_result12 = bf_11_op.execute(ig_md.md_fc.hash_field12);

        if(ig_md.md_fc.bf_result11 == 0 || ig_md.md_fc.bf_result12 == 0){
            ig_md.md_fc.valid_user_flag1 = 1;
        }
        else if(ig_md.md_fc.bf_result11 != hdr.ticket.usr_id && ig_md.md_fc.bf_result12 != hdr.ticket.usr_id){
            ig_md.md_fc.nextnode_flag = 1;
            ig_md.md_fc.valid_user_flag2 = 1;
        }
        if(ig_md.md_fc.bf_result11 == hdr.ticket.usr_id || ig_md.md_fc.bf_result12 == hdr.ticket.usr_id){
            ig_md.md_fc.valid_user_flag3 = 1;
            hdr.ticket.opcode=0b01000000;//ddos?
        }
       
        if(ig_md.md_fc.nextnode_flag == 1){
            ig_md.md_fc.bf_result21 = bf_21_op.execute(ig_md.md_fc.hash_field21);
            ig_md.md_fc.bf_result22 = bf_21_op.execute(ig_md.md_fc.hash_field22);
            if(ig_md.md_fc.bf_result21 == 0 || ig_md.md_fc.bf_result22 == 0){
                ig_md.md_fc.valid_user_flag2_1 = 1;
            }
            else if(ig_md.md_fc.bf_result21 != hdr.ticket.usr_id && ig_md.md_fc.bf_result22 != hdr.ticket.usr_id){
                ig_md.md_fc.nextnode_flag2 = 1;
                ig_md.md_fc.valid_user_flag2_2 = 1;
            }
            if(ig_md.md_fc.bf_result21 == hdr.ticket.usr_id || ig_md.md_fc.bf_result22 == hdr.ticket.usr_id){
                ig_md.md_fc.valid_user_flag2_3 = 1;
                hdr.ticket.opcode=0b01000000;//ddos?
            }
        }
  
        if(ig_md.md_fc.nextnode_flag2 == 1){
            ig_md.md_fc.bf_result31 = bf_31_op.execute(ig_md.md_fc.hash_field31);
            ig_md.md_fc.bf_result32 = bf_31_op.execute(ig_md.md_fc.hash_field32);
            if(ig_md.md_fc.bf_result31 == 0 || ig_md.md_fc.bf_result32 == 0){
                ig_md.md_fc.valid_user_flag3_1 = 1;
            }
            else if(ig_md.md_fc.bf_result31 != hdr.ticket.usr_id && ig_md.md_fc.bf_result32 != hdr.ticket.usr_id){
                ig_md.md_fc.nextnode_flag3 = 1;
                ig_md.md_fc.valid_user_flag3_2 = 1;
                ig_dprsr_md.resubmit_type = 3w1;
            }
            if(ig_md.md_fc.bf_result31 == hdr.ticket.usr_id || ig_md.md_fc.bf_result32 == hdr.ticket.usr_id){
                ig_md.md_fc.valid_user_flag3_3 = 1;
                hdr.ticket.opcode=0b01000000;//ddos?
            }
        }
        
        if(hdr.ticket.isValid()){
            if(ig_md.md_fc.valid_user_flag2_1 == 1 || ig_md.md_fc.valid_user_flag1 == 1 || ig_md.md_fc.valid_user_flag3_1==1){
                hdr.ticket.counter = flow_num_counter_op.execute(hdr.ticket.ticket_type);
                hdr.ticket.opcode=0b00010000;//pass, if ticket sold out, it will change in line 331
            }else if(ig_md.md_fc.nextnode_flag3 == 1 && ig_intr_md.resubmit_flag == 1){
                hdr.ticket.counter=ig_md.r.counter;
                hdr.ticket.opcode=0b00010000;
                ig_dprsr_md.resubmit_type = 0;
            }else if(ig_md.md_fc.nextnode_flag3 == 1 && ig_intr_md.resubmit_flag == 0){
                ig_md.r.counter = flow_num_read_op.execute(hdr.ticket.ticket_type);            
            }

            if(hdr.ticket.counter == MAX_TICKET+1){  
                hdr.ticket.opcode=0b00100000;//failed
            }

        }
    }
}


// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Switch Egress MAU
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    apply { }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
