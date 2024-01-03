#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_arp.h>


void process_arp_packet(struct rte_arp_hdr *arp_hdr, int port_id){
	if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {
		printf("Received ARP request on port %u\n", port_id);
	} else if(rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REPLY) {
		printf("Received ARP reply on port %u\n", port_id);
	}

	printf("Sender MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_hdr->arp_data.arp_sha.addr_bytes[0],
			arp_hdr->arp_data.arp_sha.addr_bytes[1],
			arp_hdr->arp_data.arp_sha.addr_bytes[2],
			arp_hdr->arp_data.arp_sha.addr_bytes[3],
			arp_hdr->arp_data.arp_sha.addr_bytes[4],
			arp_hdr->arp_data.arp_sha.addr_bytes[5]);
	printf("Sender IP address: %u.%u.%u.%u\n",
			(arp_hdr->arp_data.arp_sip >> 24) & 0xFF,
			(arp_hdr->arp_data.arp_sip >> 16) & 0xFF,
			(arp_hdr->arp_data.arp_sip >> 8) & 0xFF,
			arp_hdr->arp_data.arp_sip & 0xFF);
	printf("Dst MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_hdr->arp_data.arp_tha.addr_bytes[0],
			arp_hdr->arp_data.arp_tha.addr_bytes[1],
			arp_hdr->arp_data.arp_tha.addr_bytes[2],
			arp_hdr->arp_data.arp_tha.addr_bytes[3],
			arp_hdr->arp_data.arp_tha.addr_bytes[4],
			arp_hdr->arp_data.arp_tha.addr_bytes[5]);
	printf("Dst IP address: %u.%u.%u.%u\n",
			(arp_hdr->arp_data.arp_tip >> 24) & 0xFF,
			(arp_hdr->arp_data.arp_tip >> 16) & 0xFF,
			(arp_hdr->arp_data.arp_tip >> 8) & 0xFF,
			arp_hdr->arp_data.arp_tip & 0xFF);
}

void process_ipv4_packet(struct rte_ipv4_hdr *ipv4_hdr, int port_id){
	printf("Received IPv4 packet on port %u\n", port_id);
	printf("Source IP: %u.%u.%u.%u\n",
			(ipv4_hdr->src_addr >> 24) & 0xFF,
			(ipv4_hdr->src_addr >> 16) & 0xFF,
			(ipv4_hdr->src_addr >> 8) & 0xFF,
			ipv4_hdr->src_addr & 0xFF);

	printf("Destination IP: %u.%u.%u.%u\n",
			(ipv4_hdr->dst_addr >> 24) & 0xFF,
			(ipv4_hdr->dst_addr >> 16) & 0xFF,
			(ipv4_hdr->dst_addr >> 8) & 0xFF,
			ipv4_hdr->dst_addr & 0xFF);
}

void process_ipv6_packet(struct rte_ipv6_hdr *ipv6_hdr, int port_id){
	printf("Received IPv6 packet on port %u\n", port_id);
	char src_ip_str[INET6_ADDRSTRLEN];
	char dst_ip_str[INET6_ADDRSTRLEN];
	
	inet_ntop(AF_INET6, &(ipv6_hdr->src_addr), src_ip_str, sizeof(src_ip_str));
	inet_ntop(AF_INET6, &(ipv6_hdr->dst_addr), dst_ip_str, sizeof(dst_ip_str));

	printf("Source IP: %s\n", src_ip_str);
	printf("Destination IP: %s\n", dst_ip_str);
}

void process_vlan_packet(struct rte_vlan_hdr *vlan_hdr, int port_id){
	printf("Received VLAN packet on port %u\n", port_id);
	// rte_be16_t vlan_tci;  /**< Priority (3) + CFI (1) + Identifier Code (12) */
 	
    uint16_t vlan_id = rte_be_to_cpu_16(vlan_hdr->vlan_tci) & 0xFFF;
    uint16_t ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);

    switch (ether_type) {
        case RTE_ETHER_TYPE_IPV4: {
			printf("ipv4 in vlan\n");
			process_ipv4_packet((struct rte_ipv4_hdr *)(vlan_hdr + 1), port_id);
            break;
        }
        case RTE_ETHER_TYPE_IPV6: {
			printf("ipv6 in vlan\n");
			process_ipv6_packet((struct rte_ipv6_hdr *)(vlan_hdr + 1), port_id);
            break;
        }
        case RTE_ETHER_TYPE_ARP: {
			printf("arp in vlan\n");
			process_arp_packet((struct rte_arp_hdr *)(vlan_hdr + 1), port_id);
            break;
        }
        default:
			printf("receive other type packet protocl_type = %x\n", ether_type);
            break;
    }
}

void process_packet(struct rte_mbuf * buf, int port_id){
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	printf("Src MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth_hdr->src_addr.addr_bytes[0],
			eth_hdr->src_addr.addr_bytes[1],
			eth_hdr->src_addr.addr_bytes[2],
			eth_hdr->src_addr.addr_bytes[3],
			eth_hdr->src_addr.addr_bytes[4],
			eth_hdr->src_addr.addr_bytes[5]);

	printf("Dest MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			eth_hdr->dst_addr.addr_bytes[0],
			eth_hdr->dst_addr.addr_bytes[1],
			eth_hdr->dst_addr.addr_bytes[2],
			eth_hdr->dst_addr.addr_bytes[3],
			eth_hdr->dst_addr.addr_bytes[4],
			eth_hdr->dst_addr.addr_bytes[5]);

	switch(rte_be_to_cpu_16(eth_hdr->ether_type)){
		case RTE_ETHER_TYPE_ARP:
			process_arp_packet((struct rte_arp_hdr*)(eth_hdr+1), port_id);
			break;
		case RTE_ETHER_TYPE_IPV4:
			process_ipv4_packet((struct rte_ipv4_hdr *)(eth_hdr+1), port_id);
			break;
		case RTE_ETHER_TYPE_IPV6:
			process_ipv6_packet((struct rte_ipv6_hdr *)(eth_hdr+1), port_id);
			break;
		case RTE_ETHER_TYPE_VLAN:
			process_vlan_packet((struct rte_vlan_hdr *)(eth_hdr+1), port_id);
			break;
		default:
			printf("receive other type packet protocl_type = %x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
			break;
	}
}
