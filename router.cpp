/*Serban Andra 321CA*/

#include "./include/skel.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdio.h>
#include <algorithm>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <queue>
#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))
#define BROADCAST_ADDRES "FF:FF:FF:FF:FF:FF"
#define UNKNOWN_ADRESS "00:00:00:00:00"
using namespace std;

// structura pentru fiecare entry din tabela de rutare
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

// structura pentru fiecare entry din tabela arp
struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
};

// tabela de rutare
vector<route_table_entry> rtable;
// tabela arp
vector<arp_entry> arp_table;

/* Sortez tabela de ruatre, pentru a face cautare binara*/ 
bool sortByPrefix(route_table_entry arpEntry, route_table_entry entry2) {
	if (arpEntry.prefix == entry2.prefix) {
		return arpEntry.mask > entry2.mask;
	}
	return arpEntry.prefix < entry2.prefix;
}

/*Functie pentru citirea tabelei de rutare:
Citesc intrarile sub forma de stringuri, iar apoi le copiez intr-un vector de 
char-uri, pe care aplic functia convert ip -> decimal (inet_addr) si apoi
adaugat intrarea in tabela de rutare
*/
void read_rtable() {

	ifstream fin ("rtable.txt");
	string prefix, next_hop, mask;
	int interface;

	while (fin >> prefix >> next_hop >> mask >> interface) {

		struct route_table_entry entry;
		int n = prefix.length();
		char prefix_array[n + 1];
		strcpy(prefix_array, prefix.c_str());
		n = next_hop.length();
		char next_hop_array[n + 1];
		strcpy(next_hop_array, next_hop.c_str());
		n = mask.length();
		char mask_array[n + 1];
		strcpy(mask_array, mask.c_str());

		entry.prefix = inet_addr(prefix_array);
		entry.next_hop = inet_addr(next_hop_array);
		entry.mask = inet_addr(mask_array);
		entry.interface = interface;
		rtable.push_back(entry);
	}

	sort(rtable.begin(), rtable.end(), sortByPrefix);
	fin.close();
}

/*Functie pentru citirea tabelei arpEntry folositoare pentru o tabela arpEntry statica*/
void parse_arpTable() {
	ifstream fin("arp_table.txt");
	string ip, mac;
	while (fin >> ip >> mac) {
		int n = ip.length();
		char ip_array[n + 1];
		strcpy(ip_array, ip.c_str());
		int m = mac.length();
		char mac_array[m + 1];
		strcpy(mac_array, mac.c_str());
		struct arp_entry entry;
		entry.ip = inet_addr(ip_array);
		hwaddr_aton(mac_array, entry.mac);
		arp_table.push_back(entry);

	}
}

/*Folosind cautarea binara se  obtine cea mai buna ruta spre destinatie.
Pentru cazul in care routerul nu are drum spre destinatie se intoarce NULL */
struct route_table_entry *get_best_route(uint32_t dest_ip) {

	int current_index = -1;
	for (int i = 0; i < rtable.size(); i++) {
		if ((ntohl(dest_ip) & ntohl(rtable[i].mask)) == ntohl(rtable[i].prefix)) {
			if (ntohl(rtable[i].mask) > ntohl(rtable[current_index].mask)) {
				current_index = i;
			}
		}
	}
	if (current_index != -1) {
		return &rtable[current_index];
	}
	return NULL;
}

/*
Functia returneaza adresa intrarii din tabela arpEntry cu ip-ul primti
*/
struct arp_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table.size(); i++) {
		if (ntohl(arp_table[i].ip) == ntohl(ip)) {
			return &arp_table[i];
		}
	}
    return NULL;
}


/*Functie pentru calcul checksum */
uint16_t checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint64_t acc=0xffff;
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}

/* Functia convertIp face conversia ip -> decimal*/
uint32_t convertIp(u_char arp_spa[]) {
	return inet_addr((const char*)arp_spa);
}


void sendEchoReply(packet m) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
	int interfaceReceivedPacket = m.interface;
	uint32_t routerIpAdress = inet_addr(get_interface_ip(interfaceReceivedPacket));
	/* Completez header-ul ip
	Pentru ca pachetul trimis va fii tip echoReply modific adresele ip astfel:
	ipDestinatie <- ipSursa
	ipSursa <- ipRouter */
	ip_hdr->version = 4;
	ip_hdr->ihl = 5; 
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(m.len - sizeof(struct ether_header));
	ip_hdr->daddr = (uint32_t)(ip_hdr->saddr);
	ip_hdr->saddr = inet_addr(get_interface_ip(interfaceReceivedPacket));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, 20);

	/*Completez header-ul icmp, setand type-ul corespunzator */
	icmp_hdr->un.echo.id = htons(getpid() & 0xFFFF);
	icmp_hdr->type = ICMP_ECHOREPLY;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, 8);

	/*Actualizez adresele mac din header-ul ethernet si lungimea pachetului*/
	std::copy(std::begin(eth_hdr->ether_shost), std::end(eth_hdr->ether_shost), 
		std::begin(eth_hdr->ether_dhost));
	get_interface_mac(interfaceReceivedPacket, (uint8_t*)&eth_hdr->ether_shost);
	m.len = sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr);

	send_packet(interfaceReceivedPacket, &m);
}


void sendIcmpPacket(packet m, int type) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
	int interfaceReceivedPacket = m.interface;
	/* Completez header-ul ip
	Pentru ca pachetul trimis va fii tip echoReply modific adresele ip astfel:
	ipDestinatie <- ipSursa
	ipSursa <- ipRouter */
	ip_hdr->version = 4;
	ip_hdr->ihl = 5; 
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(iphdr) + sizeof(icmphdr));
	ip_hdr->daddr = (uint32_t)(ip_hdr->saddr);
	ip_hdr->saddr = inet_addr(get_interface_ip(interfaceReceivedPacket));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, 20);

	/*Completez header-ul icmp, setand type-ul corespunzator */
	icmp_hdr->un.echo.id = htons(getpid() & 0xFFFF);
	icmp_hdr->type = type;
	icmp_hdr->code = 0; 
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, 8);

	/*Actualizez adresele mac din header-ul ethernet si lungimea pachetului*/
	std::copy(std::begin(eth_hdr->ether_shost), std::end(eth_hdr->ether_shost), 
		std::begin(eth_hdr->ether_dhost));
	get_interface_mac(interfaceReceivedPacket, (uint8_t*)&eth_hdr->ether_shost);
	m.len = sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr);

	send_packet(interfaceReceivedPacket, &m);
}

void sendArpRequest(packet m, route_table_entry *entry) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
	struct ether_arp *arp_hdr = (ether_arp*)malloc(sizeof *arp_hdr);
	int interfaceToSendPacket = entry->interface;
	uint32_t routerIpAdress = inet_addr(get_interface_ip(interfaceToSendPacket));
	/*Pentru ca trimit un arp-request setez adresa mac atat din arp, cat si din 
	ether header ca  fiind adresa de broadcast, si completez restul campurilor
	din header-ul arp*/
	hwaddr_aton(UNKNOWN_ADRESS, (uint8_t *)&arp_hdr->arp_tha);
	memcpy(arp_hdr->arp_spa, &routerIpAdress, sizeof(routerIpAdress));
	arp_hdr->arp_op = ntohs(ARPOP_REQUEST);
	arp_hdr->arp_hrd = ntohs(1);
	arp_hdr->arp_pro = ntohs(0x800);
	arp_hdr->arp_hln = sizeof(arp_hdr->arp_sha);
	arp_hdr->arp_pln = sizeof(arp_hdr->arp_spa);
	get_interface_mac(entry->interface, (uint8_t*)&arp_hdr->arp_sha);
    memcpy(arp_hdr->arp_tpa, &ip_hdr->daddr, 4 * sizeof(uint8_t));
 	/*Actualizez mac-ul din ether-header cu mac-ul interfetei de pe care 
 	router-ul a primit pachetul*/
    get_interface_mac(entry->interface, (uint8_t*)&eth_hdr->ether_shost);
	hwaddr_aton(BROADCAST_ADDRES, eth_hdr->ether_dhost);
	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	memcpy(m.payload + sizeof(struct ether_header) , arp_hdr, 
		sizeof(struct ether_arp));

	send_packet(entry->interface, &m);
}

void sendPacketFromQueue(queue<packet> packetQueue, packet m) {
	packet *toSend = &packetQueue.front();
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct ether_arp *arp_hdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
	int interfaceReceivedPacket = m.interface;
	uint32_t routerIpAdress = inet_addr(get_interface_ip(interfaceReceivedPacket));
	struct ether_header *eth_hdr1 = (struct ether_header *)toSend->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(toSend->payload + IP_OFF);
	struct icmphdr *icm_hdr = (struct icmphdr *)(toSend->payload + IP_OFF + ICMP_OFF);

	/* Actualizez adresa mac a destinatiei*/
	memcpy(arp_hdr->arp_spa, &routerIpAdress, sizeof(routerIpAdress));
	std::copy(std::begin(eth_hdr->ether_shost), std::end(eth_hdr->ether_shost), 
		std::begin(eth_hdr1->ether_dhost));
	get_interface_mac(toSend->interface, (uint8_t*)&eth_hdr->ether_shost);

	struct route_table_entry *rtable_entry = get_best_route(ip_hdr->daddr);
	
	/*Adaug perechea ip-mac in tabela arp*/
	struct arp_entry arpEntry;
	std::copy(std::begin(arp_hdr->arp_sha), std::end(arp_hdr->arp_sha), 
		std::begin(arpEntry.mac));
	arpEntry.ip = ip_hdr->daddr;
	arp_table.push_back(arpEntry);

	send_packet(rtable_entry->interface, toSend);
}

void sendRequestReply(packet m) {
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	int interfaceReceivedPacket = m.interface;
	uint32_t routerIpAdress = inet_addr(get_interface_ip(
			interfaceReceivedPacket));
	struct ether_arp *arp_hdr;
			arp_hdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
	uint32_t ip_send_addr = *((uint32_t*) arp_hdr->arp_spa);
	uint32_t ip_dest_addr = *((uint32_t*) arp_hdr->arp_tpa);
	if (ip_dest_addr == routerIpAdress) {  
	/*Completez header-ul arp, setand ca type ARP_REPLY*/
		arp_hdr->arp_op = ntohs(ARPOP_REPLY);
		std::copy(std::begin(arp_hdr->arp_sha), std::end(arp_hdr->arp_sha), 
			std::begin(arp_hdr->arp_tha));
		std::copy(std::begin(arp_hdr->arp_spa), std::end(arp_hdr->arp_spa), 
			std::begin(arp_hdr->arp_tpa));
		get_interface_mac(interfaceReceivedPacket, (uint8_t*)&arp_hdr->arp_sha);
		memcpy(arp_hdr->arp_spa, &routerIpAdress, sizeof(routerIpAdress));

		/*Completez header-ul ethernet, setand ca type ARP si actualizez lungimea
		pachetului*/
		eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
		std::copy(std::begin(eth_hdr->ether_shost), std::end(eth_hdr->ether_shost), 
			std::begin(eth_hdr->ether_dhost));
		get_interface_mac(interfaceReceivedPacket, (uint8_t*)&eth_hdr->ether_shost);
		m.len = sizeof(ether_header) + sizeof(ether_arp);

		send_packet(interfaceReceivedPacket, &m);
	}
}
int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init();
	read_rtable();
	queue<packet> packetQueue;
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		int interfaceReceivedPacket = m.interface;
		uint32_t routerIpAdress = inet_addr(get_interface_ip(
			interfaceReceivedPacket));

		// verific type-ul din header-ul ethernet
		if (htons(eth_hdr->ether_type) == ETHERTYPE_ARP) {   
			struct ether_arp *arp_hdr;
			arp_hdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
			if (htons(arp_hdr->arp_op) == ARPOP_REQUEST) {
			send_packet(interfaceReceivedPacket, &m);
				/*Daca packetul este de tp arp request, raspund cu un packet de 
				contine mac-ul router-ului*/
				sendRequestReply(m);
			continue;
			} else if (htons(arp_hdr->arp_op) == ARPOP_REPLY) {
				/*In cazul in care pachetul primit este de tip arp reply, trimit 
				ultimul pachet din coada */
				sendPacketFromQueue(packetQueue, m);
				packetQueue.pop();
				continue;
			}
			continue;
		} else if (htons(eth_hdr->ether_type) == ETHERTYPE_IP) {
		
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
			uint32_t ip_dest_addr =  ip_hdr->daddr;

			/*  caluclez checksum-ul packetului, iar in cazul in care este 
			diferit de checksum-ul din packet ii dau drop */

			uint16_t oldChecksum = ip_hdr->check;
			ip_hdr->check = 0;
			if (oldChecksum != checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			} 
			/*Pentru pachetele primite care au time-to-live <= 1 trimit ca
			raspuns un pachet icmp-timeExceeded*/
			if (ip_hdr->ttl <= 1) {
					sendIcmpPacket(m, ICMP_TIME_EXCEEDED);
					continue;
			}
			/*In cazul in care pachetul drece de conditiile de mai sus si este
			adresat router-ului, trimit un pachet de tip EchoReply*/
			if (ip_dest_addr == routerIpAdress) {
					sendEchoReply(m);
					continue;
				
			} else {
				/*Daca pachetul nu este pentru router, caut cea mai buna
				ruta spre destinatie in tabela routarului */
				struct route_table_entry *rtable_entry = get_best_route(ip_hdr->daddr);
				/*Pentru destinatiile care nu se afla in tabela router-ului
				trimit sursei un pachet icmp-destinationUnreachable*/
				if (rtable_entry == NULL) {
					// sendDestUreachablePacket(m);
					sendIcmpPacket(m, ICMP_UNREACH);
					continue;
					
				} else {
					/*Pentru cazul in care se gaseste un drum spre destinatie
					pachetul este trimis next-hop-ului din tabela de  rutare*/
					/*Actualizez time-to-live si calculez checksum-ul pachetului*/
					ip_hdr->ttl--;
					ip_hdr->check = 0;
					ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
					struct arp_entry *arpEntry = get_arp_entry(rtable_entry->next_hop);
					if (arpEntry == NULL) {
						packetQueue.push(m);
						sendArpRequest(m, rtable_entry);
						continue;
					} else {
						/* Daca se gaseste in tabela arpEntry mac-ul destinatiei, 
						pachetul este trimis mai departe*/
						get_interface_mac(rtable_entry->interface, 
							(uint8_t*)&eth_hdr->ether_shost);
						memcpy(eth_hdr->ether_dhost, arpEntry->mac, 
							sizeof(arpEntry->mac));
						send_packet(rtable_entry->interface, &m);	
						continue;
					}
				}
			}	
		}	
		
	}
}
