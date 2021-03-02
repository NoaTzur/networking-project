#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6

#if defined _WIN32
// See at https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506(v=vs.85).aspx
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>

#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0
#define IP_MAXPACKET 65535
#pragma pack()


#else //  linux

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#endif


 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};
/*
struct icmp
{
UINT8  icmp_type;
UINT8  icmp_code;      // type sub code
UINT16 icmp_cksum;
UINT16 icmp_id;
UINT16 icmp_seq;
UINT32 icmp_data;      // time data
};
*/

#define IP_HL(ip)  ((ip->iph_ihl)&0x0f)

unsigned short calculate_checksum(unsigned short * paddress, int len);

int spoof_icmp_reply (const u_char *packet)
{

	struct ipheader *ip_h= (struct ipheader *)(packet + sizeof(struct ethheader));
	int ip_len = ntohs(ip_h->iph_len);
	
	char buff[ip_len];
	bzero(buff, sizeof(buff));
	memcpy(buff, (packet + sizeof(struct ethheader)), sizeof(buff));
	
	char *buff_p = buff;
	struct ipheader *new_ip_h= (struct ipheader *)(buff_p);
	
	int size_ip_header = IP_HL(new_ip_h)*4;
	
	
	
	struct icmp * icmp_h = (struct icmp*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
	icmp_h->icmp_type = 0;
	icmp_h->icmp_cksum =0;
	//icmp_h->icmp_cksum=calculate_checksum((unsigned short *) (buff + IP4_HDRLEN), ICMP_HDRLEN + datalen);
	
	struct in_addr temp_add = new_ip_h->iph_destip;
	new_ip_h->iph_destip=new_ip_h->iph_sourceip;
	new_ip_h->iph_sourceip=temp_add;
	
	
	struct sockaddr_in  dst;
	dst.sin_family = AF_INET;
	inet_pton(AF_INET, inet_ntoa(new_ip_h->iph_destip), &dst.sin_addr.s_addr);
	dst.sin_port = htons(0); //????????????
	
	int one =1;
	int s;
	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one,sizeof(one));
	sendto(s, buff, sizeof(buff), 0, (struct sockaddr *)&dst, sizeof(dst));
	close(s);
	
}
	

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   
    
    if(ip->iph_protocol == IPPROTO_ICMP){
    	printf("im an ICMP packet !!!\n");
    	spoof_icmp_reply(packet);
    	
   	 }
   else{
   	printf("not ICMP\n");
   }
    printf("\n");

    }
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";

  bpf_u_int32 net;
  char *myDEV= NULL;
	myDEV= pcap_lookupdev(errbuf); //this functions look for a device (NIC) on which to capture

	if (myDEV == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

  // Step 1: Open live pcap session on NIC 
  handle = pcap_open_live(myDEV, BUFSIZ, 1, 1000, errbuf); 
  
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

