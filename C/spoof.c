/*
Raw TCP packets
*/
#include <stdio.h> //for printf
#include <string.h> //memset
#include <sys/socket.h> //for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()

/*
96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/****************************************************************
  TCP checksum is calculated on the pseudo header, which includes 
  the TCP header and data, plus some part of the IP header. 
  Therefore, we need to construct the pseudo header first.
*****************************************************************/
#define PACKET_LEN  512
/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcphdr tcp;
        char payload[PACKET_LEN];
};

unsigned short calculate_checksum(unsigned short * paddress, int len);
unsigned short calculate_tcp_checksum(struct iphdr *ip);

int main (void)
{
	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;

	//zero out the packet buffer
	memset (datagram, 0, 4096);

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;

	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;


	//some address resolution
	strcpy(source_ip , "1.1.1.2");
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr ("8.8.8.8");

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + 6;
	iph->id = htonl (54321); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; //Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip ); //Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;

	//Ip checksum
	iph->check = calculate_checksum ((unsigned short *) datagram, iph->tot_len);//not neccesery

	//TCP Header
	tcph->source = htons (1234);
	tcph->dest = htons (80);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5; //tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840); /* maximum allowed window size */
	tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	//Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr)  );

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) ;
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) );

	tcph->check = calculate_tcp_checksum( (struct iphdr *) pseudogram);

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;

	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}


	//Send the packet
	if (sendto (s, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	//Data send successfully
	else
	{
		char str_dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(sin.sin_addr), str_dst, INET_ADDRSTRLEN);
		printf ("Packet length : %d \n" , iph->tot_len);
		printf ("Packet source ip : %s \n" , source_ip);
		printf ("Packet destination ip : %s \n" , str_dst);
		printf ("Packet ttl : %d \n" , iph->ttl);
		printf ("Packet id : %d \n" , iph->id);
		
	}
	// sleep for 1 seconds
	sleep(1);


	return 0;
}

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


/**********************************************
 * Listing 12.9: Calculating Internet Checksum
 **********************************************/

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

unsigned short calculate_tcp_checksum(struct iphdr *ip)
{
   struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + 
                            sizeof(struct iphdr));

   int tcp_len = ntohs(ip->tot_len) - sizeof(struct iphdr);

   /* pseudo tcp header for the checksum computation */
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

   p_tcp.saddr  = ip->saddr;
   p_tcp.daddr  = ip->daddr;
   p_tcp.mbz    = 0;
   p_tcp.ptcl   = IPPROTO_TCP;
   p_tcp.tcpl   = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp, 
                                     tcp_len + 12);
}

