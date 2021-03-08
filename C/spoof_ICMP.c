// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>
#include <time.h>

#if defined _WIN32
// See at https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506(v=vs.85).aspx
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>

/*
* This was a surpise to me...  This stuff is not defined anywhere under MSVC.
* They were taken from the MSDN ping.c program and modified.
*/

#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0
#define IP_MAXPACKET 65535

#pragma pack(1)

struct ip
{
	UINT8   ip_hl : 4;          // length of the header
	UINT8   ip_v : 4;           // Version of IP
	UINT8   ip_tos;             // Type of service
	UINT16  ip_len;             // total length of the packet
	UINT16  ip_id;              // unique identifier of the flow
	UINT16  ip_off;				// fragmentation flags
	UINT8   ip_ttl;             // Time to live
	UINT8   ip_p;               // protocol (ICMP, TCP, UDP etc)
	UINT16  ip_sum;             // IP checksum
	UINT32  ip_src;
	UINT32  ip_dst;
};

struct icmp
{
	UINT8  icmp_type;
	UINT8  icmp_code;      // type sub code
	UINT16 icmp_cksum;
	UINT16 icmp_id;
	UINT16 icmp_seq;
	UINT32 icmp_data;      // time data
};

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

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);


#define SOURCE_IP "10.0.2.15"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

int main ()
{
 
    struct icmp icmphdr; // ICMP-header
    struct in_addr Pdest;
    inet_aton(DESTINATION_IP, &Pdest);
    char data[IP_MAXPACKET] = "This is the ping.\n";
	
	
    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai
    icmphdr.icmp_code = 0;
    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
       // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet ), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    dest_in.sin_addr = Pdest;

    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    while(1) {
    
    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d"
#if defined _WIN32
			, WSAGetLastError()
#else
			, errno
#endif
			);
        return -1;
    }
    
    struct timespec startTime={0,0}, endTime={0,0};
    struct icmphdr rcv_hdr;
        int slen = 0;
        
        clock_gettime(CLOCK_MONOTONIC_RAW, &startTime);
        
	int rc = recvfrom(sock, data, sizeof data, 0, NULL, &slen);
        if (rc <= 0) {
            perror("recvfrom");

        } else if (rc < sizeof rcv_hdr) {
            printf("Error, got short ICMP packet, %d bytes\n", rc);
        } else {
            printf("packet recieved:\n");
            struct icmp *icmp = (struct icmp *)(data + sizeof(struct ip)); //convert the data to icmp structure for extracting the relevant data, in the packet we "skipping" the ip data to the icmp
            printf("	ICMP type %d\n",icmp->icmp_type);    
            printf("	ICMP code %d\n",icmp->icmp_code); 
            printf("	ICMP chksum  %d\n",icmp->icmp_cksum); 
            printf("	ICMP id %d\n",icmp->icmp_id); 
            printf("	ICMP seq %d\n",icmp->icmp_seq);

            clock_gettime(CLOCK_MONOTONIC_RAW, &endTime);
            
            uint64_t end_n = (endTime.tv_sec*1000000000) + endTime.tv_nsec;
            uint64_t start_n = (startTime.tv_sec*1000000000) + startTime.tv_nsec;
            
	    double nanoSeconds = end_n-start_n; 
	    
            break;
        }
    
    
  // Close the raw socket descriptor.
  close(sock);

	}
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
