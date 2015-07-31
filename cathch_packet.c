#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <linux/sched.h>
#include <netinet/ip.h> 
#include <sys/types.h>  
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
    int * id = (int *)arg;
    int i;
    struct iphdr *ip;
    struct in_addr ip2;
    const u_char *buf,*iphead;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct ether_header *ethernet;
    char *a1, *a2;

    ip=(struct iphdr*)(packet+14);
    
    printf("id: %d\n", ++(*id));  
    printf("Packet length: %d\n", pkthdr->len);  
    printf("Number of bytes: %d\n", pkthdr->caplen);  
    printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));   
    
    //printf("--------------------------------line:%d,function:%s-------------------------",__LINE__,__FUNCTION__);
    printf("Source address:%s\n",inet_ntoa (*(struct in_addr *)&ip->saddr));
    printf("Destination address:%s\n",inet_ntoa (*(struct in_addr *)&ip->daddr));
    
    /*sourceIP->s_addr=ip->saddr;
    destnationIP->s_addr=ip->daddr;
    
    printf("Source address:%x\n",inet_ntoa(sourceIP->s_addr));
    printf("Destination address:%s\n",inet_ntoa(destnationIP->s_addr));*/
    
    
    //if(ntohs(ethernet->ether_type)==ETHERTYPE_IP)
    
    //printf("Source address:%x\n",ip->saddr);
    //printf("Destination address:%x\n",ip->daddr);

    if(ip->protocol==6)
    {
        tcp=(struct tcphdr*)(packet+14+20);
        printf("Source Port:%d\n",ntohs(tcp->source));
        printf("Destination Port:%d\n",ntohs(tcp->dest));
        printf("Sequence Number:%u\n",tcp->ack_seq);
    }
    else if(ip->protocol==17)
    {
        udp=(struct udphdr*)(packet+14+20);
        printf("Source port:%d\n",ntohs(udp->source));
        printf("Destination port:%d\n",ntohs(udp->dest));
    }
  /*
  for(i=0; i<pkthdr->len; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  } 
  */ 
    
    printf("\n\n");  
}  


int main(void)
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    
    /* get a device */  
    //devStr = pcap_lookupdev(errBuf);
    
    devStr="br-lan";
    
    if(devStr)  
    {  
        printf("success: device: %s\n", devStr);  
    }  
    else  
    {  
        printf("error: %s\n", errBuf);  
        exit(1);  
    }  
    
    /* open a device, wait until a packet arrives */  
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
    if(!device)  
    {  
        printf("error: pcap_open_live(): %s\n", errBuf);  
        exit(1);  
    }  
    
    /* wait a packet to arrive */  
    struct pcap_pkthdr packet;
    const u_char * pktStr = pcap_next(device, &packet);  
    
    if(!pktStr)  
    {  
        printf("did not capture a packet!\n");  
        exit(1);  
    }  
    
    /*printf("Packet length: %d\n", packet.len);  
    printf("Number of bytes: %d\n", packet.caplen);  
    printf("Recieved time: %s\n", ctime((const time_t *)&packet.ts.tv_sec)); */
    
    int id = 0;  

    pcap_loop(device, -1, getPacket, (u_char*)&id);   
    
    pcap_close(device);  
    
    return 0;  
    
    //system("tcpdump -nn -i br-lan > test");
}
