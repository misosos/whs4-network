#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char *payload, int len) {
    if (len <= 0) {
        printf("    (Application 계층 데이터 없음 - 예: SYN/ACK 등)\n");
        return;
    }
    printf("    Length : %d bytes\n", len);
    printf("    -------------------- Message --------------------\n");
    for (int i = 0; i < len; i++) {
        u_char c = payload[i];
        if (isprint(c) || c == '\r' || c == '\n' || c == '\t')
            putchar(c);
        else
            putchar('.');
    }
    printf("\n    -------------------------------------------------\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    (void)args;

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {            // IP
        struct ipheader *ip = (struct ipheader *)
                              (packet + sizeof(struct ethheader));

        int ip_header_len = ip->iph_ihl * 4;           // IP 헤더 길이 (가변)

        switch (ip->iph_protocol) {                    // TCP 만 처리
            case IPPROTO_TCP: {
                struct tcpheader *tcp = (struct tcpheader *)
                                        ((u_char *)ip + ip_header_len);

                int tcp_header_len = TH_OFF(tcp) * 4;  // TCP 헤더 길이 (가변)

                // payload = IP 전체길이 - IP헤더 - TCP헤더
                int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
                const u_char *payload = (const u_char *)tcp + tcp_header_len;

                int remain = (int)header->caplen - (int)(payload - packet);
                if (payload_len < 0)      payload_len = 0;
                if (payload_len > remain) payload_len = remain;

                printf("====================================================\n");
                printf("[Ethernet Header]\n");
                printf("    Src MAC : "); print_mac(eth->ether_shost);
                printf("    Dst MAC : "); print_mac(eth->ether_dhost);

                printf("[IP Header]\n");
                printf("    Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
                printf("    Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

                printf("[TCP Header]\n");
                printf("    Src Port : %u\n", ntohs(tcp->tcp_sport));
                printf("    Dst Port : %u\n", ntohs(tcp->tcp_dport));

                printf("[HTTP Message]\n");
                print_payload(payload, payload_len);

                printf("\n");
                fflush(stdout);
                return;
            }
            default:
                return;                                // UDP/ICMP 등 무시
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // 인터페이스 이름은 환경에 맞게 변경 (ifconfig / ip -br link 로 확인)
    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
        fprintf(stderr, "-> sudo 로 실행했는지, 인터페이스 이름이 맞는지 확인하세요.\n");
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
