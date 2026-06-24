/* =====================================================================
 *  sniff.c  --  libpcap 패킷 스니퍼 (교육용)
 *
 *  강의 제공 skeleton(sniff_improved.c) 구조를 따르며, 과제 요구사항을 채움:
 *    - Ethernet Header : src MAC / dst MAC
 *    - IP Header       : src IP  / dst IP
 *    - TCP Header      : src port / dst port
 *    - HTTP Message    : Application 계층 payload
 *
 *  TCP 만 처리 (UDP/ICMP 등은 무시).
 *  IP/TCP 헤더의 "길이 필드"로 payload 위치/크기를 계산.
 *
 *  빌드 : gcc -Wall -o sniff sniff.c -lpcap
 *  실행 : sudo ./sniff
 * ===================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>   /* ntohs(), inet_ntoa() */
#include <ctype.h>       /* isprint() */

/* =====================================================================
 *  헤더 구조체 (강의 제공 myheader.h 중, 이 프로그램이 사용하는 것만 인라인)
 * ===================================================================== */

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

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

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

/* =====================================================================
 *  유틸리티
 * ===================================================================== */

/* MAC 주소 출력 (xx:xx:xx:xx:xx:xx) */
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Application 계층 payload(HTTP Message) 출력
 *  - 출력 가능 문자 / \r \n \t 는 그대로, 그 외는 '.' 로 치환
 *  - HTTPS(443) 등 암호화 트래픽은 깨진 문자로 보이는 게 정상 */
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

/* =====================================================================
 *  pcap 콜백
 * ===================================================================== */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  (void)args;  /* 사용 안 함 */

  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    /* [핵심] IP 헤더 길이는 가변: IHL 필드 * 4 (byte) */
    int ip_header_len = ip->iph_ihl * 4;

    /* determine protocol -- TCP 만 처리, 나머지(UDP/ICMP 등)는 무시 */
    switch (ip->iph_protocol) {
        case IPPROTO_TCP: {
            /* IP 헤더가 가변이므로 TCP 시작점 = IP 시작점 + ip_header_len */
            struct tcpheader *tcp = (struct tcpheader *)
                                    ((u_char *)ip + ip_header_len);

            /* [핵심] TCP 헤더 길이도 가변: data offset * 4 (byte) */
            int tcp_header_len = TH_OFF(tcp) * 4;

            /* [핵심] payload(HTTP) 위치/길이
             *  IP 전체 길이(iph_len) = IP헤더 + TCP헤더 + payload
             *  payload 길이 = iph_len - ip_header_len - tcp_header_len
             *  payload 시작 = TCP 시작점 + tcp_header_len               */
            int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
            const u_char *payload = (const u_char *)tcp + tcp_header_len;

            /* 실제 캡처된 바이트를 넘지 않도록 보정(잘린/오류 패킷 방어) */
            int remain = (int)header->caplen - (int)(payload - packet);
            if (payload_len < 0)      payload_len = 0;
            if (payload_len > remain) payload_len = remain;

            /* ---------- 출력 ---------- */
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
            /* UDP, ICMP, 기타 -> 무시 */
            return;
    }
  }
}

/* =====================================================================
 *  main
 * ===================================================================== */
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";   // TCP 만 캡처 (UDP 무시)
  bpf_u_int32 net = 0;

  // Step 1: NIC 에서 live 캡처 세션 오픈
  //         아래 인터페이스 이름("enp0s3")은 환경에 맞게 변경 ( ip link 로 확인 )
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
      fprintf(stderr, "-> sudo 로 실행했는지, 인터페이스 이름이 맞는지 확인하세요.\n");
      return EXIT_FAILURE;
  }

  // Step 2: filter_exp 를 BPF 코드로 컴파일 후 적용
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: 패킷 캡처 (cnt = -1 : 무한, 종료 Ctrl+C)
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   // 핸들 닫기
  return 0;
}
