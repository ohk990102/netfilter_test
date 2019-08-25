#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <libnet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "ASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#define GOTOIFN(cond, msg, label, exit_code)\
if(!(cond)) {\
    fprintf(stderr, "ASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    goto label;\
}

#ifdef DEBUG
#define DASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "DASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#define DEBUG_PRINT(fmt, ...) printf("DEBUG PRINT [%s:%d]: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DASSERT(...) {}
#define DEBUG_PRINT(...) {}
#endif

#define MIN_HTTP_REQUEST_SIZE   24
#define MAX_ITER                20

char *HTTP_METHODS[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
size_t LEN_HTTP_METHODS[] = {3, 4, 4, 3, 6, 7};

char *URL = "";
size_t LEN_URL = 0;
char *BUF_TO_CMP = NULL;
size_t LEN_BUF_TO_CMP = 0;

void exception_handler(int code) {
    system("iptables -F");
    exit(-1);
}
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    int id, ret;
    unsigned char *payload;
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
        if(ph->hw_protocol != htons(ETHERTYPE_IP))
            goto PASS;
    }

    hwph = nfq_get_packet_hw(nfa);
    
    ret = nfq_get_payload(nfa, &payload);
    if(ret >= 0) {

        // Parse IPv4 Packet
        struct libnet_ipv4_hdr *view_ip = (struct libnet_ipv4_hdr *)payload;
        if(view_ip->ip_p != IPPROTO_TCP)
            goto PASS;

        if(ret != ntohs(view_ip->ip_len) || ret < ((view_ip->ip_hl) * sizeof(uint32_t))) {
            DEBUG_PRINT("Wrong IPv4 Packet Size\n");
            goto PASS;
        }
        payload += ((view_ip->ip_hl) * sizeof(uint32_t));
        ret -= ((view_ip->ip_hl) * sizeof(uint32_t));
        struct libnet_tcp_hdr *view_tcp = (struct libnet_tcp_hdr *)payload;
        if(view_tcp->th_dport != htons(80))
            goto PASS;
        
        if(ret < (view_tcp->th_off * sizeof(uint32_t))) {
            DEBUG_PRINT("Wrong TCP Packet Size\n");
            goto PASS;
        }
        payload += (view_tcp->th_off * sizeof(uint32_t));
        ret -= (view_tcp->th_off * sizeof(uint32_t));

        bool found = false;
        if(ret < MIN_HTTP_REQUEST_SIZE)
            goto PASS;
        
        for(int i = 0; i < sizeof(HTTP_METHODS); i++) {
            if(memcmp(payload, HTTP_METHODS[i], LEN_HTTP_METHODS[i]) == 0) {
                found = true;
                break;
            }
        }
        if(!found)
            goto PASS;
        
        void *pos = payload;
        size_t length = ret;
        found = false;
        
        for(int i = 0; i < MAX_ITER; i++) {
            void *end = memchr(pos, '\n', length);
            if(end == NULL)
                break;
            if(end - pos < 2)
                break;
            if(end + 1 - pos < LEN_BUF_TO_CMP) {
                length -= end - pos + 1;
                pos = end + 1;
                continue;
            }
            if(memcmp(pos, BUF_TO_CMP, LEN_BUF_TO_CMP) == 0) {
                printf("Block\n");
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            length -= end - pos + 1;
            pos = end + 1;
        }
        DEBUG_PRINT("Pass\n");
    }
PASS:  
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char *argv[]) {
    struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
    char buf[4096] __attribute__ ((aligned));
    int ret;
    int fd;
	int rv;
    int exit_code = 0;

    if(argc < 2) {
        printf("Usage: %s [Host]\n", argv[0]);
        printf("Host: Host to ban (ex: gilgil.net)\n");
        exit(-1);
    }
    signal(SIGINT, exception_handler);

    ret = system("iptables -F");
    ASSERT(ret == 0, "failed flushing chains");
    ret = system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    ASSERT(ret == 0, "append to output chain");
    ret = system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    GOTOIFN(ret == 0, "append to input chain", __EXIT_1, -1);

    h = nfq_open();
    GOTOIFN(h != NULL, "error during nfq_open()", __EXIT_1, -1);

    ret = nfq_unbind_pf(h, AF_INET);
    GOTOIFN(ret == 0, "error during nfq_unbind_pf()", __EXIT_2, -1);

    ret = nfq_bind_pf(h, AF_INET);
    GOTOIFN(ret == 0, "error during nfq_bind_pf()", __EXIT_2, -1);

    qh = nfq_create_queue(h,  0, &callback, NULL);
	GOTOIFN(qh != NULL, "error during nfq_create_queue()", __EXIT_3, -1);

    ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    GOTOIFN(ret == 0, "can't set packet_copy mode", __EXIT_4, -1);

    fd = nfq_fd(h);

    URL = argv[1];
    LEN_URL = strlen(URL);

    LEN_BUF_TO_CMP = strlen("Host: \r\n") + LEN_URL;
    BUF_TO_CMP = malloc(LEN_BUF_TO_CMP + 1);
    GOTOIFN(BUF_TO_CMP != NULL, "malloc failed", __EXIT_4, -1);
    snprintf(BUF_TO_CMP, LEN_BUF_TO_CMP + 1, "Host: %s\r\n", URL);
    DEBUG_PRINT("BUF_TO_CMP => %s\n", BUF_TO_CMP);

    while(1) {
        if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
			DEBUG_PRINT("losing packets");
			continue;
		}
        GOTOIFN(1, "failed sending packet", __EXIT_4, -1);
    }

__EXIT_4:
    nfq_destroy_queue(qh);
__EXIT_3:
    nfq_unbind_pf(h, AF_INET);
__EXIT_2:
    nfq_close(h);
__EXIT_1:
    ret = system("iptables -F");

    return exit_code;
}
