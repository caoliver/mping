/* Simple multihost ping for awakeness.  Report the names of the hosts
 * that respond.  Once we see that a host is up, assume it will stay
 * that way, and don't re-report it.  If we go IPV6 internally, this
 * will need rewriting.  Exit early with success if all desired hosts
 * respond.  Otherwise exit with failure when timeout is reached.
 * Invalid hosts are treated as failing to respond.
 *
 * Options:
 *
 *     -t <secs float> timeout for ping response.
 *     -c <secs float> number of pings to send over the time.
 *
 * Christopher Oliver - 10/21/2020
 */

#include <stdio.h>
#include <time.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <err.h>
#include <string.h>
#include <sys/select.h>
#include <getopt.h>
#include <fcntl.h>

#define TBLSIZ 256
#define MINWAIT 0.1
#define MAXWAIT 15
#define NS_PER_SEC 1000000000L

uint16_t ident;
int sock;

static inline uint16_t in_cksum(uint16_t *addr, int len)
{
    uint32_t sum = 0;

    for (; len > 1; len -= 2)
	sum += *addr++;
    if( len == 1 )
	sum += *(uint8_t *)addr;
    sum =  (sum >> 16) + (sum & 0xffff);
    return ~(sum + (sum >> 16));
}


struct nameaddr {
    char *name;
    struct sockaddr_in addr;
    bool already_seen;
} hosttbl[TBLSIZ];

int tbllen;

uint32_t nonce;

uint16_t reported;

static inline bool report_replies_until_abstime(struct timespec *deadline)
{
    while (1) {
	struct timespec delay;
	clock_gettime(CLOCK_REALTIME, &delay);
	delay.tv_sec = deadline->tv_sec - delay.tv_sec;
	if ((delay.tv_nsec = deadline->tv_nsec - delay.tv_nsec) < 0) {
	    delay.tv_sec--;
	    delay.tv_nsec += NS_PER_SEC;
	}
	if (delay.tv_sec < 0 || delay.tv_sec == 0 && delay.tv_nsec < 0)
	    return false;
	fd_set read_set;
	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	int rc = pselect(sock+1, &read_set, NULL, NULL, &delay, NULL);
	if (rc < 0) perror("");
	if (rc == 1) {
	    uint8_t packet[32];
	    ssize_t actual = recv(sock, packet, 32, 0);
	    struct icmp *icp = (struct icmp *)&packet[20];
	    uint32_t *recvnonce = (uint32_t *)&packet[28];
	    if (actual == 32 &&
		icp->icmp_type == ICMP_ECHOREPLY &&
		icp->icmp_id == ident &&
		*recvnonce == nonce) {
		uint16_t hostix = ntohs(icp->icmp_seq);
		if (hostix >= tbllen || hosttbl[hostix].already_seen)
		    continue;
		puts(hosttbl[hostix].name);
		hosttbl[hostix].already_seen = true;
		if (++reported == tbllen)
		    return true;
	    }
	}
    }
}

static inline void ping_all_unseen()
{
    uint8_t outbuf[12];
    struct icmp *icp = (struct icmp *)outbuf;
    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_id = ident;
    *(uint32_t *)&outbuf[8] = nonce;

    for (int ix = 0; ix < tbllen; ix++) {
	if (!hosttbl[ix].already_seen) {
	    icp->icmp_cksum = 0;
	    icp->icmp_seq = htons(ix);
	    icp->icmp_cksum = in_cksum((uint16_t *)outbuf, 12);
	    sendto(sock, (uint8_t *)icp, 12, 0,
		   (struct sockaddr *)&hosttbl[ix].addr,
		   sizeof(struct sockaddr_in));
	}
    }
}

int main(int argc, char *argv[])
{
    int opt;
    ident = getpid() & 0xFFFF;
    float wait = 2;
    int count = 2;
    bool bad_host = false;

    while ((opt = getopt(argc, argv, "c:t:")) != -1)
	switch (opt) {
	case 'c':
	    count = atoi(optarg);
	    break;
	case 't':
	    wait = atof(optarg);
	    break;
	default:
	    fprintf(stderr,
		    "Usage: %s [-t timeout] [-c ping_count] host ...\n",
		    argv[0]);
	    exit(1);
	}

    // Requires root or CAP_NET_RAW
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	err(1, NULL);

    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd > -1) {
	read(rfd, &nonce, 4);
	close(rfd);
    }

    if (count < 1) count = 1;
    wait = wait < MINWAIT ? MINWAIT : wait > MAXWAIT ? MAXWAIT : wait;

    float ping_delta = wait/count;
    
    for (int i = optind; i < argc; i++) {
	if (tbllen == TBLSIZ)
	    errx(1, "Too many hosts");
	hosttbl[tbllen].name = argv[i];
	struct hostent *hp = gethostbyname(argv[i]);
	if (!hp) {
	    bad_host = true;
	    continue;
	}
	hosttbl[tbllen].addr.sin_family = hp->h_addrtype;
	memcpy(&hosttbl[tbllen].addr.sin_addr, hp->h_addr, hp->h_length);
	tbllen++;
    }

    if (tbllen == 0)
	return bad_host ? 1 : 0;
    
    struct timespec start;
    clock_gettime(CLOCK_REALTIME, &start);
    
    for (int i = 0; i < count; i++) {
	ping_all_unseen();
	struct timespec deadline = start;
	double deadline_delta = (i+1)*ping_delta;
	int delta_sec = deadline_delta;
	deadline.tv_nsec += NS_PER_SEC * (deadline_delta - delta_sec);
	deadline.tv_sec += delta_sec;
	if (deadline.tv_nsec > NS_PER_SEC) {
	    deadline.tv_nsec -= NS_PER_SEC;
	    deadline.tv_sec++;
	}
	if (report_replies_until_abstime(&deadline))
	    return bad_host ? 1 : 0;
    }

    return 1;
}
