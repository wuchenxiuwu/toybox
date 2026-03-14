/* map.c - Network port scanner with SYN/TCP/UDP/idle scan modes
 *
 * Copyright 2026 wuchenxiuwu <https://github.com/wuchenxiuwu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * As a special exception, the copyright holder gives permission to link
 * the code of this program with the OpenSSL library and distribute the
 * linked combination.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

USE_MAP(NEWTOY(map, "S(syn)U(udp)T(tcp)VbvrI:D:p:t#c#d#o:x:P(proxy):H(data):<1", TOYFLAG_USR|TOYFLAG_BIN))

config MAP
  bool "map"
  default n
  help
    GNU map 1.0.0, An interactive network tool

    Usage: map [OPTIONS] HOST

    Scan Types:
      -sS    SYN half-open scan (requires root)
      -sU    UDP scan (requires root)
      -sT    TCP connect scan (default)
      -sV    Version detection (send probes to identify services)
      -b     Banner grabbing (send specific probes to retrieve service banners)
      -I     Idle scan (zombie host:port, e.g., 192.168.1.5:80)

    Spoofing:
      -D     Decoy scan, comma-separated list of decoy IPs (e.g., 10.0.0.1,10.0.0.2)
      --proxy HTTP/SOCKS5 proxy (e.g., socks5://127.0.0.1:1080)

    Payload:
      --data Hexadecimal string sent to each open port (e.g., "50494e47" for PING)

    Output:
      -oX    Output results in XML format to a file

    Common Options:
      -v     Verbose output (show closed/filtered ports)
      -r     Randomize port scan order
      -p     Port list/range (e.g., 1-1000 or 80,443,8080)
      -t     Connection/read timeout in seconds (default 2)
      -T     Number of threads (default 4)
      -d     Probe delay in milliseconds (default 0)
      -o     Text output file
      HOST   Target IP or hostname
*/

#define FOR_map
#include "toys.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <ctype.h>
#include <sys/stat.h>
#include <regex.h>
#include <stdatomic.h>

// OpenSSL support (compile-time optional, define HAVE_OPENSSL to enable HTTPS functionality)
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#endif

GLOBALS(
  char *I;
  char *D;
  char *p;
  long t;
  long c;
  long d;
  char *o;
  char *x;
  char *P;
  char *H;
)

// Result record structure
typedef struct {
  int port;
  char state[16];
  char service[64];
} port_result_t;

// Global configuration
typedef struct {
  char target_ip[INET_ADDRSTRLEN];
  int *port_list;
  int num_ports;
  int scan_type;                 // 0=TCP, 1=SYN, 2=UDP
  int do_banner;
  int do_version;
  int verbose;
  int randomize;
  int timeout_sec;
  int thread_count;
  int delay_ms;
  FILE *outfile;
  FILE *xmlfile;
  atomic_int stop;
  pthread_mutex_t print_mutex;
  pthread_mutex_t stats_mutex;
  int total_open;
  int total_closed;
  int total_filtered;

  // Decoy scan
  int decoy_count;
  struct in_addr *decoy_addrs;

  // Idle scan
  char *zombie_host;
  int zombie_port;
  struct in_addr zombie_ip;
  int idle_scan;

  // Proxy
  char *proxy_url;
  enum { PROXY_NONE, PROXY_HTTP, PROXY_SOCKS5 } proxy_type;
  char proxy_host[256];
  int proxy_port;

  // Custom payload
  char *payload_data;
  int payload_len;

  // Result storage
  port_result_t *results;
  int results_capacity;
  pthread_mutex_t results_mutex;
} global_config_t;

static global_config_t g_config;

// Thread data
typedef struct {
  int thread_id;
  int start_idx;
  int end_idx;
  int raw_sock;
} thread_data_t;

// Banner grabbing probes
typedef struct {
  int port;
  const char *probe;
} banner_probe_t;

static banner_probe_t banner_probes[] = {
  { 21,    "HELP\r\n" },
  { 22,    "\r\n" },
  { 23,    "\r\n" },
  { 25,    "HELO localhost\r\n" },
  { 80,    "HEAD / HTTP/1.0\r\n\r\n" },
  { 110,   "HELP\r\n" },
  { 111,   "\r\n" },
  { 143,   "HELP\r\n" },
  { 443,   "HEAD / HTTP/1.0\r\n\r\n" },
  { 445,   "\r\n" },
  { 465,   "\r\n" },
  { 993,   "HELP\r\n" },
  { 995,   "HELP\r\n" },
  { 3306,  "\r\n" },
  { 5432,  "\r\n" },
  { 6379,  "*1\r\n$4\r\nINFO\r\n" },
  { 8443,  "HEAD / HTTP/1.0\r\n\r\n" },
  { 8080,  "HEAD / HTTP/1.0\r\n\r\n" },
  { 27017, "\r\n" },
  { 0,     NULL }
};

// Version detection fingerprints
typedef struct {
  const char *service;
  int port;
  const char *probe;
  const char *pattern;
} service_fingerprint;

static service_fingerprint service_fingerprints[] = {
  { "http",    80,    "HEAD / HTTP/1.0\r\n\r\n",   "HTTP/1\\.[01]\\s+\\d{3}" },
  { "http",    8080,  "HEAD / HTTP/1.0\r\n\r\n",   "HTTP/1\\.[01]\\s+\\d{3}" },
  { "https",   443,   "HEAD / HTTP/1.0\r\n\r\n",   "HTTP/1\\.[01]\\s+\\d{3}" },
  { "https",   8443,  "HEAD / HTTP/1.0\r\n\r\n",   "HTTP/1\\.[01]\\s+\\d{3}" },
  { "ssh",     22,    "",                           "SSH-\\d+\\.\\d+" },
  { "ftp",     21,    "",                           "^220.*FTP" },
  { "smtp",    25,    "",                           "^220.*SMTP" },
  { "pop3",    110,   "",                           "^\\+OK" },
  { "imap",    143,   "",                           "^\\* OK" },
  { "mysql",   3306,  "",                           "mysql" },
  { "redis",   6379,  "*1\r\n$4\r\nINFO\r\n",      "\\$\\d+\\r\\n.*redis_version" },
  { "mongodb", 27017, "",                           "MongoDB" },
  { NULL,      0,     NULL,                         NULL }
};

#define IS_HTTPS_PORT(p) ((p) == 443 || (p) == 8443 || (p) == 465 || (p) == 993 || (p) == 995)

// ----------------------------- Helper functions ---------------------------------
static int parse_port_list(const char *arg, int **ports, int *count)
{
  char *copy = strdup(arg);
  char *token;
  int cap = 256;
  int *list = malloc(cap * sizeof(int));
  int n = 0;
  char *saveptr;

  for (token = strtok_r(copy, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
    int start, end;
    if (sscanf(token, "%d-%d", &start, &end) == 2) {
      if (start < 1) start = 1;
      if (end > 65535) end = 65535;
      if (start > end) continue;
      for (int p = start; p <= end; p++) {
        if (n >= cap) {
          cap *= 2;
          int *new_list = realloc(list, cap * sizeof(int));
          if (!new_list) {
            free(list);
            free(copy);
            error_exit("Out of memory parsing port list");
          }
          list = new_list;
        }
        list[n++] = p;
      }
    } else if (sscanf(token, "%d", &start) == 1) {
      if (start < 1 || start > 65535) {
        error_msg("Port %d out of range (1-65535), skipped", start);
        continue;
      }
      if (n >= cap) {
        cap *= 2;
        int *new_list = realloc(list, cap * sizeof(int));
        if (!new_list) {
          free(list);
          free(copy);
          error_exit("Out of memory parsing port list");
        }
        list = new_list;
      }
      list[n++] = start;
    }
  }
  free(copy);
  *ports = list;
  *count = n;
  return 0;
}

static void shuffle_ports(int *ports, int n)
{
  for (int i = n-1; i > 0; i--) {
    int j = rand() % (i+1);
    int tmp = ports[i];
    ports[i] = ports[j];
    ports[j] = tmp;
  }
}

static int parse_proxy_url(const char *url)
{
  char *p = NULL;
  if (strncmp(url, "http://", 7) == 0) {
    g_config.proxy_type = PROXY_HTTP;
    p = strdup(url + 7);
  } else if (strncmp(url, "socks5://", 9) == 0) {
    g_config.proxy_type = PROXY_SOCKS5;
    p = strdup(url + 9);
  } else {
    return -1;
  }
  char *colon = strchr(p, ':');
  if (!colon) {
    free(p);
    return -1;
  }
  *colon = '\0';
  strncpy(g_config.proxy_host, p, sizeof(g_config.proxy_host)-1);
  g_config.proxy_host[sizeof(g_config.proxy_host)-1] = '\0';
  g_config.proxy_port = atoi(colon+1);
  free(p);
  return 0;
}

static int proxy_connect_and_check(const char *host, int port)
{
  int sock = -1;
  int target_open = 0;

  if (g_config.proxy_type == PROXY_HTTP) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_config.proxy_port);
    inet_pton(AF_INET, g_config.proxy_host, &proxy_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
      close(sock); return -1;
    }
    char req[512];
    snprintf(req, sizeof(req), "CONNECT %s:%d HTTP/1.0\r\n\r\n", host, port);
    send(sock, req, strlen(req), 0);
    char resp[1024];
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    if (n <= 0) { close(sock); return -1; }
    resp[n] = '\0';
    int http_code = 0;
    if (sscanf(resp, "HTTP/1.%*d %d", &http_code) == 1) {
      if (http_code == 200) target_open = 1;
      else { close(sock); return 0; }
    } else { close(sock); return -1; }
  } else if (g_config.proxy_type == PROXY_SOCKS5) {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_config.proxy_port);
    inet_pton(AF_INET, g_config.proxy_host, &proxy_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
      close(sock); return -1;
    }
    unsigned char handshake[] = {0x05, 0x01, 0x00};
    send(sock, handshake, sizeof(handshake), 0);
    unsigned char resp[2];
    if (recv(sock, resp, 2, 0) != 2 || resp[0] != 0x05 || resp[1] != 0x00) {
      close(sock); return -1;
    }
    struct hostent *he = gethostbyname(host);
    if (!he) { close(sock); return -1; }
    unsigned char req[4 + 4 + 2] = {0x05, 0x01, 0x00, 0x01};
    memcpy(req+4, he->h_addr_list[0], 4);
    req[8] = (port >> 8) & 0xFF;
    req[9] = port & 0xFF;
    send(sock, req, sizeof(req), 0);
    unsigned char rsp[10];
    if (recv(sock, rsp, 10, 0) != 10) { close(sock); return -1; }
    if (rsp[1] == 0x00) target_open = 1;
    else { close(sock); return 0; }
  }
  if (sock != -1) close(sock);
  return target_open ? 1 : 0;
}

static int proxy_connect_for_banner(const char *host, int port)
{
    int sock = -1;

    if (g_config.proxy_type == PROXY_HTTP) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        struct sockaddr_in proxy_addr;
        proxy_addr.sin_family = AF_INET;
        proxy_addr.sin_port = htons(g_config.proxy_port);
        inet_pton(AF_INET, g_config.proxy_host, &proxy_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
            close(sock); return -1;
        }
        char req[512];
        snprintf(req, sizeof(req), "CONNECT %s:%d HTTP/1.0\r\n\r\n", host, port);
        send(sock, req, strlen(req), 0);
        char resp[1024];
        int n = recv(sock, resp, sizeof(resp)-1, 0);
        if (n <= 0) { close(sock); return -1; }
        resp[n] = '\0';
        int http_code = 0;
        if (sscanf(resp, "HTTP/1.%*d %d", &http_code) == 1) {
            if (http_code == 200) {
                return sock;
            } else {
                close(sock);
                return -1;
            }
        } else {
            close(sock);
            return -1;
        }
    } else if (g_config.proxy_type == PROXY_SOCKS5) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        struct sockaddr_in proxy_addr;
        proxy_addr.sin_family = AF_INET;
        proxy_addr.sin_port = htons(g_config.proxy_port);
        inet_pton(AF_INET, g_config.proxy_host, &proxy_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
            close(sock); return -1;
        }
        unsigned char handshake[] = {0x05, 0x01, 0x00};
        send(sock, handshake, sizeof(handshake), 0);
        unsigned char resp[2];
        if (recv(sock, resp, 2, 0) != 2 || resp[0] != 0x05 || resp[1] != 0x00) {
            close(sock); return -1;
        }
        struct hostent *he = gethostbyname(host);
        if (!he) { close(sock); return -1; }
        unsigned char req[4 + 4 + 2] = {0x05, 0x01, 0x00, 0x01};
        memcpy(req+4, he->h_addr_list[0], 4);
        req[8] = (port >> 8) & 0xFF;
        req[9] = port & 0xFF;
        send(sock, req, sizeof(req), 0);
        unsigned char rsp[10];
        if (recv(sock, rsp, 10, 0) != 10) { close(sock); return -1; }
        if (rsp[1] == 0x00) {
            return sock;
        } else {
            close(sock);
            return -1;
        }
    }
    return -1;
}

static unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
  long sum;
  unsigned short oddbyte;
  short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

static unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
  struct pseudo_header {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t tcp_len;
  } psh;
  char *pseudogram;
  int psize = sizeof(psh) + ntohs(ip->tot_len) - ip->ihl*4;

  psh.src_addr = ip->saddr;
  psh.dst_addr = ip->daddr;
  psh.zero = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_len = htons(ntohs(ip->tot_len) - ip->ihl*4);

  pseudogram = malloc(psize);
  memcpy(pseudogram, &psh, sizeof(psh));
  memcpy(pseudogram + sizeof(psh), tcp, psize - sizeof(psh));
  unsigned short sum = in_cksum((unsigned short *)pseudogram, psize);
  free(pseudogram);
  return sum;
}

static int send_syn_packet(int raw_sock, struct in_addr src, struct in_addr dst,
                           u_int16_t sport, u_int16_t dport, u_int32_t seq,
                           int window, int options)
{
  char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 40];
  struct iphdr *ip = (struct iphdr *)packet;
  struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
  int ip_len = sizeof(struct iphdr);
  int tcp_len = sizeof(struct tcphdr);

  char *optptr = (char *)(tcp + 1);
  if (options & 1) {
    *optptr++ = 2; *optptr++ = 4;
    uint16_t mss = htons(1460);
    memcpy(optptr, &mss, 2);
    optptr += 2;
    tcp_len += 4;
  }
  if (options & 2) {
    *optptr++ = 4; *optptr++ = 2;
    tcp_len += 2;
  }
  if (options & 4) {
    *optptr++ = 8; *optptr++ = 10;
    uint32_t ts_val = htonl(time(NULL));
    memcpy(optptr, &ts_val, 4);
    optptr += 4;
    uint32_t ts_ecr = 0;
    memcpy(optptr, &ts_ecr, 4);
    optptr += 4;
    tcp_len += 10;
  }
  if (options & 8) {
    *optptr++ = 3; *optptr++ = 3; *optptr++ = 7;
    tcp_len += 3;
  }
  while (tcp_len % 4) { *optptr++ = 1; tcp_len++; }

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = htons(ip_len + tcp_len);
  ip->id = htons(rand() % 65535);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->check = 0;
  ip->saddr = src.s_addr;
  ip->daddr = dst.s_addr;

  tcp->source = htons(sport);
  tcp->dest = htons(dport);
  tcp->seq = htonl(seq);
  tcp->ack_seq = 0;
  tcp->doff = tcp_len / 4;
  tcp->syn = 1;
  tcp->window = htons(window);
  tcp->check = 0;
  tcp->urg_ptr = 0;

  ip->check = in_cksum((unsigned short *)ip, ip_len);
  tcp->check = tcp_checksum(ip, tcp);

  struct sockaddr_in to;
  to.sin_family = AF_INET;
  to.sin_addr = dst;
  to.sin_port = htons(dport);

  if (sendto(raw_sock, packet, ip_len + tcp_len, 0,
             (struct sockaddr *)&to, sizeof(to)) < 0)
    return -1;
  return 0;
}

static int recv_syn_response(int raw_sock, struct in_addr dst, u_int16_t dport,
                             u_int16_t sport, u_int32_t seq, int timeout_sec,
                             int *flags, u_int32_t *ack_seq, u_int32_t *window,
                             struct in_addr *src_ip)
{
  fd_set fdset;
  struct timeval tv;
  char buffer[65536];
  struct iphdr *ip;
  struct tcphdr *tcp;
  int len;
  time_t start = time(NULL);

  while (!atomic_load(&g_config.stop)) {
    int elapsed = time(NULL) - start;
    int remaining = timeout_sec - elapsed;
    if (remaining <= 0) break;
    int select_timeout = (remaining > 1) ? 1 : remaining;

    FD_ZERO(&fdset);
    FD_SET(raw_sock, &fdset);
    tv.tv_sec = select_timeout;
    tv.tv_usec = 0;

    int sel = select(raw_sock + 1, &fdset, NULL, NULL, &tv);
    if (sel <= 0) continue;

    len = recv(raw_sock, buffer, sizeof(buffer), 0);
    if (len < (int)sizeof(struct iphdr)) continue;

    ip = (struct iphdr *)buffer;
    if (ip->protocol != IPPROTO_TCP) continue;
    if (ip->saddr != dst.s_addr) continue;
    if (ip->ihl*4 + (int)sizeof(struct tcphdr) > len) continue;

    tcp = (struct tcphdr *)(buffer + ip->ihl*4);
    if (ntohs(tcp->source) != dport) continue;
    if (ntohs(tcp->dest) != sport) continue;
    if (ntohl(tcp->ack_seq) != seq + 1) continue;

    *flags = 0;
    if (tcp->syn) *flags |= 0x01;
    if (tcp->ack) *flags |= 0x02;
    if (tcp->rst) *flags |= 0x04;
    if (tcp->fin) *flags |= 0x08;
    *ack_seq = ntohl(tcp->ack_seq);
    *window = ntohs(tcp->window);
    if (src_ip) src_ip->s_addr = ip->daddr;
    return 0;
  }
  return -1;
}

static int syn_scan_port(thread_data_t *td, int port, int *open, int *filtered,
                         struct in_addr *used_src)
{
  *open = 0;
  *filtered = 0;
  int raw_sock = td->raw_sock;
  struct in_addr dst;
  inet_aton(g_config.target_ip, &dst);
  struct in_addr src;
  u_int16_t sport = 20000 + (td->thread_id * 1000) + (port % 1000);
  u_int32_t seq = rand();
  int window = 14600;
  int options = 0x0F;

  if (g_config.decoy_count > 0) {
    int idx = rand() % (g_config.decoy_count + 1);
    if (idx < g_config.decoy_count) src = g_config.decoy_addrs[idx];
    else src.s_addr = INADDR_ANY;
  } else {
    src.s_addr = INADDR_ANY;
  }

  for (int retry = 0; retry < 3; retry++) {
    if (atomic_load(&g_config.stop)) return -1;
    if (send_syn_packet(raw_sock, src, dst, sport, port, seq, window, options) < 0) {
      if (retry == 2) return -1;
      usleep(100000);
      continue;
    }
    int flags;
    u_int32_t ack_seq, win;
    struct in_addr resp_dst;
    int res = recv_syn_response(raw_sock, dst, port, sport, seq,
                                 g_config.timeout_sec, &flags, &ack_seq, &win,
                                 &resp_dst);
    if (res == 0) {
      if (used_src) *used_src = resp_dst;
      if (flags & 0x04) return 1;
      else if (flags & 0x01 && flags & 0x02) { *open = 1; return 0; }
      else return 1;
    }
  }
  *filtered = 1;
  return 0;
}

static int get_ipid(int raw_sock, struct in_addr zombie_ip, int zombie_port)
{
  struct in_addr src;
  src.s_addr = INADDR_ANY;
  u_int16_t sport = 30000 + (rand() % 10000);
  u_int32_t seq = rand();
  if (send_syn_packet(raw_sock, src, zombie_ip, sport, zombie_port, seq, 1460, 0) < 0)
    return -1;

  fd_set fdset;
  struct timeval tv;
  char buffer[65536];
  struct iphdr *ip;
  struct tcphdr *tcp;
  int len;
  time_t start = time(NULL);
  while (!atomic_load(&g_config.stop) && time(NULL) - start < 2) {
    FD_ZERO(&fdset);
    FD_SET(raw_sock, &fdset);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(raw_sock+1, &fdset, NULL, NULL, &tv) <= 0) continue;
    len = recv(raw_sock, buffer, sizeof(buffer), 0);
    if (len < (int)sizeof(struct iphdr)) continue;
    ip = (struct iphdr *)buffer;
    if (ip->saddr != zombie_ip.s_addr) continue;
    if (ip->protocol != IPPROTO_TCP) continue;
    tcp = (struct tcphdr *)(buffer + ip->ihl*4);
    if (ntohs(tcp->source) != zombie_port) continue;
    if (ntohs(tcp->dest) != sport) continue;
    if (!tcp->rst) continue;
    return ntohs(ip->id);
  }
  return -1;
}

static int idle_scan_port(thread_data_t *td, int port, int *open)
{
  *open = 0;
  int raw_sock = td->raw_sock;
  struct in_addr dst;
  inet_aton(g_config.target_ip, &dst);
  struct in_addr zombie = g_config.zombie_ip;

  int ipid1 = get_ipid(raw_sock, zombie, g_config.zombie_port);
  if (ipid1 < 0) return -1;

  u_int16_t sport = 40000 + (td->thread_id * 1000) + (port % 1000);
  u_int32_t seq = rand();
  if (send_syn_packet(raw_sock, zombie, dst, sport, port, seq, 1460, 0) < 0)
    return -1;

  int ipid2 = get_ipid(raw_sock, zombie, g_config.zombie_port);
  if (ipid2 < 0) return -1;

  if (ipid2 == ipid1 + 1) { *open = 1; return 0; }
  else if (ipid2 == ipid1) { *open = 0; return 0; }
  else return -1;
}

static int udp_scan_port(thread_data_t *td, int port, int *open, int *filtered)
{
  *open = 0;
  *filtered = 0;
  int raw_sock = td->raw_sock;
  struct sockaddr_in addr;
  int sock;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return -1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

  struct timeval tv;
  tv.tv_sec = g_config.timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    perror_msg("setsockopt SO_SNDTIMEO");
    close(sock);
    return -1;
  }

  if (sendto(sock, "", 0, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sock);
    return -1;
  }

  fd_set fdset;
  char buffer[65536];
  struct iphdr *ip;
  struct icmphdr *icmp;
  struct iphdr *orig_ip;
  struct udphdr *orig_udp;
  int len;

  time_t start = time(NULL);
  while (!atomic_load(&g_config.stop)) {
    int elapsed = time(NULL) - start;
    int remaining = g_config.timeout_sec - elapsed;
    if (remaining <= 0) break;
    int select_timeout = (remaining > 1) ? 1 : remaining;

    FD_ZERO(&fdset);
    FD_SET(raw_sock, &fdset);
    tv.tv_sec = select_timeout;
    tv.tv_usec = 0;

    int sel = select(raw_sock + 1, &fdset, NULL, NULL, &tv);
    if (sel <= 0) continue;

    len = recv(raw_sock, buffer, sizeof(buffer), 0);
    if (len < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))) continue;

    ip = (struct iphdr *)buffer;
    if (ip->protocol != IPPROTO_ICMP) continue;
    if (ip->saddr != addr.sin_addr.s_addr) continue;

    icmp = (struct icmphdr *)(buffer + ip->ihl*4);
    if (icmp->type != 3 || icmp->code != 3) continue;

    orig_ip = (struct iphdr *)(buffer + ip->ihl*4 + sizeof(struct icmphdr));
    if (orig_ip->protocol != IPPROTO_UDP) continue;
    if (orig_ip->saddr != addr.sin_addr.s_addr) continue;

    orig_udp = (struct udphdr *)((char *)orig_ip + orig_ip->ihl*4);
    if (ntohs(orig_udp->dest) == port) {
      close(sock);
      return 1;
    }
  }

  close(sock);
  *filtered = 1;
  return 0;
}

static int tcp_connect_scan_port(int port, int *open)
{
  if (g_config.proxy_type != PROXY_NONE) {
    int result = proxy_connect_and_check(g_config.target_ip, port);
    if (result < 0) { *open = 0; return -1; }
    else if (result == 0) { *open = 0; return 0; }
    else { *open = 1; return 0; }
  }

  struct sockaddr_in addr;
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return -1;

  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

  connect(sock, (struct sockaddr *)&addr, sizeof(addr));

  fd_set fdset;
  struct timeval tv;
  FD_ZERO(&fdset);
  FD_SET(sock, &fdset);
  tv.tv_sec = g_config.timeout_sec;
  tv.tv_usec = 0;

  int res = select(sock + 1, NULL, &fdset, NULL, &tv);
  if (res <= 0) { close(sock); return -1; }

  socklen_t len = sizeof(int);
  int so_error;
  getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
  close(sock);
  *open = (so_error == 0);
  return 0;
}

// ----------------------------------------------------------------------
// Banner grabbing (separate SSL version)
// ----------------------------------------------------------------------

#ifdef HAVE_OPENSSL
static void ssl_banner_grab(int sock, int port, FILE *out)
{
    const char *probe = NULL;
    for (banner_probe_t *bp = banner_probes; bp->port != 0; bp++) {
        if (bp->port == port) {
            probe = bp->probe;
            break;
        }
    }
    if (!probe) probe = "\r\n";

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(sock);
        return;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }

    SSL_write(ssl, probe, strlen(probe));
    char buf[2048];
    int n = SSL_read(ssl, buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] < 32 && buf[i] != '\t' && buf[i] != '\r' && buf[i] != '\n')
                buf[i] = '?';
        }
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Banner: %s\n", buf);
        pthread_mutex_unlock(&g_config.print_mutex);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
}
#endif

static void tcp_banner_grab(int sock, int port, FILE *out)
{
    const char *probe = NULL;
    for (banner_probe_t *bp = banner_probes; bp->port != 0; bp++) {
        if (bp->port == port) {
            probe = bp->probe;
            break;
        }
    }
    if (!probe) probe = "\r\n";

    if (send(sock, probe, strlen(probe), 0) < 0) {
        close(sock);
        return;
    }
    char buf[2048];
    int n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n > 0) {
        buf[n] = '\0';
        for (int i = 0; i < n; i++) {
            if (buf[i] < 32 && buf[i] != '\t' && buf[i] != '\r' && buf[i] != '\n')
                buf[i] = '?';
        }
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Banner: %s\n", buf);
        pthread_mutex_unlock(&g_config.print_mutex);
    }
    close(sock);
}

static void banner_grab(int port, FILE *out)
{
    int sock = -1;

    if (g_config.proxy_type != PROXY_NONE) {
        sock = proxy_connect_for_banner(g_config.target_ip, port);
        if (sock < 0) return;
    } else {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return;

        struct timeval tv;
        tv.tv_sec = g_config.timeout_sec;
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            perror_msg("setsockopt timeout");
            close(sock);
            return;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(sock);
            return;
        }
    }

#ifdef HAVE_OPENSSL
    if (IS_HTTPS_PORT(port)) {
        ssl_banner_grab(sock, port, out);
    } else
#endif
    {
        tcp_banner_grab(sock, port, out);
    }
}

// ----------------------------------------------------------------------
// Version detection (separate SSL version + proxy-specific version detection)
// ----------------------------------------------------------------------

static void proxy_version_detection(FILE *out)
{
    const char *test_host = "httpbin.org";
    const int test_port = 80;

    pthread_mutex_lock(&g_config.print_mutex);
    fprintf(out ? out : stdout, "  [Proxy probe] Testing proxy %s:%d ...\n",
            g_config.proxy_host, g_config.proxy_port);
    pthread_mutex_unlock(&g_config.print_mutex);

    int sock = proxy_connect_for_banner(test_host, test_port);
    if (sock < 0) {
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Proxy error: cannot connect to test site via proxy\n");
        pthread_mutex_unlock(&g_config.print_mutex);
        return;
    }

    char req[512];
    snprintf(req, sizeof(req),
        "GET /get HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: map-probe/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        test_host);

    if (send(sock, req, strlen(req), 0) < 0) {
        close(sock);
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Proxy error: failed to send test request\n");
        pthread_mutex_unlock(&g_config.print_mutex);
        return;
    }

    char buf[8192];
    int n = recv(sock, buf, sizeof(buf)-1, 0);
    close(sock);

    if (n <= 0) {
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Proxy error: no response received\n");
        pthread_mutex_unlock(&g_config.print_mutex);
        return;
    }
    buf[n] = '\0';

    char *header_end = strstr(buf, "\r\n\r\n");
    if (!header_end) header_end = strstr(buf, "\n\n");
    if (!header_end) {
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(out ? out : stdout, "  └─ Proxy error: invalid response format\n");
        pthread_mutex_unlock(&g_config.print_mutex);
        return;
    }

    char *body = header_end + (header_end[1] == '\n' ? 2 : 4);
    char *headers = buf;
    *header_end = '\0';

    char proxy_type_str[64] = "unknown";
    char anonymity[64] = "unknown";

    if (strcasestr(headers, "Via:")) {
        strcpy(proxy_type_str, "HTTP proxy");
    } else if (g_config.proxy_type == PROXY_HTTP) {
        strcpy(proxy_type_str, "HTTP proxy (possibly transparent)");
    } else if (g_config.proxy_type == PROXY_SOCKS5) {
        strcpy(proxy_type_str, "SOCKS5 proxy");
    }

    if (strcasestr(headers, "X-Forwarded-For:") ||
        strcasestr(headers, "X-Real-IP:") ||
        strcasestr(headers, "Forwarded:")) {
        strcpy(anonymity, "transparent (leaks client IP)");
    } else {
        char *origin = strstr(body, "\"origin\": \"");
        if (origin) {
            origin += 11;
            char *end = strchr(origin, '"');
            if (end) *end = '\0';
            strcpy(anonymity, "anonymous (hides client IP)");
        } else {
            strcpy(anonymity, "unknown");
        }
    }

    pthread_mutex_lock(&g_config.print_mutex);
    fprintf(out ? out : stdout, "  └─ Proxy type: %s\n", proxy_type_str);
    fprintf(out ? out : stdout, "  └─ Anonymity level: %s\n", anonymity);
    char *server = strcasestr(headers, "Server:");
    if (server) {
        server += 7;
        while (*server == ' ') server++;
        char *nl = strchr(server, '\r');
        if (!nl) nl = strchr(server, '\n');
        if (nl) *nl = '\0';
        fprintf(out ? out : stdout, "  └─ Server: %s\n", server);
    }
    pthread_mutex_unlock(&g_config.print_mutex);
}

#ifdef HAVE_OPENSSL
static void ssl_version_detection(int port, FILE *out)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

    for (service_fingerprint *fp = service_fingerprints; fp->service; fp++) {
        if (fp->port != 0 && fp->port != port) continue;

        int sock = -1;
        if (g_config.proxy_type != PROXY_NONE) {
            sock = proxy_connect_for_banner(g_config.target_ip, port);
            if (sock < 0) continue;
        } else {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) return;

            struct timeval tv;
            tv.tv_sec = g_config.timeout_sec;
            tv.tv_usec = 0;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                perror_msg("setsockopt timeout");
                close(sock);
                return;
            }

            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock);
                continue;
            }
        }

        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close(sock);
            return;
        }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            continue;
        }

        if (fp->probe && strlen(fp->probe) > 0) {
            SSL_write(ssl, fp->probe, strlen(fp->probe));
        }

        char buf[8192];
        int n = SSL_read(ssl, buf, sizeof(buf)-1);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);

        if (n <= 0) continue;
        buf[n] = '\0';

        regex_t regex;
        int ret = regcomp(&regex, fp->pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        if (ret == 0) {
            ret = regexec(&regex, buf, 0, NULL, 0);
            regfree(&regex);
        }

        if (ret == 0) {
            pthread_mutex_lock(&g_config.print_mutex);
            fprintf(out ? out : stdout, "  └─ Service: %s\n", fp->service);
            pthread_mutex_unlock(&g_config.print_mutex);
            pthread_mutex_lock(&g_config.results_mutex);
            for (int i = 0; i < g_config.num_ports; i++) {
                if (g_config.results[i].port == port) {
                    strncpy(g_config.results[i].service, fp->service, sizeof(g_config.results[i].service)-1);
                    break;
                }
            }
            pthread_mutex_unlock(&g_config.results_mutex);
            return;
        }
    }
}
#endif

static void tcp_version_detection(int port, FILE *out)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

    for (service_fingerprint *fp = service_fingerprints; fp->service; fp++) {
        if (fp->port != 0 && fp->port != port) continue;

        int sock = -1;
        if (g_config.proxy_type != PROXY_NONE) {
            sock = proxy_connect_for_banner(g_config.target_ip, port);
            if (sock < 0) continue;
        } else {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) return;

            struct timeval tv;
            tv.tv_sec = g_config.timeout_sec;
            tv.tv_usec = 0;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                perror_msg("setsockopt timeout");
                close(sock);
                return;
            }

            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock);
                continue;
            }
        }

        if (fp->probe && strlen(fp->probe) > 0) {
            if (send(sock, fp->probe, strlen(fp->probe), 0) < 0) {
                close(sock);
                continue;
            }
        }

        char buf[8192];
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        close(sock);

        if (n <= 0) continue;
        buf[n] = '\0';

        regex_t regex;
        int ret = regcomp(&regex, fp->pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        if (ret == 0) {
            ret = regexec(&regex, buf, 0, NULL, 0);
            regfree(&regex);
        }

        if (ret == 0) {
            pthread_mutex_lock(&g_config.print_mutex);
            fprintf(out ? out : stdout, "  └─ Service: %s\n", fp->service);
            pthread_mutex_unlock(&g_config.print_mutex);
            pthread_mutex_lock(&g_config.results_mutex);
            for (int i = 0; i < g_config.num_ports; i++) {
                if (g_config.results[i].port == port) {
                    strncpy(g_config.results[i].service, fp->service, sizeof(g_config.results[i].service)-1);
                    break;
                }
            }
            pthread_mutex_unlock(&g_config.results_mutex);
            return;
        }
    }
}

static void version_detection(int port, FILE *out)
{
#ifdef HAVE_OPENSSL
    if (IS_HTTPS_PORT(port)) {
        ssl_version_detection(port, out);
    } else
#endif
    {
        tcp_version_detection(port, out);
    }
}

// ----------------------------------------------------------------------
// Custom payload injection
// ----------------------------------------------------------------------
static void send_payload(int port, FILE *out)
{
  if (g_config.payload_len == 0) return;
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return;
  struct timeval tv;
  tv.tv_sec = g_config.timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
      setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    perror_msg("setsockopt timeout");
    close(sock);
    return;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, g_config.target_ip, &addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sock);
    return;
  }
  if (send(sock, g_config.payload_data, g_config.payload_len, 0) < 0) {
    close(sock);
    return;
  }
  char buf[256];
  int n = recv(sock, buf, sizeof(buf)-1, 0);
  if (n > 0) {
    buf[n] = '\0';
    pthread_mutex_lock(&g_config.print_mutex);
    fprintf(out ? out : stdout, "  └─ Payload response: %s\n", buf);
    pthread_mutex_unlock(&g_config.print_mutex);
  }
  close(sock);
}

// Thread main function
static void *scan_thread_func(void *arg)
{
  thread_data_t *td = (thread_data_t *)arg;
  int *ports = g_config.port_list;

  // If main thread (thread_id == 0) and proxy version detection enabled, do it once
  if (td->thread_id == 0 && g_config.proxy_type != PROXY_NONE && g_config.do_version) {
      proxy_version_detection(g_config.outfile);
  }

  for (int idx = td->start_idx; idx < td->end_idx && !atomic_load(&g_config.stop); idx++) {
    int port = ports[idx];
    int open = 0, filtered = 0, closed = 0;
    int res = -1;

    if (g_config.delay_ms > 0)
      usleep(g_config.delay_ms * 1000);

    if (g_config.idle_scan) {
      res = idle_scan_port(td, port, &open);
      if (res == 0) closed = !open;
    } else if (g_config.scan_type == 0) {  // TCP connect
      res = tcp_connect_scan_port(port, &open);
      if (res == 0 && open) { closed = 0; filtered = 0; }
      else closed = 1;
    } else if (g_config.scan_type == 1) {  // SYN
      struct in_addr used_src;
      res = syn_scan_port(td, port, &open, &filtered, &used_src);
      if (res == 0) {
        if (filtered) closed = 0;
        else if (open) closed = 0;
        else closed = 1;
      }
      if (g_config.decoy_count > 0 && g_config.verbose) {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &used_src, src_ip, sizeof(src_ip));
        pthread_mutex_lock(&g_config.print_mutex);
        fprintf(g_config.outfile ? g_config.outfile : stdout,
                "  [Decoy used: %s]\n", src_ip);
        pthread_mutex_unlock(&g_config.print_mutex);
      }
    } else if (g_config.scan_type == 2) {  // UDP
      res = udp_scan_port(td, port, &open, &filtered);
      if (res == 0) {
        if (filtered) closed = 0;
        else if (open) closed = 0;
        else closed = 1;
      }
    }

    pthread_mutex_lock(&g_config.stats_mutex);
    if (open) g_config.total_open++;
    else if (closed) g_config.total_closed++;
    else if (filtered) g_config.total_filtered++;
    pthread_mutex_unlock(&g_config.stats_mutex);

    // Record result
    pthread_mutex_lock(&g_config.results_mutex);
    if (idx >= g_config.results_capacity) {
        fprintf(stderr, "Thread %d: severe error: port index %d out of range (max %d). Exiting thread.\n",
                td->thread_id, idx, g_config.results_capacity-1);
        pthread_mutex_unlock(&g_config.results_mutex);
        return NULL;
    }
    port_result_t *r = &g_config.results[idx];
    r->port = port;
    if (open) strcpy(r->state, "open");
    else if (closed) strcpy(r->state, "closed");
    else if (filtered) strcpy(r->state, "filtered");
    else strcpy(r->state, "unknown");
    r->service[0] = '\0';
    pthread_mutex_unlock(&g_config.results_mutex);

    if (open || g_config.verbose) {
      pthread_mutex_lock(&g_config.print_mutex);
      FILE *out = g_config.outfile ? g_config.outfile : stdout;
      if (open)
        fprintf(out, "Port %d/%s: open\n", port,
                (g_config.scan_type == 2) ? "udp" : "tcp");
      else if (closed)
        fprintf(out, "Port %d/%s: closed\n", port,
                (g_config.scan_type == 2) ? "udp" : "tcp");
      else if (filtered)
        fprintf(out, "Port %d/%s: filtered\n", port,
                (g_config.scan_type == 2) ? "udp" : "tcp");
      pthread_mutex_unlock(&g_config.print_mutex);

      if (open) {
        if (g_config.do_banner && g_config.scan_type != 2) {
          banner_grab(port, g_config.outfile);
        }
        if (g_config.do_version && g_config.scan_type != 2) {
          version_detection(port, g_config.outfile);
        }
        if (g_config.payload_len > 0 && g_config.scan_type != 2) {
          send_payload(port, g_config.outfile);
        }
      }
    }
  }
  return NULL;
}

// XML output functions
static void xml_open(FILE *f)
{
  fprintf(f, "<?xml version=\"1.0\"?>\n");
  fprintf(f, "<nmaprun scanner=\"toybox-portscan\" start=\"%ld\">\n", time(NULL));
  fprintf(f, "  <scaninfo type=\"%s\" protocol=\"%s\"/>\n",
          g_config.scan_type==0?"connect":(g_config.scan_type==1?"syn":"udp"),
          g_config.scan_type==2?"udp":"tcp");
  fprintf(f, "  <target>\n");
  fprintf(f, "    <host>%s</host>\n", g_config.target_ip);
  fprintf(f, "  </target>\n");
  fprintf(f, "  <ports>\n");
}

static void xml_port(FILE *f, int port, const char *state, const char *service)
{
  fprintf(f, "    <port portid=\"%d\" protocol=\"%s\">\n", port,
          g_config.scan_type==2?"udp":"tcp");
  fprintf(f, "      <state state=\"%s\"/>\n", state);
  if (service && service[0]) fprintf(f, "      <service name=\"%s\"/>\n", service);
  fprintf(f, "    </port>\n");
}

static void xml_close(FILE *f)
{
  fprintf(f, "  </ports>\n");
  fprintf(f, "  <runstats>\n");
  fprintf(f, "    <finished time=\"%ld\"/>\n", time(NULL));
  fprintf(f, "    <hosts up=\"%d\" down=\"%d\" total=\"%d\"/>\n",
          g_config.total_open, g_config.total_closed, g_config.num_ports);
  fprintf(f, "  </runstats>\n");
  fprintf(f, "</nmaprun>\n");
}

// Signal handler
static void sigint_handler(int sig)
{
  atomic_store(&g_config.stop, 1);
}

void map_main(void)
{
  char *host = toys.optargs[0];
  struct hostent *he;
  struct in_addr addr;
  int *port_list = NULL;
  int num_ports = 0;
  int scan_type = 0;
  int thread_count = 4;
  int timeout = 2;
  int delay_ms = 0;
  int verbose = 0;
  int randomize = 0;
  int do_banner = 0;
  int do_version = 0;
  int idle_scan = 0;
  char *zombie_arg = NULL;
  char *decoy_arg = NULL;
  char *outfile_name = NULL;
  char *xmlfile_name = NULL;
  FILE *outfile = NULL;
  FILE *xmlfile = NULL;

#ifdef HAVE_OPENSSL
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
#endif

  if (toys.optflags & FLAG_S) {
    scan_type = 1;
    if (geteuid() != 0) error_exit("SYN scan requires root privileges");
  }
  if (toys.optflags & FLAG_U) {
    scan_type = 2;
    if (geteuid() != 0) error_exit("UDP scan requires root privileges");
  }
  if (toys.optflags & FLAG_T) scan_type = 0;
  if (toys.optflags & FLAG_V) do_version = 1;
  if (toys.optflags & FLAG_b) do_banner = 1;
  if (toys.optflags & FLAG_v) verbose = 1;
  if (toys.optflags & FLAG_r) randomize = 1;
  if (TT.p) parse_port_list(TT.p, &port_list, &num_ports);
  
  if (num_ports == 0) {
    port_list = malloc(1024 * sizeof(int));
    for (int i = 1; i <= 1024; i++) port_list[i-1] = i;
    num_ports = 1024;
  }
  if (TT.t > 0) timeout = (int)TT.t;
  if (TT.c > 0) thread_count = (int)TT.c;
  if (thread_count > 200) thread_count = 200;
  if (TT.d > 0) delay_ms = (int)TT.d;
  
  if (TT.o) outfile_name = TT.o;
  if (TT.x) xmlfile_name = TT.x;

  if (toys.optflags & FLAG_I) {
    idle_scan = 1;
    zombie_arg = TT.I;
    char *colon = strchr(zombie_arg, ':');
    if (!colon) error_exit("Idle scan requires zombie host:port format");
    *colon = '\0';
    g_config.zombie_host = strdup(zombie_arg);
    g_config.zombie_port = atoi(colon+1);
  }

  if (toys.optflags & FLAG_D) {
    decoy_arg = TT.D;
    char *copy = strdup(decoy_arg);
    char *token;
    int count = 0;
    struct in_addr *addrs = NULL;
    for (token = strtok(copy, ","); token; token = strtok(NULL, ",")) {
      struct in_addr d;
      if (inet_pton(AF_INET, token, &d) != 1) {
        error_msg("Invalid decoy IP: %s", token);
        continue;
      }
      addrs = realloc(addrs, (count+1) * sizeof(struct in_addr));
      addrs[count++] = d;
    }
    free(copy);
    g_config.decoy_addrs = addrs;
    g_config.decoy_count = count;
  }

  if (toys.optflags & FLAG_P) {
    if (parse_proxy_url(TT.P) < 0)
      error_exit("Invalid proxy URL. Use http://host:port or socks5://host:port");
  }

  if (toys.optflags & FLAG_H) {
    char *hex = TT.H;
    int len = strlen(hex);
    if (len % 2 != 0) error_exit("--data must be an even-length hexadecimal string");
    g_config.payload_len = len / 2;
    g_config.payload_data = malloc(g_config.payload_len);
    for (int i = 0; i < g_config.payload_len; i++) {
      unsigned int byte;
      sscanf(hex + 2*i, "%2x", &byte);
      g_config.payload_data[i] = (char)byte;
    }
  }

  if (randomize) {
    srand(time(NULL));
    shuffle_ports(port_list, num_ports);
  }

  // Resolve target
  if (inet_pton(AF_INET, host, &addr) != 1) {
    he = gethostbyname(host);
    if (!he) error_exit("Unable to resolve hostname");
    memcpy(&addr, he->h_addr_list[0], he->h_length);
  }
  inet_ntop(AF_INET, &addr, g_config.target_ip, sizeof(g_config.target_ip));

  if (outfile_name) {
    outfile = fopen(outfile_name, "w");
    if (!outfile) perror_exit("Unable to open output file");
  }
  if (xmlfile_name) {
    xmlfile = fopen(xmlfile_name, "w");
    if (!xmlfile) perror_exit("Unable to open XML file");
    xml_open(xmlfile);
  }

  // Initialize global configuration
  memset(&g_config, 0, sizeof(g_config));
  g_config.port_list = port_list;
  g_config.num_ports = num_ports;
  g_config.scan_type = scan_type;
  g_config.do_banner = do_banner;
  g_config.do_version = do_version;
  g_config.verbose = verbose;
  g_config.randomize = randomize;
  g_config.timeout_sec = timeout;
  g_config.thread_count = thread_count;
  g_config.delay_ms = delay_ms;
  g_config.outfile = outfile;
  g_config.xmlfile = xmlfile;
  atomic_store(&g_config.stop, 0);
  g_config.idle_scan = idle_scan;
  if (idle_scan) {
    inet_pton(AF_INET, g_config.zombie_host, &g_config.zombie_ip);
  }
  pthread_mutex_init(&g_config.print_mutex, NULL);
  pthread_mutex_init(&g_config.stats_mutex, NULL);
  pthread_mutex_init(&g_config.results_mutex, NULL);
  g_config.total_open = 0;
  g_config.total_closed = 0;
  g_config.total_filtered = 0;

  g_config.results_capacity = num_ports;
  g_config.results = calloc(num_ports, sizeof(port_result_t));

  int raw_sock_tcp = -1;
  int raw_sock_icmp = -1;
  if (scan_type == 1 || idle_scan) {
    raw_sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock_tcp < 0) perror_exit("Raw socket (TCP)");
    int on = 1;
    if (setsockopt(raw_sock_tcp, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
      perror_msg("setsockopt IP_HDRINCL");
  }
  if (scan_type == 2) {
    raw_sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock_icmp < 0) perror_exit("Raw socket (ICMP)");
  }

  int ports_per_thread = num_ports / thread_count;
  int remainder = num_ports % thread_count;
  pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
  thread_data_t *tdata = malloc(thread_count * sizeof(thread_data_t));
  int idx = 0;

  printf("Scanning %s (%s) for %d ports using %d threads\n",
         host, g_config.target_ip, num_ports, thread_count);

  signal(SIGINT, sigint_handler);

  for (int i = 0; i < thread_count; i++) {
    int start = idx;
    int end = start + ports_per_thread + (i < remainder ? 1 : 0);
    if (end > num_ports) end = num_ports;
    idx = end;
    tdata[i].thread_id = i;
    tdata[i].start_idx = start;
    tdata[i].end_idx = end;
    tdata[i].raw_sock = (scan_type == 1 || idle_scan) ? raw_sock_tcp :
                         (scan_type == 2) ? raw_sock_icmp : -1;
    pthread_create(&threads[i], NULL, scan_thread_func, &tdata[i]);
  }

  for (int i = 0; i < thread_count; i++) {
    pthread_join(threads[i], NULL);
  }

  if (raw_sock_tcp != -1) close(raw_sock_tcp);
  if (raw_sock_icmp != -1) close(raw_sock_icmp);

  if (xmlfile) {
    for (int i = 0; i < num_ports; i++) {
      port_result_t *r = &g_config.results[i];
      xml_port(xmlfile, r->port, r->state, r->service);
    }
    xml_close(xmlfile);
    fclose(xmlfile);
  }

  printf("Scan completed: open %d, closed %d, filtered %d\n",
         g_config.total_open, g_config.total_closed, g_config.total_filtered);

  if (outfile) fclose(outfile);
  free(port_list);
  free(g_config.decoy_addrs);
  free(g_config.payload_data);
  free(g_config.results);
  free(threads);
  free(tdata);
  pthread_mutex_destroy(&g_config.print_mutex);
  pthread_mutex_destroy(&g_config.stats_mutex);
  pthread_mutex_destroy(&g_config.results_mutex);
}
