#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <argp.h>
#include <stdbool.h>
#include "global.h"
#include "utils.h"

//
// Created by matyas on 21/04/2020.
//

// A few constants used by cping.
#define DEFAULT_TTL 64
#define TTL_MAX 255

#define DEFAULT_RCVTIMEO 2
#define DEFAULT_INTERVAL 1000

#define ICMP_TYPE_EXCTTL 11
#define ICMP_CODE_ECHOREP 0


// Information for argument parser (argp).
const char *argp_program_version = "cping 2.0";
const char *argp_program_bug_address = "<horkay.matyas@gmail.com>";

static char doc[] = "A small ping CLI application to send ICMP echo requests in a loop";


static char args_doc[] = "TARGET";

static struct argp_option options[] = {
    {"target",   0,   "TARGET",   0, "Specify TARGET host by IP or HOSTNAME"},
    {"ttl",      't', "TTL",      0, "Specify TTL (default=64, max=255)."},
    {"interval", 'i', "INTERVAL", 0, "Specify INTERVAL in ms between packets (default=1000)"},
    {"count",    'c', "COUNT",    0, "Specify COUNT number of packets to be sent (min=1)."},
    {0}
};

struct arguments {
    char *target;
    int ttl;
    int interval;
    int count;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {

  struct arguments *arguments = state->input;
  bool target_specified = strcmp(arguments->target, "");

  switch (key) {

    case ARGP_KEY_ARG:
      if (state->arg_num != 0) {
        // If here too many arguments passed in for TARGET
        argp_usage(state);
        break;
      }

      arguments->target = arg;
      break;
    case 't': {

      // Check if ttl value specified is greater than TTL_MAX set to DEFAULT_TTL.
      uint8_t ttl = strtol(arg, NULL, 0);
      arguments->ttl = ttl > TTL_MAX ? DEFAULT_TTL : ttl;
      break;
    }

    case 'i':

      arguments->interval = strtol(arg, NULL, 0);

      // Invalid count value < 1.
      if (arguments->interval < 1) {
        argp_usage(state);
      }
      break;

    case 'c':

      arguments->count = strtol(arg, NULL, 0);
      break;

    case ARGP_KEY_END:

      // If all arguments parsed and neither hostname or ip specified, stop execution and display help message.
      if (!target_specified) {
        argp_usage(state);
        return ARGP_ERR_UNKNOWN;
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};


// Variable and custom interrupt handler for ping loop.
static bool ping = true;

void int_handler(int unused) {
  ping = false;
}


// Function sends ICMP echo ping requests to host_ip (IPv4/IPv6) with ttl=ttl, interval=interval, count=count.
void ping_loop(int socket_fd, struct sockaddr host_address, char *host_ip, int ttl, int interval, int count) {

  bool ipv6 = host_address.sa_family == AF_INET6;
  if(ipv6) {
    printf("it is what ti is \n");
  }
  // Variables/structs used for ping.
  struct icmp ping_packet;
  char recv_buf[sizeof(struct ip) + sizeof(struct icmp)];
  int addr_length = ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
  ssize_t bytes_received;

  // Variables/structs for statistics.
  int total_sent = 0, total_received = 0;
  long double rtt = 0, total_time = 0, min_rtt = INT_MAX, max_rtt = 0, total_rtt = 0;
  struct timespec initial, final;
  struct timespec loop_initial, loop_final;

  // Set socket TTL.
  int level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
  int optname = ipv6 ? IPV6_UNICAST_HOPS : IP_TTL;
  if (setsockopt(socket_fd, level, optname, &ttl, sizeof(ttl))) {
    printf("Error! Failed to set ttl to %d.\n", ttl);
    exit(EXIT_FAILURE);
  }

  int icmp_type = ipv6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
  clock_gettime(CLOCK_MONOTONIC, &loop_initial);

  while (ping && count != 0) {

    // Convert interval from milliseconds to microseconds.
    usleep(interval * 1000);

    // Set up ping packet.
    bzero(&ping_packet, sizeof(ping_packet));
    ping_packet.icmp_type = icmp_type;
    ping_packet.icmp_id = getpid();
    ping_packet.icmp_seq = total_sent++;
    ping_packet.icmp_cksum = ~checksum(&ping_packet, sizeof(struct icmp));

    clock_gettime(CLOCK_MONOTONIC, &initial);

    if (sendto(socket_fd, &ping_packet, sizeof(struct icmp), 0, &host_address, addr_length) <= 0) {
      printf("Failed to send packet!\n");
      goto loop_end;
    }

    if ((bytes_received = recv(socket_fd, &recv_buf, sizeof(recv_buf), 0)) < 0) {
      printf("Failed to receive response!\n");
      goto loop_end;
    }

    struct icmp *recv_packet = (struct icmp *) (recv_buf + sizeof(struct ip));

    clock_gettime(CLOCK_MONOTONIC, &final);
    rtt = time_delta(&initial, &final);

    // Used for end statistics.
    min_rtt = rtt < min_rtt ? rtt : min_rtt;
    max_rtt = rtt > max_rtt ? rtt : max_rtt;
    total_rtt += rtt;

    // Report if packet unable to reach destination.
    if (recv_packet->icmp_code == ICMP_DEST_UNREACH) {
      printf("Error. Destination not reached.\n");
      goto loop_end;
    }

    // Report any other errors (note: these should be unlikely in this context).
    if (recv_packet->icmp_code != ICMP_CODE_ECHOREP) {
      printf("Error. Packet received with ICMP type: %d, code: %d", recv_packet->icmp_type, recv_packet->icmp_code);
      goto loop_end;

    }

    // If here response received.
    printf("%ld bytes from %s icmp_seq=%d: ", bytes_received, host_ip, total_sent);

    if (recv_packet->icmp_type == ICMP_TYPE_EXCTTL) {
      // If here TTL for packet exceeded.
      printf("Time to live exceeded\n");
      goto loop_end;
    }

    // If here packet was received correctly.
    printf("ttl=%d rtt = %.2Lf ms.\n", ttl, rtt);
    total_received++;

    // Label to jump to if any error occurs.
    loop_end:
      count--;
  }

  clock_gettime(CLOCK_MONOTONIC, &loop_final);
  total_time = time_delta(&loop_initial, &loop_final);

  printf("\n\n%d packets sent, %d packets received, %f percent packet loss. Total time: %.0Lf ms.\n", total_sent,
         total_received, ((double) (total_sent - total_received) / total_sent) * 100.0, total_time);
  printf("rtt min/avg/max = %.3Lf/%.3Lf/%.3Lf ms\n", min_rtt, total_rtt / (double) total_sent, max_rtt);


}

int main(int argc, char **argv) {

  // Set up arguments struct and parse command line arguments.
  struct arguments arguments;
  arguments.target = "";
  arguments.ttl = DEFAULT_TTL;
  arguments.interval = DEFAULT_INTERVAL;
  arguments.count = -1;   // set count to -1 to indicate that no count was specified.
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  // Declare variables used to set up input to ping_loop.
  int ttl = arguments.ttl;
  int interval = arguments.interval;
  int count = arguments.count;
  char *target = arguments.target;
  char *ip = NULL;
  char *hostname = NULL;

  bool ipv6 = is_ip6(target);

  // If target specified is a hostname or an ipv4 address, set up addr using dns_loopkup4.
  struct sockaddr addr;
  bzero(&addr, sizeof(addr));

  if (!ipv6) {

    // If here target is hostname or ipv4 addresss. Set up addr struct accordingly.
    if ((ip = dns_lookup4(target, (struct sockaddr_in *) &addr)) == NULL) {
      printf("Error! DNS lookup for %s failed!\n", hostname);
      exit(EXIT_FAILURE);
    }

  } else {
    
    // If here target specified is an ipv6 address. Set up addr struct accordingly.
    ip = target;
    if(ipv6_to_addr(target, (struct sockaddr_in6*)&addr)) {
      printf("Error! %s is not a valid ip address.", target);
      exit(EXIT_FAILURE);
    }

  }

  // Open socket based on address type.
  int socket_fd;
  int af = ipv6 ? AF_INET6 : AF_INET;
  int protocol = ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
  if ((socket_fd = socket(af, SOCK_RAW, protocol)) < 0) {
    printf("Error! Failed to create socket, make sure you are running the program as root!\n");
    exit(EXIT_FAILURE);
  }

  // Set socket receive timeout to 2 seconds.
  struct timeval rcvtimeo;
  bzero(&rcvtimeo, sizeof(struct timeval));
  rcvtimeo.tv_sec = DEFAULT_RCVTIMEO;
  if(setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &rcvtimeo, sizeof(rcvtimeo))) {
    printf("Error! Failed to set RCVTIMEO.\n");
    exit(EXIT_FAILURE);
  }

  // Create custom SIGINT handler, so ping statistics can be display when loop is broken.
  signal(SIGINT, int_handler);

  printf("\nPinging %s (%s)\n\n", ip, target);
  ping_loop(socket_fd, addr, ip, ttl, interval, count);

  exit(EXIT_SUCCESS);

}
