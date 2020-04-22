#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <argp.h>
#include <stdbool.h>
#include "global.h"
#include "utils.h"

// ARG PARSE BEGIN
// Information for argument parser (argp).
const char *argp_program_version = "cping 1.0";
const char *argp_program_bug_address = "<horkay.matyas@gmail.com>";

static char doc[] = "A small ping CLI application to send ICMP echo requests in a loop";


static char args_doc[] = "TARGET";

static struct argp_option options[] = {
    {"target", 0,   "TARGET", 0, "Specify TARGET host by IP or HOSTNAME"},
    {"ttl",    't', "TTL",    0, "Specify TTL (default=64, max=255)."},
    {0}
};

struct arguments {
    char *target;
    uint8_t ttl;
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

      // Check if ttl value specified is greater than TTL_MAX set to TTL_DEFAULT.
      uint8_t ttl = strtol(arg, NULL, 0);
      arguments->ttl = ttl > TTL_MAX ? TTL_DEFAULT : ttl;
      break;
    }

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

// ARG PARSE END

// PING SEND BEGIN


bool loop = true;

void init_ping_packet(struct icmp_packet *packet, int sequence) {

  bzero(packet, sizeof(struct icmp_packet));
  memset(packet, 0, sizeof(struct icmp_packet));
  packet->header.type = ICMP_ECHO;
  packet->header.un.echo.id = getpid();
  packet->header.un.echo.sequence = sequence;
  packet->header.checksum = ~checksum(&packet, sizeof(packet));

}

void send_ping(int socket_fd, struct sockaddr_in *host_address, char *hostname, char *host_ip, int ttl) {


  int total_sent = 0, total_received = 0;
  long double rtt = 0, total_time = 0;
  struct timespec intial_time, final_time, loop_start, loop_end;
  struct icmp ipacket;
//  struct icmp buffer;

  //TODO THIS IS RANDOM AF.
  struct timeval tv_out;
  tv_out.tv_sec = 1;
  tv_out.tv_usec = 0;
  clock_gettime(CLOCK_MONOTONIC, &loop_start);


  if (setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) {
    printf("Error! Failed to set ttl to %d.\n", ttl);
    exit(EXIT_FAILURE);
  }

  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv_out, sizeof(tv_out));

  while (loop) {

    sleep(1);

    // Set up ping packet.
    bzero(&ipacket, sizeof(ipacket));
    ipacket.icmp_type = ICMP_ECHO;
    ipacket.icmp_id = getpid();
    ipacket.icmp_seq = total_sent++;
    ipacket.icmp_cksum = ~checksum(&ipacket, sizeof(struct icmp));

    clock_gettime(CLOCK_MONOTONIC, &intial_time);

    char recv_buf[sizeof(struct ip) + sizeof(struct icmp)];

    if (sendto(socket_fd, &ipacket, sizeof(ipacket), 0, (struct sockaddr *) host_address, sizeof(*host_address)) <= 0) {
      printf("Failed to send packet!\n");
      continue;
    }
    ssize_t bytes_received;
    if ((bytes_received = recv(socket_fd, &recv_buf, sizeof(recv_buf), 0)) < 0) {
      printf("Failed to receive response!\n");
    } else {

      struct icmp *icmp = (struct icmp *) (recv_buf + sizeof(struct ip));
      printf("\n\n type: %d, code: %d\n\n", icmp->icmp_type, icmp->icmp_code);
      clock_gettime(CLOCK_MONOTONIC, &final_time);
      double time_elapsed = ((double) (final_time.tv_nsec - intial_time.tv_nsec)) / 1000000.0;
      rtt = (double) (final_time.tv_sec - intial_time.tv_sec) * 1000.0 + time_elapsed;

      if (icmp->icmp_code != 0) {
        printf("Error. Packet received with ICMP type: %d, code: %d", icmp->icmp_type, icmp->icmp_code);
        continue;
      }

      // If here response successfully received.
      printf("%ld bytes from %s (%s) icmp_seq=%d:", bytes_received, hostname, host_ip, total_sent);
      if (icmp->icmp_type == 11) {
        // If here TTL exceeded.
        printf("Time to live exceeded\n");
        continue;
      }

      printf("ttl=%d rtt = %Lf ms.\n", ttl, rtt);
      total_received++;

    }
  }

  clock_gettime(CLOCK_MONOTONIC, &loop_end);
  double time_elapsed = ((double) (loop_end.tv_nsec - loop_start.tv_nsec)) / 1000000.0;
  total_time = (loop_end.tv_sec - loop_start.tv_sec) * 1000.0 + time_elapsed;

  printf("%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms.\n\n", total_sent,
         total_received, ((double) (total_sent - total_received) / total_sent) * 100.0, total_time);


}

void intHandler(int dummy) {
  loop = false;
}

// Function return true iff target is a valid string representation of an IPv4 address.
bool is_ip4(char *target) {
  struct in_addr in_addr;
  return inet_aton(target, &in_addr) != 0;
}

// Function return true iff target is a valid string representation of an IPv6 address.
bool is_ip6(char *target) {
  struct in6_addr in_addr;
  return inet_pton(AF_INET6, target, (void *)&in_addr) == 1;
}

int main(int argc, char **argv) {

  // Set up arguments struct and parse command line arguments.
  struct arguments arguments;
  arguments.target = "";
  arguments.ttl = TTL_DEFAULT;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  char *target = arguments.target;
  char *ip = NULL;
  char *hostname = NULL;
  struct sockaddr_in addr;

  // Target specified is either an ip address or a hostname.
  if (is_ip6(target)) {
    ip = target;
  } else if (is_ip4(target)) {
    ip = target;
    if ((hostname = reverse_dns_lookup(AF_INET, ip)) == NULL) {
      printf("Error! Reverse DNS lookup for ip %s failed!\n", ip);
      exit(EXIT_FAILURE);
    }
    if ((ip = dns_lookup(hostname, &addr)) == NULL) {
      printf("Error! DNS lookup for hostname %s failed!\n", hostname);
      exit(EXIT_FAILURE);
    }
  } else {
    hostname = target;
    if ((ip = dns_lookup(hostname, &addr)) == NULL) {
      printf("Error! DNS lookup for hostname %s failed!\n", hostname);
      exit(EXIT_FAILURE);
    }
  }

  uint8_t ttl = arguments.ttl;

  printf("Attempting to connect to host: %s ip: %s\n", hostname, ip);

  int socket_fd;
  if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    printf("Error! Failed to create socket, make sure you are running the program as root!\n");
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, intHandler);

  send_ping(socket_fd, &addr, hostname, ip, ttl);

  exit(EXIT_SUCCESS);

}


