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

void send_ping(int socket_fd, struct sockaddr_in *host_address, char *hostname, char *host_ip, int ttl) {

  //TODO: PARSE TTL
  int total_sent = 0, total_received = 0;
  struct icmp_packet packet;
  struct sockaddr_in receive_addr;
  long double rtt = 0, total_time = 0;
  struct timespec time_start, time_end, tfs, tfe;


  //TODO THIS IS RANDOM AF.
  struct timeval tv_out;
  tv_out.tv_sec = 1;
  tv_out.tv_usec = 0;
  clock_gettime(CLOCK_MONOTONIC, &tfs);


  if (setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) {
    printf("Error! Failed to set ttl to %d.\n", ttl);
    exit(EXIT_FAILURE);
  }

  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv_out, sizeof(tv_out));

  while (loop) {

    bool packet_sent = true;
    bzero(&packet, sizeof(packet));

    int i;
    for (i = 0; i < sizeof(packet.data) - 1; i++) {
      packet.data[i] = i + '0';
    }

    packet.data[i] = 0;


    packet.header.type = ICMP_ECHO;
    packet.header.un.echo.id = getpid();
    packet.header.un.echo.sequence = total_sent++;
    packet.header.checksum = ~checksum(&packet, sizeof(packet));

    usleep(5);

    clock_gettime(CLOCK_MONOTONIC, &time_start);


    if (sendto(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *) host_address, sizeof(*host_address)) <= 0) {
      printf("Failed to send packet!\n");
      packet_sent = false;
    }

    socklen_t receive_addr_len = (sizeof(receive_addr));
    if (recvfrom(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *) &receive_addr, &receive_addr_len) <= 0) {
      printf("Failed to receive response!\n");
    } else {
      clock_gettime(CLOCK_MONOTONIC, &time_end);
      double time_elapsed = ((double) (time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
      rtt = (double) (time_end.tv_sec - time_start.tv_sec) * 1000.0 + time_elapsed;

      if (packet_sent) {

        if (!(packet.header.type == 69 && packet.header.code == 0)) {
          printf("Error. Packet received with ICMP type: %d, code: %d", packet.header.type, packet.header.code);
        } else {

          printf("%d bytes from %s (%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n", 64, hostname,
                 host_ip,
                 total_sent, ttl, rtt);
          total_received++;
        }
      }

    }
  }

  clock_gettime(CLOCK_MONOTONIC, &tfe);
  double time_elapsed = ((double) (tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
  total_time = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + time_elapsed;

  printf("%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms.\n\n", total_sent,
         total_received, ((double) (total_sent - total_received) / total_sent) * 100.0, total_time);


}

void intHandler(int dummy) {
  loop = false;
}

// Function return true iff target is a valid string representation of an IPv4 address.
bool is_ip(char *target) {
  struct in_addr in_addr;
  return inet_aton(target, &in_addr) != 0;
}

int main(int argc, char **argv) {

  // Set up arguments struct and parse command line arguments.
  struct arguments arguments;
    arguments.target = "";
  arguments.ttl = TTL_DEFAULT;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  char *target = arguments.target;
  char *ip;
  char *hostname;
  struct sockaddr_in addr;

  // Target specified is either an ip address or a hostname.
  printf("Target is %s\n", target);
  if (is_ip(target)) {
    printf("Target is %s\n", target);
    ip = target;
    if ((hostname = reverse_dns_lookup(ip)) == NULL) {
      printf("Error! Reverse DNS lookup for ip %s failed!\n", ip);
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


