#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include "utils.h"

//
// Created by matyas on 21/04/2020.
//


uint16_t checksum(void *buffer, int bytes) {
  uint32_t sum = 0;
  uint16_t *buff = (uint16_t *) buffer;
  int words = (bytes + 1) / 2;

  while (words-- > 0) {
    sum += *buff++;
  }

  while (sum & 0xffff0000) {
    sum = (sum >> 16) + (sum & 0xffff);
  }

  return (uint16_t) sum;
}

bool is_ip4(char *target) {
  struct in_addr in_addr;
  return inet_aton(target, &in_addr) != 0;
}

bool is_ip6(char *target) {
  struct in6_addr in_addr;
  return inet_pton(AF_INET6, target, (void *) &in_addr) == 1;
}

double time_delta(struct timespec *initial, struct timespec *final) {
  return (double) (final->tv_sec - initial->tv_sec) * SECTOMILLI +
         ((double) (final->tv_nsec - initial->tv_nsec)) / NANOTOMILLI;
}

char *dns_lookup4(char *hostname, struct sockaddr_in *addr) {

  struct hostent *host;

  // Try to get host by hostname.
  if ((host = gethostbyname(hostname)) == NULL) {
    return NULL;
  }

  addr->sin_family = host->h_addrtype;
  addr->sin_addr = *(struct in_addr *)host->h_addr;
  addr->sin_port = 0;

  char *ip_addr = malloc(IPV4_SIZE);
  strcpy(ip_addr, inet_ntoa(*(struct in_addr *) host->h_addr));

  return ip_addr;

}

char *reverse_dns_lookup4(char *ip) {

  struct in_addr in_addr;

  // Convert from IPv4 string representation into binary.
  if ((inet_aton(ip, &in_addr)) == 0) {
    return NULL;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr = in_addr;
  addr.sin_port = 0;

  char buffer[NI_MAXHOST];

  if ((getnameinfo((struct sockaddr *) &addr, sizeof(addr), buffer, sizeof(buffer), NULL, 0, NI_NAMEREQD))) {
    // If here reverse lookup of ip was unsuccessful.
    return NULL;
  }

  char *result = malloc((strlen(buffer) + 1));
  strcpy(result, buffer);
  return result;

}

