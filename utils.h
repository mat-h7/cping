//
// Created by matyas on 21/04/2020.
//

#include <netinet/ip_icmp.h>
#include "global.h"

#ifndef CPING_UTILS_H
#define CPING_UTILS_H

// Function to perform checksum on buffer of size bytes.
uint16_t checksum(void *buffer, int bytes);

// Function return true iff target is a valid string representation of an IPv4 address.
bool is_ip4(char *target);

// Function return true iff target is a valid string representation of an IPv6 address.
bool is_ip6(char *target);

// Function returns time delta between initial and final in ms.
double time_delta(struct timespec *initial, struct timespec *final);

// Function to perform dns lookup on hostname or IPv4 address. Returns NULL if lookup fails.
char *dns_lookup4(char *hostname, struct sockaddr_in *addr);

// Function performs dns reverse lookup of IPv4 address. Returns NULL on failure.
char *reverse_dns_lookup4(char *ip);

// Function turns target (IPv6 address) into the corresponding sockaddr struct. Returns 0 iff successful.
int ipv6_to_addr(char *target, struct sockaddr_in6* addr);


#endif //CPING_UTILS_H
