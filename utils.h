//
// Created by matyas on 21/04/2020.
//

#include <netinet/ip_icmp.h>
#include "global.h"

#ifndef CPING_UTILS_H
#define CPING_UTILS_H

struct icmp_packet {
    struct icmphdr header;
    char data[ICMP_PACKET_SIZE - sizeof(struct icmphdr)];
};

// Function to perform checksum on buffer of size bytes.
uint16_t checksum(void *buffer, int bytes);

// Function to perform dns lookup based on hostname,
// returns NULL if the lookup fails.
char *dns_lookup(char *hostname, struct sockaddr_in *addr);

// Function performs dns reverse lookup of IPv4 address.
// returns NULL on failure.
char *reverse_dns_lookup(char *ip);


#endif //CPING_UTILS_H
