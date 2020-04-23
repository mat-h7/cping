//
// Created by matyas on 22/04/2020.
//

#ifndef CPING_GLOBAL_H
#define CPING_GLOBAL_H

#define IPV4_SIZE 4
#define DEFAULT_TTL 64
#define DEFAULT_INTERVAL 1000
#define TTL_MAX 255
#define INVALID -1
#define ICMP_TYPE_EXCTTL 11
#define ICMP_CODE_ECHOREP 0

#define SECTOMILLI 1000.0
#define NANOTOMILLI 1000000.0
#define DEFAULT_RCVTIMEO 2


// This is the minimum size for the data segment of an ethernet frame.
#define ICMP_PACKET_SIZE 64

#endif //CPING_GLOBAL_H
