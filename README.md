# CPING
Small ping CLI for Cloudflare Internship Application: Systems.  

##Description
This program allows the user to send ping (ICMP ECHO REQUEST) packets to a host.  
Reports statistics such as percentage of packets lost, min/avg/max rtt times.
Host can be specified by either **HOSTNAME**, **IP4** (or **IPV6**<sup>*</sup>).  
The following parameters can be specified:  
* TTL
* Count
* Interval
   
   
*Note that support for IPV6 is limited, as I could not manage to receive any responses 
to the ping packets when testing locally.

##Usage
1. make cping
2. sudo ./cping www.example.com

For more information on how parametrs can be specified run: ./cping --help
 
##Author
Matyas Horkay <horkay.matyas@gmail.com>