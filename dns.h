#ifndef __DNS_H__
#define __DNS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct DNS_Head
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
}Header;

typedef struct DNS_Query
{
    unsigned char *qname;
    unsigned short qtype;
    unsigned short qclass;
}Query;

typedef struct DNS_RR
{
    unsigned char *rname;
    unsigned short rtype;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short datalen;
    unsigned char *rdata;
}RR;

#endif