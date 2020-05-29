#ifndef __DNS_H__
#define __DNS_H__

typedef struct DNS_Head
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};

typedef struct DNS_Query
{
    unsigned char *qname;
    unsigned short qtype;
    unsigned short qclass;
};

typedef struct DNS_RR
{
    unsigned char *rname;
    unsigned short rtype;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short datalen;
    unsigned char *rdata;
};

#endif