#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <memory.h>

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15

#define CLIENT_SVR "127.0.0.1"
#define LOCAL_SVR "127.0.0.2"
#define ROOT_SVR "127.0.0.3"
#define NATION_SVR "127.0.0.4"
#define ORG_SVR "127.0.0.5"
#define EDU_SVR "127.0.0.6"
#define GOV_SVR "127.0.0.7"
#define PORT 53

typedef struct DNS_Header
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
} Header;

typedef struct DNS_Query
{
    unsigned char name[128];
    unsigned short qtype;
    unsigned short qclass;
} Query;

typedef struct DNS_RR
{
    unsigned char name[128];
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char rdata[128];
} RR;

typedef struct header_flags { //大小端字节序
	uint8_t qr:1;
    uint8_t opcode:4;
    uint8_t a:1;
    uint8_t tc:1;
    uint8_t rd:1;
    uint8_t ra:1;
    uint8_t z:1;
    uint8_t aa:1;
    uint8_t na:1;
    uint8_t rcode:4;
	

	
	
	
	
	
} Flag;

int WSAGetLastError()
{
    return -1;
}

#endif