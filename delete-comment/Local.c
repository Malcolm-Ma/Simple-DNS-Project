#include "dns.h"

unsigned char ip[64];
unsigned char tcpsendpacket[1024] = {0};
unsigned char tcprecvpacket[1024]; 
unsigned char udpsendpacket[1024]; 
unsigned char udprecvpacket[1024]; 

int tcpsendpos, tcprecvpos, udpsendpos, udprecvpos;

RR rrdb[4];
int rrnum;
unsigned char db[1024];
unsigned char *dbptr;

void formdomain(unsigned char *);
void gethead(unsigned char *, int *, struct DNS_Header *);
void getquery(unsigned char *, int *, struct DNS_Query *);
void getrr(unsigned char *, int *, struct DNS_RR *);
void setstdhead(unsigned char *, int *);
void setreshead(unsigned char *, int *, int id);
void setaquery(unsigned char *, int *, unsigned char *);
void setrr(unsigned char *, int *, struct DNS_RR);
void getAddrr(unsigned char *, int *, struct DNS_RR *);

int main()
{

    int tcpServerSocket, tcpClientSocket;
    struct sockaddr_in tcpServerAddr, tcpClientAddr;
    int tcpaddrlen;

    int udpSocket;
    struct sockaddr_in udpRemoteAddr;
    int udpaddrlen;

    tcpServerSocket = socket(AF_INET, SOCK_STREAM, 0); 
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);        
    if (tcpServerSocket < 0)
    {
        printf("tcpsocket creation failed\n");
        exit(0);
    }
    if (udpSocket < 0)
    {
        printf("udpsocket creation failed\n");
        exit(0);
    }

    tcpServerAddr.sin_family = AF_INET; 
    tcpServerAddr.sin_port = htons(PORT); 
    tcpServerAddr.sin_addr.s_addr = inet_addr(LOCAL_SVR);

    udpRemoteAddr.sin_family = AF_INET;
    udpRemoteAddr.sin_port = htons(PORT);


    if (bind(tcpServerSocket, (struct sockaddr *)&tcpServerAddr, sizeof(struct sockaddr)) < 0)
    {
        perror("TCP SOCKET BINDS ERROR!\n");
        exit(0);
    }
    if (bind(udpSocket, (struct sockaddr *)&tcpServerAddr, sizeof(struct sockaddr)) < 0)
    {
        perror("UDP SOCKET BINDS ERROR!\n");
        exit(0);
    }
    listen(tcpServerSocket, 4);
    tcpaddrlen = sizeof(struct sockaddr_in);
    udpaddrlen = sizeof(struct sockaddr_in);

    clock();

    rrnum = 0;
    dbptr = db;

    while (1)
    {
        
        tcpClientSocket = accept(tcpServerSocket, (struct sockaddr *)&tcpClientAddr, &tcpaddrlen);

        strcpy(ip, ROOT_SVR);
        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);

        recv(tcpClientSocket, tcprecvpacket, sizeof(tcprecvpacket), 0); // flags为0
        printf("server recv packet from client\n");

        Header head;
        Query query;
        RR rr;

        tcprecvpos = 2;
        gethead(tcprecvpacket, &tcprecvpos, &head);
        getquery(tcprecvpacket, &tcprecvpos, &query);

        int i;
        for (i = 0; i < rrnum; ++i)
        {
            if (strcmp(rrdb[i].name, query.name) == 0 && rrdb[i].type == query.qtype)
            {
                printf("using cache\n");

                tcpsendpos = 2;
                setreshead(tcpsendpacket, &tcpsendpos, head.id);
                setrr(tcpsendpacket, &tcpsendpos, rrdb[i]);
               *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);

                send(tcpClientSocket, tcpsendpacket, tcpsendpos, 0);
                printf("server send packet to client\n");

                i = rrnum + 1;

                break;
            }
        }
        if (i == rrnum + 1)
            continue;


        for (i = 2; i < sizeof(tcprecvpacket); ++i)
        {
            udpsendpacket[i - 2] = tcprecvpacket[i];
        }
        udpsendpos = tcprecvpos - 2;

        while (1)
        {
            int flag = 0;
    
            sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr *)&udpRemoteAddr, sizeof(struct sockaddr));
            printf("server send packet to %s\n", ip);
            
            recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr *)&udpRemoteAddr, &udpaddrlen);
            printf("server recv packet from %s\n", ip);
            
            udprecvpos = 0;
            gethead(udprecvpacket, &udprecvpos, &head);
            getquery(udprecvpacket, &udprecvpos, &query);
            getrr(udprecvpacket, &udprecvpos, &rr);

            switch (head.tag)
            {
            case (unsigned short)0x8020: 
                for (i = 2; i < sizeof(udprecvpacket); ++i)
                {
                    tcpsendpacket[i] = udprecvpacket[i - 2];
                }
                tcpsendpos = udprecvpos + 2;
                *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);

                if (rr.type == 1 || rr.type == 2) 
                {
                    flag = 1;
                    break;
                }
                else if (rr.type == 5) 
                {
                    Header h1;
                    Query q1;
                    udpsendpos = 0;
                    gethead(udpsendpacket, &udpsendpos, &h1);
                    getquery(udpsendpacket, &udpsendpos, &q1);
                    if (q1.qtype == 5) 
                    {
                        flag = 1;
                        break;
                    }
                    else if (q1.qtype == 1) 
                    {
                        
                        unsigned char domain[64];
                        strcpy(domain, rr.rdata);
                        formdomain(domain);

                        udpsendpos = 0;
                        setstdhead(udpsendpacket, &udpsendpos);
                        setaquery(udpsendpacket, &udpsendpos, domain);

                        strcpy(ip, ROOT_SVR);
                        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                        
                        while (1)
                        {
                            sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr *)&udpRemoteAddr, sizeof(struct sockaddr));
                            printf("server send packet to %s\n", ip);
                            recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr *)&udpRemoteAddr, &udpaddrlen);
                            printf("server recv packet from %s\n", ip);

                            Header h2;
                            Query q2;
                            RR r2;

                            udprecvpos = 0;
                            gethead(udprecvpacket, &udprecvpos, &h2);
                            getquery(udprecvpacket,&udprecvpos, &q2);
                            getrr(udprecvpacket, &udprecvpos, &r2);

                            if (r2.type == 2)
                            {
                                
                                strcpy(ip, r2.rdata);
                                udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                            }
                            else if (r2.type == 1)
                            {
                                
                                for (i = 2; i < sizeof(udprecvpacket); ++i)
                                {
                                    
                                    tcpsendpacket[i] = udprecvpacket[i - 2];
                                }

                                tcpsendpos = udprecvpos + 2;
                                *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);

                                flag = 1;
                                break;
                            }
                        }
                        break;
                    }
                }
                else if (rr.type == 15)
                {
                    
                    unsigned char domain[64];
                    strcpy(domain, rr.rdata);
                    printf("domain:%s\n", domain);
                    formdomain(domain);

                    memset(udpsendpacket,0,sizeof(udpsendpacket));
                    udpsendpos = 0;
                    setstdhead(udpsendpacket, &udpsendpos);
                    setaquery(udpsendpacket, &udpsendpos, domain);

                    strcpy(ip, ROOT_SVR);
                    udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                    
                    while (1)
                    {
                        sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr *)&udpRemoteAddr, sizeof(struct sockaddr));
                        printf("server send packet to %s\n", ip);

                        recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr *)&udpRemoteAddr, &udpaddrlen);
                        printf("server recv packet from %s\n", ip);

                        Header h3;
                        Query q3;
                        RR r3;

                        udprecvpos = 0;
                        gethead(udprecvpacket, &udprecvpos, &h3);
                        getquery(udprecvpacket,&udprecvpos, &q3);
                        getAddrr(udprecvpacket, &udprecvpos, &r3);

                        if (r3.type == 2) // NS
                        {
                            strcpy(ip, r3.rdata);
                            udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                        }
                        else if (r3.type == 1) // A
                        {
                            *(unsigned short *)(tcpsendpacket + 12) = htons(1);

                            setrr(tcpsendpacket, &tcpsendpos, r3);
                            *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);
                            flag = 1;
                            break;
                        }
                    }
                    break;
                }
                break;
            case (unsigned short)0x8400: 
                if (rr.type == 2)       
                {
                    strcpy(ip, rr.rdata);
                    udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                }
                break;
            }
            if (flag == 1)
                break;
        }

        send(tcpClientSocket, tcpsendpacket, tcpsendpos, 0);
        printf("server send packet to client\n");


        rrnum = rrnum % 4;

        tcpsendpos = 2;
        gethead(tcpsendpacket, &tcpsendpos, &head);
        getquery(tcpsendpacket, &tcpsendpos, &query);
        getAddrr(tcpsendpacket, &tcpsendpos, &rrdb[rrnum]);

        if (rrdb[rrnum].type != 15)
        {
            strcpy(dbptr, rrdb[rrnum].name);
            dbptr += strlen(dbptr) + 1;

            strcpy(dbptr, rrdb[rrnum].rdata);
            dbptr += strlen(dbptr) + 1;
            rrnum++;
        }
        //打印cache
        printf("cache:\n");
        for (i = 0; i < rrnum; ++i)
        {
            printf("%s\n", rrdb[i].name);
        }

        close(tcpClientSocket);
    }
}

void formdomain(unsigned char *domain)
{
    unsigned char dotdomain[64];
    int i = 0;
    while (domain[i] != '\0')
    {
        dotdomain[i] = domain[i];
        ++i;
    }
    dotdomain[i] = '\0';

    int counter;
    unsigned char *flag;
    unsigned char *ptr = dotdomain;
    while (1)
    {
        counter = 0;
        flag = domain;
        domain++;
        while (1)
        {
            if (*ptr == '.' || *ptr == '\0')
                break;
            *domain++ = *ptr++;
            counter++;
        }
        *flag = (unsigned char)counter;
        if (*ptr == '\0')
        {
            *domain = '\0';
            break;
        }
        ptr++;
    }
}

void gethead(unsigned char *packet, int *packetlen, Header *head)
{
    packet += *packetlen; 

    *head = *(Header *)packet;

    head->id = ntohs(head->id);
    head->tag = ntohs(head->tag);
    head->queryNum = ntohs(head->queryNum);
    head->answerNum = ntohs(head->answerNum);
    head->authorNum = ntohs(head->authorNum);
    head->addNum = ntohs(head->addNum);

    *packetlen += 12;
}

void getquery(unsigned char *packet, int *packetlen, Query *query)
{
    packet += *packetlen;
    
    strcpy(query->name, packet); 
    *packetlen += strlen(packet) + 1;
    packet += strlen(packet) + 1;

    query->qtype = ntohs(*(unsigned short *)packet);
    packet += 2;

    query->qclass = ntohs(*(unsigned short *)packet);

    *packetlen += 4;
}

void getrr(unsigned char *packet, int *packetlen, RR *rr)
{
    packet += *packetlen;

    strcpy(rr->name, packet);
    *packetlen += strlen(packet) + 1;
    packet += strlen(packet) + 1;

    rr->type = ntohs(*(unsigned short *)packet);
    packet += 2;
    rr->_class = ntohs(*(unsigned short *)packet);
    packet += 2;
    rr->ttl += ntohl(*(unsigned int *)packet);
    packet += 4;
    rr->data_len = ntohs(*(unsigned short *)packet) - 1;
    packet += 2;

    if (rr->type == 15)
    {
        packet += 3;
        strcpy(rr->rdata, packet);
    } else {
        packet++;
        strcpy(rr->rdata, packet);
    }

    *packetlen += rr->data_len + 10 + 1;
}

void getAddrr(unsigned char *packet, int *packetlen, RR *rr)
{
    packet += *packetlen;

    strcpy(rr->name, packet);
    *packetlen += strlen(packet) + 1;
    packet += strlen(packet) + 1;

    rr->type = ntohs(*(unsigned short *)packet);
    packet += 2;
    rr->_class = ntohs(*(unsigned short *)packet);
    packet += 2;
    rr->ttl += ntohl(*(unsigned int *)packet);
    packet += 4;
    rr->data_len = ntohs(*(unsigned short *)packet) - 1;
    packet += 2;

    if (rr->type == 2)
    {
        packet++;
        strcpy(rr->rdata, packet);
    } else {
        strcpy(rr->rdata, packet);
    }

    *packetlen += rr->data_len + 10 + 1;
}

void setstdhead(unsigned char *packet, int *packetlen)
{
    packet += *packetlen;

    Header head;

    head.id = htons((unsigned short)clock());
    head.tag = htons((unsigned short)0x0000);
    head.queryNum = htons((unsigned short)1);
    head.answerNum = htons((unsigned short)0);
    head.authorNum = htons((unsigned short)0);
    head.addNum = htons((unsigned short)0);

    unsigned char *ptr = (unsigned char *)&head;
    int i;
    for (i = 0; i < 12; ++i)
    {
        *packet++ = *ptr++;
    }

    *packetlen += 12;
}

void setreshead(unsigned char *packet, int *packetlen, int id)
{
    packet += *packetlen;

    Header head;

    head.id = htons((unsigned short)id);
    head.tag = htons((unsigned short)0x8000);
    head.queryNum = htons((unsigned short)0);
    head.answerNum = htons((unsigned short)1);
    head.authorNum = htons((unsigned short)0);
    head.addNum = htons((unsigned short)0);

    unsigned char *ptr = (unsigned char *)&head;
    int i;
    for (i = 0; i < 12; ++i)
    {
        *packet++ = *ptr++;
    }

    *packetlen += 12;
}

void setaquery(unsigned char *packet, int *packetlen, unsigned char *domain)
{
    Query query1;
    
    strcpy(query1.name, domain);
    query1.qtype = htons(1);
    query1.qclass = htons(1);

    packet += *packetlen;

    int i;
    unsigned char *ptr = query1.name;
    for (i = 0; i < strlen((char *)query1.name) + 1; ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += strlen((char *)query1.name) + 1;

    *(unsigned short *)packet = query1.qtype;
    packet += 2;
    *(unsigned short *)packet = query1.qclass;

    *packetlen += 4;
}

void setrr(unsigned char *packet, int *packetlen, RR rr)
{
    packet += *packetlen;

    int i;
    unsigned char *ptr = rr.name;
    for (i = 0; i < strlen(rr.name) + 1; ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += strlen(rr.name) + 1;

    *(unsigned short *)packet = htons(rr.type);
    packet += 2;
    *(unsigned short *)packet = htons(rr._class);
    packet += 2;
    *(unsigned int *)packet = htonl(rr.ttl);
    packet += 4;
    *(unsigned short *)packet = htons(rr.data_len + 1);
    packet += 2;
    ptr = rr.rdata;
    for (i = 0; i < (rr.data_len+1); ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += rr.data_len + 10 + 1;
}
