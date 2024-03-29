#include "dns.h"

//DNS服务器ip
unsigned char ip[64];
//包缓存
unsigned char tcpsendpacket[1024] = {0}; // 发给client的数据缓存区
unsigned char tcprecvpacket[1024]; // client发来的数据缓存区
unsigned char udpsendpacket[1024]; // 发给服务器的数据缓存区
unsigned char udprecvpacket[1024]; // 服务器发来的数据缓存区
//包位置、长度
int tcpsendpos, tcprecvpos, udpsendpos, udprecvpos;
//rr缓存
RR rrdb[4];
int rrnum;
unsigned char db[1024];
unsigned char *dbptr;
//函数表
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
    //初始化socket
    int tcpServerSocket, tcpClientSocket;
    struct sockaddr_in tcpServerAddr, tcpClientAddr;
    int tcpaddrlen;

    int udpSocket;
    struct sockaddr_in udpRemoteAddr;
    int udpaddrlen;

    tcpServerSocket = socket(AF_INET, SOCK_STREAM, 0); // 协议族，socket类型，protocol（通常为0）
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);        // tcp:stream,udp:dgram
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

    //开始赋值
    //TCP设置
    tcpServerAddr.sin_family = AF_INET; //地址族
    tcpServerAddr.sin_port = htons(53); //网络字节序
    tcpServerAddr.sin_addr.s_addr = inet_addr(LOCAL_SVR);
    //UDP设置
    udpRemoteAddr.sin_family = AF_INET;
    udpRemoteAddr.sin_port = htons(PORT);

    //配置socket
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
    listen(tcpServerSocket, 4); //sockfd, backlog(缺省值20)
    tcpaddrlen = sizeof(struct sockaddr_in);
    udpaddrlen = sizeof(struct sockaddr_in);
    //开始计时
    clock();
    //初始化缓存
    rrnum = 0;
    dbptr = db;

    while (1)
    {
        //接受连接，睡眠等待客户请求
        tcpClientSocket = accept(tcpServerSocket, (struct sockaddr *)&tcpClientAddr, &tcpaddrlen);
        //初始化rootDNS服务器ip
        strcpy(ip, ROOT_SVR);
        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
        //接受client报文
        recv(tcpClientSocket, tcprecvpacket, sizeof(tcprecvpacket), 0); // flags为0
        printf("server recv packet from client\n");

        Header head;
        Query query;
        RR rr;
        //解析client TCP报文
        tcprecvpos = 2; //TCP额外的2字节
        gethead(tcprecvpacket, &tcprecvpos, &head);
        getquery(tcprecvpacket, &tcprecvpos, &query);
        //查询缓存
        int i;
        for (i = 0; i < rrnum; ++i)
        {
            if (strcmp(rrdb[i].name, query.name) == 0 && rrdb[i].type == query.qtype)
            {
                printf("using cache\n");
                tcpsendpos = 2;
                setreshead(tcpsendpacket, &tcpsendpos, head.id);
                // setaquery(tcpsendpacket, &tcpsendpos, query.name);
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

        //生成查询报文，准备向根域请求
        for (i = 2; i < sizeof(tcprecvpacket); ++i)
        {
            //将移动的两个字节移动回来
            udpsendpacket[i - 2] = tcprecvpacket[i];
        }
        udpsendpos = tcprecvpos - 2;

        while (1)
        {
            int flag = 0;
            //向根域发送DNS请求报文,udp
            sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr *)&udpRemoteAddr, sizeof(struct sockaddr));
            printf("server send packet to %s\n", ip);
            //接受报文
            recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr *)&udpRemoteAddr, &udpaddrlen);
            printf("server recv packet from %s\n", ip);
            //解析报文
            udprecvpos = 0;
            gethead(udprecvpacket, &udprecvpos, &head);
            getquery(udprecvpacket, &udprecvpos, &query);
            getrr(udprecvpacket, &udprecvpos, &rr);

            switch (head.tag)
            {
            case (unsigned short)0x8020: //回答是结果
                for (i = 2; i < sizeof(udprecvpacket); ++i)
                {
                    //生成给client的报文，空2个字节
                    tcpsendpacket[i] = udprecvpacket[i - 2];
                }
                tcpsendpos = udprecvpos + 2;
                //将长度写在TCP报文前两个字节
                *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);

                if (rr.type == 1 || rr.type == 2) //A或者NS类型的查询
                {
                    flag = 1;
                    break;
                }
                else if (rr.type == 5) //CNAME类型的查询
                {
                    Header h1;
                    Query q1;
                    udpsendpos = 0;
                    gethead(udpsendpacket, &udpsendpos, &h1);
                    getquery(udpsendpacket, &udpsendpos, &q1);
                    if (q1.qtype == 5) //发送的查询是CNAME
                    {
                        flag = 1;
                        break;
                    }
                    else if (q1.qtype == 1) //发送的查询是A 进行第二次查询
                    {
                        //生成查询报文
                        unsigned char domain[64];
                        strcpy(domain, rr.rdata);
                        formdomain(domain);

                        udpsendpos = 0;
                        //生成A类型UDP查询报文
                        setstdhead(udpsendpacket, &udpsendpos);
                        setaquery(udpsendpacket, &udpsendpos, domain);
                        //初始化DNS服务器地址
                        strcpy(ip, ROOT_SVR);
                        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                        //查询
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
                                //更新ip地址，若为NS类型，则继续向下一服务器进行请求
                                strcpy(ip, r2.rdata);
                                udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                            }
                            else if (r2.type == 1)
                            {
                                //查到A记录，证明查到
                                for (i = 2; i < sizeof(udprecvpacket); ++i)
                                {
                                    //生成TCP报文，准备返回给client
                                    tcpsendpacket[i] = udprecvpacket[i - 2];
                                }
                                tcpsendpos = udprecvpos + 2;
                                //报文长度放在包前面两个字节
                                *(unsigned short *)tcpsendpacket = htons(tcpsendpos - 2);
                                flag = 1;
                                break;
                            }
                        }
                        break;
                    }
                }
                else if (rr.type == 15) //MX类型的查询 进行第二次查询
                {
                    //生成查询报文
                    unsigned char domain[64];
                    strcpy(domain, rr.rdata);
                    printf("domain:%s\n", domain);
                    formdomain(domain);
                    memset(udpsendpacket,0,sizeof(udpsendpacket));
                    udpsendpos = 0;
                    setstdhead(udpsendpacket, &udpsendpos);
                    setaquery(udpsendpacket, &udpsendpos, domain);
                    //初始化DNS服务器ip
                    strcpy(ip, ROOT_SVR);
                    udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                    //查询
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
            case (unsigned short)0x8400: //回答是另一个DNS服务器
                if (rr.type == 2)       //NS
                {
                    //设置新的ip地址
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
         //   memcpy(rrdb[rrnum].name, dbptr, sizeof(dbptr));
            dbptr += strlen(dbptr) + 1;
            strcpy(dbptr, rrdb[rrnum].rdata);
           // memcpy(rrdb[rrnum].rdata, dbptr, sizeof(dbptr));
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
    packet += *packetlen; //TCP整个报文需要向后移动两个元素以读取,UDP此处为0

    //将packet中数据强制转换类型并让head指向packet
    *head = *(Header *)packet;

    //网络字节序转换为主机字节序
    head->id = ntohs(head->id);
    head->tag = ntohs(head->tag);
    head->queryNum = ntohs(head->queryNum);
    head->answerNum = ntohs(head->answerNum);
    head->authorNum = ntohs(head->authorNum);
    head->addNum = ntohs(head->addNum);

    *packetlen += 12; // 2+12=14，每项两个字节*6 = 12
}

void getquery(unsigned char *packet, int *packetlen, Query *query)
{
    packet += *packetlen; //（header部分+12）以读取query
    
    strcpy(query->name, packet);      // name长度不固定
    *packetlen += strlen(packet) + 1; //加上结束符 /0
    //继续读取
    packet += strlen(packet) + 1;
    query->qtype = ntohs(*(unsigned short *)packet);
    packet += 2;
    query->qclass = ntohs(*(unsigned short *)packet);

    *packetlen += 4; //2*2
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
    rr->data_len = ntohs(*(unsigned short *)packet) - 1; //减掉data最后的‘/0’
    packet += 2;
    if (rr->type == 15)
    {
        //MX类型多preference field,多移动两个字节
        packet += 3;
        strcpy(rr->rdata, packet);
    } else {
        packet++;
        strcpy(rr->rdata, packet);
    }

    *packetlen += rr->data_len + 10 + 1; //计算长度时加回来
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
    rr->data_len = ntohs(*(unsigned short *)packet) - 1; //减掉data最后的‘/0’
    packet += 2;
    if (rr->type == 2)
    {
        packet++;
        strcpy(rr->rdata, packet);
    } else {
        strcpy(rr->rdata, packet);
    }

    *packetlen += rr->data_len + 10 + 1; //计算长度时加回来
}

void setstdhead(unsigned char *packet, int *packetlen)
{
    packet += *packetlen;

    Header head;

    //主机字节序转网络字节序以传输
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
        //将header赋值进packet中
        *packet++ = *ptr++;
    }

    //更新pakcetlen
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
    query1.qtype = htons(1); //A
    query1.qclass = htons(1);

    //移动指针，准备query
    packet += *packetlen;

    int i;
    unsigned char *ptr = query1.name;
    for (i = 0; i < strlen((char *)query1.name) + 1; ++i)
    {
        //query放入packet
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
