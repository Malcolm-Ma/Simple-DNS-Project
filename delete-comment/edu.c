#include "dns.h"
#include "tools.h"

Header header;
Query query;
RR rr[10];
struct sockaddr_in clientAddr;
int udp_socket, clientSocket; 
int err;                      
int len_header_query = 0;     
unsigned char dns_message[1024];
unsigned char *rr_ptr;     
unsigned char *get_rr_ptr;

void init()
{
    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(EDU_SVR);
    err = bind(udp_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (err < 0)
    {
        printf("bind failed: %d\n", errno);
        exit(-1);
    }
    initSucceed("Education Server");
}

void getRR(unsigned char *ptr)
{
    int i, flag, num;
    for (i = 0; i < header.answerNum; i++)
    {
        num = 0;
        for (;;)
        {
            flag = (int)ptr[0];
            num += (flag + 1);
            ptr += (flag + 1);
            if (flag == 0)
                break;
        }
        ptr -= num;
        memset(rr[i].name, 0, sizeof(rr[i].name));
        memcpy(rr[i].name, ptr, num - 1);
        ptr += num;
        rr[i].type = ntohs(*((unsigned short *)ptr));
        ptr += 2;
        rr[i]._class = ntohs(*((unsigned short *)ptr));
        ptr += 2;
        rr[i].ttl = ntohl(*((unsigned short *)ptr));
        ptr += 4;
        rr[i].data_len = ntohs(*((unsigned short *)ptr));
        ptr += 2;
        memset(rr[i].rdata, 0, sizeof(rr[i].rdata));
        memcpy(rr[i].rdata, ptr, rr[i].data_len);
        ptr += rr[i].data_len;
    }
    rr_ptr = ptr;
}

void getMessage(int traceState) 
{
    char *ptr = dns_message;
    int i, flag, num = 0; 
    
    header.id = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    header.tag = ntohs(*((unsigned short *)ptr));
    *((unsigned short *)ptr) = htons((unsigned short)0x8020);
    ptr += 2;
    header.queryNum = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    header.answerNum = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    header.authorNum = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    header.addNum = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    len_header_query += 12;
    
    for (i = 0; i < header.queryNum; i++)
    {
        int k = 0;
        for (;;)
        {
            flag = (int)ptr[0];
            k++;
            num += flag;
            ptr += (flag + 1);
            if (flag == 0)
                break;
        }
        ptr -= (num + k);
        memset(query.name, 0, sizeof(query.name));
        memcpy(query.name, ptr, num + k - 1);
        ptr += (num + k);
        len_header_query += (num + k);
        query.qtype = ntohs(*((unsigned short *)ptr));
        ptr += 2;
        query.qclass = ntohs(*((unsigned short *)ptr));
        rr_ptr = ptr + 2;
        len_header_query += 4;
    }

    if (traceState == 1)
    {
        showDNSHeader(&header);
        showDNSQuery(&query);
        header.tag = 0x8400;
    }

    get_rr_ptr = rr_ptr;
}

int containStr(const unsigned char *dname, const unsigned char *rname, const unsigned char type)
{
    int len1 = strlen(dname);
    int len2 = strlen(rname);
    int i = len1 - 1, j = len2 - 1;
    if (type == 'N')
    {
        for (;; i--, j--) 
        {
            if (j < 0) 
            {
                return 1;
            }
            if (dname[i] != rname[j]) 
                return -1;
        }
    }
    else
    {
        if (strcmp(dname, rname) == 0)
        {
            return 1;
        }
        return -1;
    }
}

void addRR(const unsigned char *str, const unsigned char *rname)
{
    RR rr1;
    strcpy(rr1.name, rname);
    unsigned char buf[128];
    unsigned char *ptr = dns_message;
    ptr += 6;
    *((unsigned short *)ptr) = htons(htons(*((unsigned short *)ptr)) + 1); 
    ptr = buf;
    char *pos;
    int n, len = 0; 
    pos = (char *)rname;
    
    for (;;)
    {
        n = strlen(pos) - (strstr(pos, ".") ? strlen(strstr(pos, ".")) : 0);
        *ptr++ = (unsigned char)n;
        memcpy(ptr, pos, n);
        len += n + 1;
        ptr += n;
        if (!strstr(pos, "."))
        {
            *ptr = (unsigned char)0;
            ptr++;
            len += 1;
            break;
        }
        pos += n + 1;
    }
    memcpy(rr_ptr, buf, len);
    rr_ptr += len;
    pos = (char *)str;
    pos += (len + 2);
    int flag = 0;

    switch (pos[0])
    {
    case 'A':
    {
        rr1.type = 1;
        *((unsigned short *)rr_ptr) = htons(1);
        rr_ptr += 2;
        pos += 2;
        flag = 1;
        break;
    }
    case 'N':
    {
        rr1.type = 2;
        unsigned char *_ptr = dns_message;
        _ptr += 6;
        *((unsigned short *)_ptr) = htons(htons(*((unsigned short *)_ptr)) - 1);
        _ptr += 2;
        *((unsigned short *)_ptr) = htons(htons(*((unsigned short *)_ptr)) + 1);
        *((unsigned short *)rr_ptr) = htons(2);
        rr_ptr += 2;
        pos += 3;
        break;
    }
    case 'C':
    {
        rr1.type = 5;
        *((unsigned short *)rr_ptr) = htons(5);
        rr_ptr += 2;
        pos += 6;
        break;
    }
    case 'M':
    {
        rr1.type = 15;
        *((unsigned short *)rr_ptr) = htons(15);
        rr_ptr += 2;
        pos += 3;
        flag = 2;
        break;
    }
    }
    *((unsigned short *)rr_ptr) = htons(1);
    rr1._class = 1;
    rr_ptr += 2;
    *((unsigned short *)rr_ptr) = htonl(0);
    rr1.ttl = 0;
    rr_ptr += 4;
    len = strlen(pos);
    len = len - 1;
    if (flag == 1)
    {
        *((unsigned short *)rr_ptr) = htons(4);
        rr1.data_len = 4;
        rr_ptr += 2;
        struct in_addr addr;
        char ip[32];
        memset(ip, 0, sizeof(ip));
        strcpy(rr1.rdata, pos);
        memcpy(ip, pos, len);
        inet_aton(ip, &addr);
        *((unsigned long *)rr_ptr) = addr.s_addr;
        rr_ptr += 4;
    }
    else if (flag == 2)
    {
        *((unsigned short *)rr_ptr) = htons(len + 4);
        rr1.data_len = len + 4;
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 3, 2);
        rr_ptr += 2;
        *rr_ptr = (unsigned char)len;
        rr_ptr += 1;
        strcpy(rr1.rdata, pos);
        memcpy(rr_ptr, pos, len);
        rr_ptr += len;
        memset(rr_ptr, 0, 1);
        rr_ptr++;
    }
    else
    {
        *((unsigned short *)rr_ptr) = htons(len + 20);
        rr1.data_len = len + 20;
        rr_ptr += 2;
        strcpy(rr1.rdata, pos);
        memcpy(rr_ptr, pos - 1, len + 2);
        rr_ptr += (len + 2);
    }

    header.tag = 0x8020;
    header.queryNum = 0;
    header.answerNum = 1;
    showDNSRR(&header, &rr1);
}

void setRR()
{
    unsigned char temp_rr[256];
    getMessage(1);
    memset(rr_ptr, 0, sizeof(dns_message) - len_header_query);
    unsigned char *ptr = dns_message;
    ptr += 6;
    *((unsigned short *)ptr) = 0;
    FILE *fp;
    fp = fopen("edu.txt", "r");
    if (fp == NULL)
    {
        printf("the file cannot be opened");
        exit(-1);
    }
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char *temp_ptr = query.name;
    int flag, i, num = 0;
    for (;;) 
    {
        flag = (int)temp_ptr[0];
        for (i = 0; i < flag; i++)
        {
            dname[i + num] = temp_ptr[i + 1];
        }
        temp_ptr += (flag + 1);
        if ((int)temp_ptr[0] == 0)
            break;
        dname[flag + num] = '.';
        num += (flag + 1);
    }
    while (fgets(temp_rr, sizeof(temp_rr), fp) != NULL) 
    {
        unsigned char rname[128]; 
        unsigned char type; 
        memset(rname, 0, sizeof(rname));
        int len = strlen(temp_rr);
        for (i = 0; i < len; i++)
        {
            if (temp_rr[i] == ' ')
                break;
        }
        memcpy(rname, temp_rr, i);
        int numofspace = 0;
        for (i = 0; i < len; i++)
        {
            if (temp_rr[i] == ' ')
                numofspace++;
            if (temp_rr[i] == ' ' && numofspace == 2)
                break;
        }
        type = temp_rr[i + 1];
        if (containStr(dname, rname, type) == 1)
        {
            addRR(temp_rr, rname);
        }
        memset(temp_rr, 0, sizeof(temp_rr));
    }
    err = fclose(fp);
    if (err == EOF)
    {
        printf("The file close failed");
        exit(-1);
    }
}

void addaddrr()
{
    getMessage(0);
    getRR(rr_ptr);
    int i, j;
    for (j = 0; j < header.answerNum; j++)
    {
        if (rr[i].type == 15)
        {
            unsigned char temp_rr[256];
            unsigned char type; 
            FILE *fp;
            fp = fopen("edu.txt", "r");
            if (fp == NULL)
            {
                printf("the file cannot be opened");
                exit(-1);
            }
            while (fgets(temp_rr, sizeof(temp_rr), fp) != NULL) 
            {
                unsigned char rname[128]; 
                memset(rname, 0, sizeof(rname));
                int len = strlen(temp_rr);
                for (i = 0; i < len; i++)
                {
                    if (temp_rr[i] == ' ')
                        break;
                }
                memcpy(rname, temp_rr, i);
                int numofspace = 0;
                for (i = 0; i < len; i++)
                {
                    if (temp_rr[i] == ' ')
                        numofspace++;
                    if (temp_rr[i] == ' ' && numofspace == 2)
                        break;
                }
                type = temp_rr[i + 1];
                if (containStr(rr[j].rdata, rname, type) == 1)
                {
                    addRR(temp_rr, rname);
                    unsigned char *ptr = dns_message;
                    ptr += 6;
                    
                    *((unsigned short *)ptr) = htons(htons(*((unsigned short *)ptr)) - 1);
                    ptr += 4;
                    *((unsigned short *)ptr) = htons(htons(*((unsigned short *)ptr)) + 1);
                }
                memset(temp_rr, 0, sizeof(temp_rr));
            }
            err = fclose(fp);
            if (err == EOF)
            {
                printf("The file close failed");
                exit(-1);
            }
            break;
        }
    }
}

void recvQuestion() 
{
    memset(dns_message, 0, 1024);
    int len = sizeof(clientAddr);
    err = recvfrom(udp_socket, dns_message, sizeof(dns_message), 0, (struct sockaddr *)&clientAddr, &len);
    if (err <= 0) 
    {
        printf("UDP socket receive failed: %d\n", errno);
        exit(-1);
    }
    dns_message[err] = '\0';
}

void sendAnswer(const unsigned char *message)
{
    int len = sizeof(dns_message);
    err = sendto(udp_socket, message, len, 0, (struct sockaddr *)&clientAddr, sizeof(struct sockaddr));
    if (err <= 0)
    {
        printf("UDP send failed: %d\n", errno);
        exit(-1);
    }
    printf("%s", DIVIDING_LINE_LONG);
}

int main()
{
    init();
    while (1)
    {
        recvQuestion();
        setRR();
        addaddrr();
        sendAnswer(dns_message);
    }
    closesocket(udp_socket);
    closesocket(clientSocket);
    return 0;
}
