#include "dns.h"
#include "tools.h"

Header header;
Query query;
RR rr[10];
struct sockaddr_in clientAddr;
int udp_socket, clientSocket; //套接字标识符
int err;                      //记录返回值
int len_header_query = 0;     //报头和查询请求的长度，用来清空rr部分
unsigned char dns_message[1024];
unsigned char *rr_ptr;     //记录rr的位置
unsigned char *get_rr_ptr; //用于getRR的指针

void init()
{
    //初始化UDP套接字
    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(ROOT_SVR);
    err = bind(udp_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (err < 0)
    {
        printf("bind failed: %d\n", errno);
        exit(-1);
    }
    initSucceed("Root Server");
}

void getRR(unsigned char *ptr) //结构体存储RR
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

void getMessage(int traceState) //将字符串形式的报文转换成结构体存储方式
{
    char *ptr = dns_message;
    int i, flag, num = 0; //num记录name的长度
    /*提取报头*/
    header.id = ntohs(*((unsigned short *)ptr));
    ptr += 2;
    header.tag = ntohs(*((unsigned short *)ptr));
    *((unsigned short *)ptr) = htons((unsigned short)0x8400);
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
    /*提取查询请求*/
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

/*
    从末尾匹配dname和rname,看rname是否为dname的子集
    如果类型是NS则只需要rname是dname的子集，否则需要
    每一位都匹配
*/
int containStr(const unsigned char *dname, const unsigned char *rname, const unsigned char type)
{
    int len1 = strlen(dname);
    int len2 = strlen(rname);
    int i = len1 - 1, j = len2 - 1;
    if (type == 'N')
    {
        for (;; i--, j--) //自后向前遍历
        {
            if (j < 0) //rname读完,表示每一位都匹配上
            {
                return 1;
            }
            if (dname[i] != rname[j]) //某一位未匹配上
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
    *((unsigned short *)ptr) = htons(htons(*((unsigned short *)ptr)) + 1); //报头的资源记录数加1
    ptr = buf;
    char *pos;
    int n, len = 0; //len记录域名的长度
    pos = (char *)rname;
    /*将域名存到buf中，buf中存储每个域的长度和内容
    比如当前域是edu.cn，存到buf中就变成了3edu2cn0
    ,0表示结尾*/
    for (;;)
    {
        // cn为例
        n = strlen(pos) - (strstr(pos, ".") ? strlen(strstr(pos, ".")) : 0); // 2
        *ptr++ = (unsigned char)n;                                           // 指针在 2 后
        memcpy(ptr, pos, n);                                                 // 2cn
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
    /*因为只考虑A,NS,MX,CNAME四种查询类型
    ，所以只做了匹配第一个字母的简单处理*/
    switch (pos[0])
    {
    case 'A':
    {
        rr1.type = 1;
        *((unsigned short *)rr_ptr) = htons(1);
        rr_ptr += 2;
        pos += 2;
        break;
    }
    case 'N':
    {
        rr1.type = 2;
        *((unsigned short *)rr_ptr) = htons(2);
        rr_ptr += 2;
        pos += 2;
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
        break;
    }
    }
    // IN
    *((unsigned short *)rr_ptr) = htons(1);
    rr1._class = 1;
    rr_ptr += 2;
    //
    *((unsigned short *)rr_ptr) = htonl(0);
    rr1.ttl = 0;
    rr_ptr += 4;
    len = strlen(pos);
    len = len - 1; //len - 1是因为从文件中读取的字符串最后一位是回车
    *((unsigned short *)rr_ptr) = htons(len);
    rr1.data_len = len;
    rr_ptr += 2;
    memcpy(rr_ptr, pos, len);
    rr_ptr += len;
    memcpy(rr1.rdata, pos + 1, len);

    showDNSRR(&header, &rr1);
}

/*查询文件中存储的资源记录,查询到符合要求
的则调用addRR函数，将资源记录加入到报文中*/
void setRR()
{
    unsigned char temp_rr[256];
    getMessage(1);
    //目前rr_ptr移动至header+query后面
    memset(rr_ptr, 0, sizeof(dns_message) - len_header_query); //清空报文中的rr部分
    unsigned char *ptr = dns_message;
    ptr += 6;
    *((unsigned short *)ptr) = 0; //报头的资源记录数置零
    FILE *fp;
    fp = fopen("root.txt", "r");
    if (fp == NULL)
    {
        printf("the file cannot be opened");
        exit(-1);
    }
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char *temp_ptr = query.name;
    int flag, i, num = 0;
    for (;;) //将query.name转换成标准的域名格式，如：www.baidu.com
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

    while (fgets(temp_rr, sizeof(temp_rr), fp) != NULL) //逐行查询
    {
        unsigned char rname[128]; //记录一条资源记录中第一个空格前的部分
        unsigned char type;       //记录第二个空格后的字符，也就是RR类型的首字母
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
        if (rr[i].type == 15) //找到MX对应data对应的IP地址
        {
            unsigned char temp_rr[256];
            unsigned char type; //记录第二个空格后的字符，也就是RR类型的首字母
            FILE *fp;
            fp = fopen("root.txt", "r");
            if (fp == NULL)
            {
                printf("the file cannot be opened");
                exit(-1);
            }
            while (fgets(temp_rr, sizeof(temp_rr), fp) != NULL) //逐行查询
            {
                unsigned char rname[128]; //记录一条资源记录中第一个空格前的部分
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
                    /*因为添加additional rr也是用的添加RR的函数，所以
                    需要报头的资源记录数减1，然后附加资源记录数加1*/
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

void recvQuestion() //从上一层服务器(递归解析)或Local服务器(迭代解析)接受报文
{
    memset(dns_message, 0, 1024);
    int len = sizeof(clientAddr);
    err = recvfrom(udp_socket, dns_message, sizeof(dns_message), 0, (struct sockaddr *)&clientAddr, &len);
    if (err <= 0) //等于0时表示连接已终止
    {
        printf("UDP socket receive failed: %d\n", errno);
        exit(-1);
    }
    // printf("receive message from %s\n", inet_ntoa(clientAddr.sin_addr));
    printf("收到 Local Server 请求: \n");
    dns_message[err] = '\0';
}

void sendAnswer(const unsigned char *message) //向LocalDNS服务器或上一层服务器发送报文(迭代解析)
{
    int len = sizeof(dns_message);
    err = sendto(udp_socket, message, len, 0, (struct sockaddr *)&clientAddr, sizeof(struct sockaddr));
    if (err <= 0)
    {
        printf("UDP send failed: %d\n", errno);
        exit(-1);
    }
    printf("%s", DIVIDING_LINE_LONG);
    // printf("send message to %s\n", inet_ntoa(clientAddr.sin_addr));
}

/*向下一层DNS服务器发送查询请求, svr决定目标服务器的地址(递归解析)*/
void sendQuestion(const char *message, unsigned char *svr)
{
    struct sockaddr_in destSvr;
    memset(&destSvr, 0, sizeof(destSvr));
    destSvr.sin_family = AF_INET;
    destSvr.sin_port = htons(PORT);
    destSvr.sin_addr.s_addr = inet_addr(svr);
    int len = sizeof(dns_message);
    err = sendto(udp_socket, message, len, 0, (struct sockaddr *)&destSvr, sizeof(struct sockaddr));
    if (err <= 0)
    {
        printf("send question to next dns failed: %d\n", errno);
        exit(-1);
    }
    printf("send message to %s\n", svr);
}

void recvAnswer()
{
    memset(dns_message, 0, 1024);
    struct sockaddr_in addr;
    int len = sizeof(addr);
    err = recvfrom(udp_socket, dns_message, sizeof(dns_message), 0, (struct sockaddr *)&addr, &len);
    if (err <= 0) //等于0时表示连接已终止
    {
        printf("UDP socket receive failed: %d\n", errno);
        exit(-1);
    }
    printf("receive message from %s\n", inet_ntoa(addr.sin_addr));
    dns_message[err] = '\0';
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
