#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <memory.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dns.h>

struct DNS_Head header;
struct DNS_Query query;
struct DNS_RR rr[10];			
struct sockaddr_in clientAddr;	//��¼UDP�����еĿͻ��˵�ַ
unsigned char dnsmessage[1024];//����
unsigned char udpsendpacket[1024];// 发给服务器的数据缓存区
unsigned char* rr_ptr;			//��¼rr��λ��
unsigned char* get_rr_ptr;		//����getRR��ָ��	
int socketudp;					//�׽��ֱ�ʶ��
int err;						//��¼����ֵ
int len_header_query = 0;   	//��¼��������Դ��¼֮ǰ���ֵĳ���
int tcpsendpos,tcprecvpos, udpsendpos, udprecvpos;
unsigned char ip[64];

void initSocket()
{
    socketudp = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    //为socket生成地址
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr("127.0.0.3");
    //绑定
    err = bind(socketudp, (struct sockaddr*)&addr, sizeof(struct sockaddr));
    if(err < 0)
    {
        perror("udpsocket bind failed");
        exit(0);
    }
}

int containStr(const unsigned char* dname, const unsigned char* rname, const unsigned char type)
{
    int len1 = strlen(dname);
    int len2 = strlen(rname);
    int i = len1 - 1, j = len2 - 1;
    if(type == 'N')
    {
        for(;; i--,j--) //�Ժ���ǰ����
        {
            if(j < 0)//rname����,��ʾÿһλ��ƥ����
            {
                return 1;
            }
            if(dname[i] != rname[j])//ĳһλδƥ����
                return -1;
        }
    }
    else
    {
        if(strcmp(dname, rname) == 0)
        {
            return 1;
        }
        return -1;
    }
}

void setRR()
{
    unsigned char temp_rr[256];
    rr_ptr = getMessage(&header, &query, dnsmessage, &len_header_query);
    get_rr_ptr = rr_ptr;
    memset(rr_ptr, 0, sizeof(dnsmessage) - len_header_query);//��ձ����е�rr����
    unsigned char* ptr = dnsmessage;
    ptr += 6;
    *((unsigned short*)ptr) = 0;//��ͷ����Դ��¼������
    ptr += 2;
    *((unsigned short*)ptr) = 0;
    FILE *fp;
    fp = fopen(filename, "r");
    if(fp == NULL)
    {
        printf("the file cannot be opened: %d\n", errno);
        exit(0);
    }
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char* temp_ptr = query.name;
    int flag, i, num = 0;
    for(;;)//��query.nameת���ɱ�׼��������ʽ
    {
        flag = (int)temp_ptr[0];
        for(i = 0; i < flag; i++)
        {
            dname[i + num] = temp_ptr[i + 1];
        }
        temp_ptr += (flag + 1);
        if((int)temp_ptr[0] == 0)
            break;
        dname[flag + num] = '.';
        num += (flag + 1);
    }
    while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)//���в�ѯ
    {
        unsigned char rname[128];//��¼һ����Դ��¼�е�һ���ո�ǰ�Ĳ���
        unsigned char type;//��¼�ڶ����ո����ַ���Ҳ����RR���͵�����ĸ
        memset(rname, 0, sizeof(rname));
        int len = strlen(temp_rr);
        for(i = 0; i < len; i++)
        {
            if(temp_rr[i] == ' ')
                break;
        }
        memcpy(rname, temp_rr, i);
        int numofspace = 0;
        for(i = 0; i < len; i++)
        {
            if(temp_rr[i] == ' ')
                numofspace++;
            if(temp_rr[i] == ' ' && numofspace == 2)
                break;
        }
        type = temp_rr[i + 1];
        if(containStr(dname, rname, type) == 1)
        {
            addRR(temp_rr, rname);
        }
        memset(temp_rr, 0, sizeof(temp_rr));
    }
    err = fclose(fp);
    if(err == EOF)
    {
        printf("The file close failed: %d\n", errno);
        exit(0);
    }
}

void addRR(const unsigned char* str, const unsigned char* rname)
{
    unsigned char buf[128];
    unsigned char* ptr = dnsmessage;
    ptr += 6;
    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);//��ͷ����Դ��¼����1
    ptr = buf;
    char *pos;
    int n, len = 0;//len��¼�����ĳ���
    pos = (char*)rname;
    /*�������浽buf�У�buf�д洢ÿ����ĳ��Ⱥ�����
    ���統ǰ����edu.cn���浽buf�оͱ����3edu2cn0
    ,0��ʾ��β*/
    for(;;)
    {
        n = strlen(pos) - (strstr(pos , ".") ? strlen(strstr(pos , ".")) : 0);
        *ptr ++ = (unsigned char)n;
        memcpy(ptr , pos , n);
        len += n + 1;
        ptr += n;
        if(!strstr(pos , "."))
        {
            *ptr = (unsigned char)0;
            ptr ++;
            len += 1;
            break;
        }
        pos += n + 1;
    }
    memcpy(rr_ptr, buf, len);
    rr_ptr += len;
    pos = (char*)str;
    pos += (len + 2);
    int flag = 0;
    /*��Ϊֻ����A,NS,MX,CNAME���ֲ�ѯ����
    ������ֻ����ƥ���һ����ĸ�ļ򵥴���*/
    switch(pos[0])
    {
    case'A':
    {
        *((unsigned short*)rr_ptr) = htons(1);
        rr_ptr += 2;
        pos += 2;
        flag = 1;
        break;
    }
    case'N':
    {
    	unsigned char* _ptr = dnsmessage;
        _ptr += 6;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) - 1);
        _ptr += 2;
        *((unsigned short*)_ptr) = htons(htons(*((unsigned short*)_ptr)) + 1);
        *((unsigned short*)rr_ptr) = htons(2);
        rr_ptr += 2;
        pos += 3;
        break;
    }
    case'C':
    {
        *((unsigned short*)rr_ptr) = htons(5);
        rr_ptr += 2;
        pos += 6;
        break;
    }
    case'M':
    {
        *((unsigned short*)rr_ptr) = htons(15);
        rr_ptr += 2;
        pos += 3;
        flag = 2;
        break;
    }
    }
    *((unsigned short*)rr_ptr) = htons(1);
    rr_ptr += 2;
    *((unsigned short*)rr_ptr) = htonl(0);
    rr_ptr += 4;
    len = strlen(pos);
    len = len - 2;//len - 2����Ϊ���ļ��ж�ȡ���ַ��������λ�ǻس��ӻ���
    if (flag == 1)
    {
        *((unsigned short*)rr_ptr) = htons(4);
        rr_ptr += 2;
        struct in_addr addr;
        char ip[32];
        memset(ip, 0, sizeof(ip));
        memcpy(ip, pos, len);
        inet_aton(ip, &addr);
        *((unsigned long*)rr_ptr) = addr.s_addr;
        rr_ptr += 4;
    }
    else if(flag == 2)
    {
    	*((unsigned short*)rr_ptr) = htons(len);
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 3, 2);
        rr_ptr += 2;
        *rr_ptr = (unsigned char)len;
        rr_ptr += 1;
        memcpy(rr_ptr, pos, len);
        rr_ptr += len;
        memset(rr_ptr, 0, 1);
        rr_ptr++;
    }
    else
    {
        *((unsigned short*)rr_ptr) = htons(len);
        rr_ptr += 2;
        memcpy(rr_ptr, pos - 1, len + 1);
        rr_ptr += (len + 1);
    }
}

void setAddRR()
{
    rr_ptr = getMessage(&header, &query, dnsmessage, &len_header_query);
    rr_ptr = getRR(rr, &header, rr_ptr);
    rr_ptr++;
    int i, j;
    for(j = 0; j < header.answerNum; j++)
    {
        if(rr[i].type == 15)//�ҵ�MX��Ӧdata��Ӧ��IP��ַ
        {
            unsigned char temp_rr[256];
            unsigned char type;//��¼�ڶ����ո����ַ���Ҳ����RR���͵�����ĸ
            FILE *fp;
            fp = fopen(filename, "r");
            if(fp == NULL)
            {
                printf("the file cannot be opened: %d", errno);
                exit(0);
            }
            while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)//���в�ѯ
            {
                unsigned char rname[128];//��¼һ����Դ��¼�е�һ���ո�ǰ�Ĳ���
                memset(rname, 0, sizeof(rname));
                int len = strlen(temp_rr);
                for(i = 0; i < len; i++)
                {
                    if(temp_rr[i] == ' ')
                        break;
                }
                memcpy(rname, temp_rr, i);
                int numofspace = 0;
                for(i = 0; i < len; i++)
                {
                    if(temp_rr[i] == ' ')
                        numofspace++;
                    if(temp_rr[i] == ' ' && numofspace == 2)
                        break;
                }
                type = temp_rr[i + 1];
                if(containStr(rr[j].rdata, rname, type) == 1)
                {
                    addRR(temp_rr, rname);
                    unsigned char* ptr = dnsmessage;
                    ptr += 6;
                    /*��Ϊ����additional rrҲ���õ�����RR�ĺ���������
                    ��Ҫ��ͷ����Դ��¼����1��Ȼ�󸽼���Դ��¼����1*/
                    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) - 1);
                    ptr += 4;
                    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);
                }
                memset(temp_rr, 0, sizeof(temp_rr));
            }
            err = fclose(fp);
            if(err == EOF)
            {
                printf("The file close failed: %d", errno);
                exit(0);
            }
            break;
        }
    }
}

void recvfromSvr(int flag)
{
	memset(dnsmessage, 0, 1024);
	switch(flag)
	{
		case 0:
		{
			struct sockaddr_in addr;
    		int len = sizeof(addr);
    		err = recvfrom(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&addr, &len);
			break;
		}
		case 1:
		{
			int len = sizeof(clientAddr);
            //clientAddr中接收到了local的地址结构
    		err = recvfrom(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, &len);
			break;
		}
	}
    if(err <= 0)//����0ʱ��ʾ��������ֹ
    {
        perror("UDP socket receive failed");
        exit(0);
    }
    int i;
}

void sendtoSvr(const unsigned char* svr, int flag)
{
	switch(flag)
	{
		case 0:
		{
            unsigned char* ptr = dnsmessage;
            ptr += 2;
            if (*((unsigned short*)ptr) == htons(0x8080))
            {
                *((unsigned short*)ptr) = htons(0x0080);
            }
            else if(*((unsigned short*)ptr) == htons(0x8180))
            {
                *((unsigned short*)ptr) = htons(0x0180);
            }
			struct sockaddr_in destSvr;
		    memset(&destSvr, 0, sizeof(destSvr));
		    destSvr.sin_family = AF_INET;
		    destSvr.sin_port = htons(PORT);
		    destSvr.sin_addr.s_addr = inet_addr(svr);
		    int len = sizeof(dnsmessage);
		    err = sendto(socketudp, dnsmessage, len, 0, (struct sockaddr*)&destSvr, sizeof(struct sockaddr));
			break;
		}
		case 1:
		{
            unsigned char* ptr = dnsmessage;
            ptr += 2;
            if (*((unsigned short*)ptr) == htons(0x0080))
            {
                *((unsigned short*)ptr) = htons(0x8080);
            }
            else if(*((unsigned short*)ptr) == htons(0x0180))
            {
                *((unsigned short*)ptr) = htons(0x8180);
            }
			err = sendto(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, sizeof(struct sockaddr));
		}
	}
	if(err <= 0)
    {
        printf("send question to next dns failed: %d\n", errno);
        exit(0);
    }
}

void iterantion()
{
    printf("\nITERATION\n");
    sendtoSvr("", 1);
}

void recursion()
{
    printf("\nRECURSION\n");
    rr_ptr = getRR(rr, &header, get_rr_ptr);
    int i;
    for(i = 0; i < header.answerNum; i++)
    {
        if(rr[i].type == 2)
        {
            sendtoSvr(rr[i].rdata, 0);
            recvfromSvr(0);
            sendtoSvr("", 1);
        }
        else//�����ѯ���Ͳ�ΪA��ʾ�Ѿ��鵽���
        {
            sendtoSvr("", 1);
        }
    }
}

void gethead(unsigned char* packet, int* packetlen, struct DNS_Head* head)
{
    packet += *packetlen;//整个报文需要向后移动两个元素以读取

    //将packet中数据强制转换类型并让head指向packet
    *head = *(struct DNS_Head*)packet;

    //网络字节序转换为主机字节序
    head->id = ntohs(head->id);
    head->tag = ntohs(head->tag);
    head->queryNum = ntohs(head->queryNum);
    head->answerNum = ntohs(head->answerNum);
    head->authorNum = ntohs(head->authorNum);
    head->addNum = ntohs(head->addNum);

    *packetlen += 12;// 2+12=14，每项两个字节*6 = 12
}

void getquery(unsigned char* packet, int* packetlen, struct DNS_Query* query)
{
    packet += *packetlen;//（header部分+2）以读取query

    query->qname = packet;// name长度不固定
    *packetlen += strlen(packet) + 1;//加上结束符 /0
    //继续读取
    packet += strlen(packet) + 1;
    query->qtype = ntohs(*(unsigned short*)packet);
    packet += 2;
    query->qclass = ntohs(*(unsigned short*)packet);

    *packetlen += 4;//2*2
}
void findRR(unsigned char* qname)
{
    int i = 0;
    int m = 0;
    int len = strlen(qname);
    char name[len-1];
    char *ptr = NULL;

    for(int i =0; i<= (len-1); i++)
    {
        name[i] = *qname++;
    }
    for(int m =0;m<=(len-1);m++)
    {
        if((strstr(name,"com"))!= NULL)
        {
            ptr = strstr(name,"com");
        }
        else if((strstr(name,"cn"))!= NULL)
        {
            ptr = strstr(name,"cn");
        }
        else if((strstr(name,"gov"))!= NULL)
        {
            ptr = strstr(name,"gov");
        }
        else
        {
            ptr = strstr(name,"org");
        }
    }


}

void process()
{
	while(1)
    {
        recvfromSvr(1);
        udprecvpos = 0;
        gethead(dnsmessage, &udprecvpos, &header);
        getquery(dnsmessage, &udprecvpos, &query);
        findRR(query.qname);
        setheader();
        setRR();
        setAddRR();
        sendtoSvr();
        /*�ж�ʹ�ú��ֽ�����ʽ*/
        if(header.tag == 0x0080)
        {
            iterantion();
        }
        else if(header.tag == 0x0180)
        {
            recursion();
        }
    }
}
int main()
{
    initSocket();
    process();
    return 0;
}
