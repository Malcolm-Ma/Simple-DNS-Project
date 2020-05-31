struct DNSHeader header;
struct DNSQuery query;
struct DNSRR rr[10];			
struct sockaddr_in clientAddr;	//???UDP?????§Ö???????
unsigned char dnsmessage[1024];//????
unsigned char* rr_ptr;			//???rr??¦Ë??
unsigned char* get_rr_ptr;		//????getRR?????
char* filename;					//?????
int socketudp;					//?????????
int err;						//????????
int len_header_query = 0;   	//?????????????????????????

void initSocket(const char* svr, const char* _filename)
{
	filename = _filename;
    //?????UDP?????
    socketudp = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(svr);
    err = bind(socketudp, (struct sockaddr*)&addr, sizeof(struct sockaddr));
    if(err < 0)
    {
        printf("bind failed: %d\n",errno);
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
        for(;; i--,j--) //??????????
        {
            if(j < 0)//rname????,?????¦Ë???????
            {
                return 1;
            }
            if(dname[i] != rname[j])//??¦Ë¦Ä?????
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
    memset(rr_ptr, 0, sizeof(dnsmessage) - len_header_query);//???????§Ö?rr????
    unsigned char* ptr = dnsmessage;
    ptr += 6;
    *((unsigned short*)ptr) = 0;//?????????????????
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
    for(;;)//??query.name????????????????
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
    while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)//???§Ó??
    {
        unsigned char rname[128];//?????????????§Ö?????????????
        unsigned char type;//???????????????????????RR??????????
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
    *((unsigned short*)ptr) = htons(htons(*((unsigned short*)ptr)) + 1);//???????????????1
    ptr = buf;
    char *pos;
    int n, len = 0;//len????????????
    pos = (char*)rname;
    /*???????›Ôbuf?§µ?buf?§Õ›¥??????????????
    ???½y?????edu.cn???›Ôbuf?§à?????3edu2cn0
    ,0?????¦Â*/
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
    /*????????A,NS,MX,CNAME??????????
    ???????????????????????????*/
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
    len = len - 2;//len - 2???????????§Ø??????????????¦Ë?????????
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
        if(rr[i].type == 15)//???MX???data?????IP???
        {
            unsigned char temp_rr[256];
            unsigned char type;//???????????????????????RR??????????
            FILE *fp;
            fp = fopen(filename, "r");
            if(fp == NULL)
            {
                printf("the file cannot be opened: %d", errno);
                exit(0);
            }
            while(fgets(temp_rr, sizeof(temp_rr), fp) != NULL)//???§Ó??
            {
                unsigned char rname[128];//?????????????§Ö?????????????
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
                    /*???????additional rr??????????RR???????????
                    ??????????????????1????????????????1*/
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
    		err = recvfrom(socketudp, dnsmessage, sizeof(dnsmessage), 0, (struct sockaddr*)&clientAddr, &len);
			break;
		}
	}
    if(err <= 0)//????0?????????????
    {
        printf("UDP socket receive failed: %d\n", errno);
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
        else//????????????A???????ùz???
        {
            sendtoSvr("", 1);
        }
    }
}

void process()
{
	while(1)
    {
        recvfromSvr(1);
        setRR();
        setAddRR();
        /*?§Ø???¨²?????????*/
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
    initSocket(ROOT, "root.txt");
    process();
    return 0;
}
