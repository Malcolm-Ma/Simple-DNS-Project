#ifndef TOOL_H_INCLUDED
#define DNS_H_INCLUDED

#include "dns.h"
#include <stdio.h>

#define DIVIDING_LINE_LONG "======================================================\n\n"
#define DIVIDING_LINE_SHORT "=====================================\n"

char *get_type_name(unsigned short type)
{
	switch (type)
	{
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_CNAME:
		return "CNAME";
	case DNS_TYPE_PTR:
		return "PTR";
	case DNS_TYPE_MX:
		return "MX";
	default:
		return "Unknown";
	}
}

int initSucceed(char *serverName)
{
    printf("%s", "\033[1H\033[2J");
    printf("-> 初始化 %s 成功\n", serverName);
    printf("%s", DIVIDING_LINE_LONG);
    return 0;
}

int showDNSHeader(Header *header)
{
    printf("[DNS HEADER]\n");
    printf("ID           :      0x%04x\n", header->id);
    printf("TAG          :      0x%04x\n", header->tag);
    printf("QueryNum     :      %d\n", header->queryNum);
    printf("AnswerNum    :      %d\n", header->answerNum);
    printf("AuthorNum    :      %d\n", header->authorNum);
    printf("AddNum       :      %d\n", header->addNum);
    printf("\n");
    return 0;
}

int showDNSQuery(Query *query)
{
    unsigned char dname[128];
    memset(dname, 0, sizeof(dname));
    unsigned char *temp_ptr = query->name;
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
    printf("[DNS QUERY]\n");
    printf("Name         :      %s\n", dname);
    printf("Type         :      %s\n", get_type_name(query->qtype));
    printf("Class        :      IN\n");
    printf("\n");
    return 0;
}

int showDNSRR(Header *header, RR  *rr)
{
    printf("%s", DIVIDING_LINE_SHORT);
    if (rr->type == 2)
    {
        printf("本服务器没有找到\n\n下一级服务器信息: \n");
    }

    showDNSHeader(header);
    
    printf("[RESOURCE RECORD]\n");
    printf("Name         :      %s\n", rr->name);
    printf("Type         :      %s\n", get_type_name(rr->type));
    printf("Class        :      IN\n");
    printf("TTL          :      %d\n", rr->ttl);
    printf("Data_len     :      %d\n", rr->data_len);
    printf("IP|DOMAIN    :      %s\n", rr->rdata);
    return 0;
}

#endif