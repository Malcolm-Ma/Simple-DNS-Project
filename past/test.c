#include <stdio.h>
#include <string.h>


void transform(unsigned char *query_name, unsigned char *hostname) {
	int loc = 0;
	char host[64] = {0};
	memcpy(host, hostname, strlen((const char *) hostname));
	strcat(host, ".");//www.bupt.edu.cn.

	int i;
	for (i = 0; i < strlen(host); i++) {
		if (host[i] == '.') {
			*query_name++ = (unsigned char) (i - loc);
			for (; loc < i; loc++) {
				*query_name++ = (unsigned char) host[loc];
			}
			loc++;
		}
	}
	*query_name = 0;
}
void formdomain(unsigned char *domain)
{
    int len = 0;
    int n =0;

    unsigned char* ptr;
    ptr = domain;
    unsigned char stddomain[64];
    for(int i =0;i<sizeof(domain);i++)
    {
        if(*(ptr+i)!='.')
        {
            stddomain[i+1]=*(domain+i);
            len++;
        }
        else
        {
            stddomain[i-len] = (unsigned char)len;
            len = 0;
        }
        ptr++;
    }
    domain = stddomain;
    printf("%s", stddomain);
}
int main ()
{
    struct Books
    {
    char  title[50];
    char  author[50];
    char  subject[100];
    int   book_id;
    };
    unsigned short a =10;
   struct Books book1;
   struct Books* p = &book1;
    unsigned char domain[64] = "avc.bupt.edu.cn\0";
    unsigned char* test;
    test = domain;
    unsigned char buf[64];
    unsigned char* test2;
    test2 = buf;
    memcpy((char*)buf,(char*)test,(size_t)64);
   printf("%s", test2);  
}

