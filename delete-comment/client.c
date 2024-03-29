#include "dns.h"
#include "tools.h"

int server_socket;
unsigned char buf[512];
struct timeval start, end;

unsigned char *get_data_name(unsigned char *data)
{
	unsigned char *name = malloc(64);
	memcpy(name, data, strlen((const char *)data) + 1);

	int i = 0;
	for (; i < strlen((const char *)name); i++)
	{
		int num = name[i];
		int j;
		for (j = 0; j < num; j++)
		{
			name[i] = name[i + 1];
			i++;
		}
		name[i] = '.';
	}
	name[i - 1] = '\0';
	return name;
}

unsigned char *get_name(int *loc, unsigned char *reader)
{
	unsigned char *name = malloc(64);
	int num = 0;
	*loc = 0;

	while (*reader != 0)
	{
		name[num++] = *reader;
		reader++;
		(*loc)++;
	}
	name[num] = '\0';
	(*loc)++;

	return get_data_name(name);
}

void transform(unsigned char *query_name, unsigned char *hostname)
{
	int loc = 0;
	char host[64] = {0};
	memcpy(host, hostname, strlen((const char *)hostname));
	strcat(host, ".");

	int i;
	for (i = 0; i < strlen(host); i++)
	{
		if (host[i] == '.')
		{
			*query_name++ = (unsigned char)(i - loc);
			for (; loc < i; loc++)
			{
				*query_name++ = (unsigned char)host[loc];
			}
			loc++;
		}
	}
	*query_name = 0;
}

size_t make_rr(size_t loc, unsigned char *buf, RR *pRecord)
{
	unsigned char *name = pRecord->name;
	unsigned short type = pRecord->type;
	unsigned short class = pRecord->_class;
	unsigned int ttl = pRecord->ttl;
	unsigned short len = pRecord->data_len;
	unsigned char *data = pRecord->rdata;

	unsigned char *query_name = &buf[loc];
	transform(query_name, name);
	loc += strlen((const char *)query_name) + 1;

	type = htons(type);
	memcpy(&buf[loc], &type, sizeof(type));
	loc += sizeof(type);

	class = htons(class);
	memcpy(&buf[loc], &class, sizeof(class));
	loc += sizeof(class);

	ttl = htonl(ttl);
	memcpy(&buf[loc], &ttl, sizeof(ttl));
	loc += sizeof(ttl);

	len = htons(len);
	memcpy(&buf[loc], &len, sizeof(len));
	loc += sizeof(len);

	memcpy(&buf[loc], data, pRecord->data_len);
	loc += pRecord->data_len;

	return loc;
}

Header *make_header(unsigned short id, uint8_t qr, uint8_t rd, uint8_t rcode, unsigned short queries, unsigned short answers, unsigned short auth_rr, unsigned short add_rr)
{
	Header *header = malloc(sizeof(Header));

	if (id > 0)
		header->id = id;
	else
		header->id = (unsigned short)clock();

	header->tag = (unsigned short)0x0080;
	header->queryNum = queries;
	header->answerNum = answers;
	header->authorNum = auth_rr;
	header->addNum = add_rr;

	return header;
}

unsigned long make_packet(unsigned long loc, unsigned char *buf, Header *header, Query q1, RR **answers, RR **auths, RR **adds)
{
	unsigned short id = htons(header->id);
	memcpy(&buf[loc], &id, sizeof(id));
	loc += sizeof(id);

	unsigned short tag;
	memcpy(&tag, &(header->tag), sizeof((header->tag)));
	tag = htons(tag);
	memcpy(&buf[loc], &tag, sizeof(tag));
	loc += sizeof(tag);

	unsigned short query_num = htons(header->queryNum);
	memcpy(&buf[loc], &query_num, sizeof(query_num));
	loc += sizeof(query_num);

	unsigned short answer_num = htons(header->answerNum);
	memcpy(&buf[loc], &answer_num, sizeof(answer_num));
	loc += sizeof(answer_num);

	unsigned short auth_rr = htons(header->authorNum);
	memcpy(&buf[loc], &auth_rr, sizeof(auth_rr));
	loc += sizeof(auth_rr);

	unsigned short add_rr = htons(header->addNum);
	memcpy(&buf[loc], &add_rr, sizeof(add_rr));
	loc += sizeof(add_rr);

	int i;
	unsigned char *name = q1.name;
	unsigned short type = q1.qtype;
	unsigned short class = q1.qclass;

	unsigned char *query_name = &buf[loc];
	transform(query_name, name);
	loc += strlen((const char *)query_name) + 1;

	type = htons(type);
	memcpy(&buf[loc], &type, sizeof(type));
	loc += sizeof(type);

	class = htons(class);
	memcpy(&buf[loc], &class, sizeof(class));
	loc += sizeof(class);

	for (i = 0; i < header->answerNum; i++)
		loc = make_rr(loc, buf, answers[i]);

	for (i = 0; i < header->authorNum; i++)
		loc = make_rr(loc, buf, auths[i]);

	for (i = 0; i < header->addNum; i++)
		loc = make_rr(loc, buf, adds[i]);

	return loc;
}

RR *read_query(size_t *loc, unsigned char *reader)
{
	*loc = 0;
	int temp_loc = 0;
	Query q2;
	Query *pQuery = &q2;

	strcpy(pQuery->name, get_name(&temp_loc, reader));
	reader += temp_loc;
	*loc += temp_loc;
	reader += 4;
	*loc += 4;
}

RR *read_rr(size_t *loc, unsigned char *reader)
{
	*loc = 0;
	int temp_loc = 0;
	RR rr1;
	RR *pRecord = &rr1;

	strcpy(pRecord->name, get_name(&temp_loc, reader));
	reader += temp_loc;
	*loc += temp_loc;
	printf("Name        :	    %s \n", pRecord->name);

	memcpy(&pRecord->type, reader, sizeof(pRecord->type));
	pRecord->type = ntohs(pRecord->type);
	reader += 2;
	*loc += 2;
	printf("Type	    : 		%s \n", get_type_name(pRecord->type));

	memcpy(&pRecord->_class, reader, sizeof(pRecord->_class));
	pRecord->_class = ntohs(pRecord->_class);
	reader += 2;
	*loc += sizeof(pRecord->_class);

	memcpy(&pRecord->ttl, reader, 4);
	pRecord->ttl = ntohl(pRecord->ttl);
	reader += sizeof(pRecord->ttl);
	*loc += sizeof(pRecord->ttl);
	printf("TTL	    : 		%d\n", pRecord->ttl);

	memcpy(&pRecord->data_len, reader, sizeof(pRecord->data_len));
	pRecord->data_len = ntohs(pRecord->data_len);
	reader += sizeof(pRecord->data_len);
	*loc += sizeof(pRecord->data_len);

	unsigned char *_data = malloc(pRecord->data_len);
	bzero(_data, pRecord->data_len);
	memcpy(_data, reader, pRecord->data_len);
	strcpy(pRecord->rdata, _data);

	if (pRecord->type == DNS_TYPE_A)
	{
		struct sockaddr_in t;
		memcpy(&t.sin_addr, pRecord->rdata, sizeof(struct in_addr));
		printf("Address	    : 	    %s\n", inet_ntoa(t.sin_addr));
	}
	else if (pRecord->type == DNS_TYPE_NS)
	{
		printf("Name Server		: 		%s\n", get_name(&temp_loc, reader));
	}
	else if (pRecord->type == DNS_TYPE_CNAME)
	{
		printf("CNAME	    :	    %s\n", get_name(&temp_loc, reader));
	}
	else if (pRecord->type == DNS_TYPE_PTR)
	{
		printf("Domain Name		: 		%s\n", get_name(&temp_loc, reader));
	}
	else if (pRecord->type == DNS_TYPE_MX)
	{
		unsigned short preference;
		memcpy(&preference, pRecord->rdata, sizeof(preference));
		reader += sizeof(preference);
		printf("Preference		: 		%hu\nMail Exchange		: 		%s\n", ntohs(preference), get_name(&temp_loc, reader));
		reader -= sizeof(preference);
	}
	printf("\n");
	reader += pRecord->data_len;
	*loc += pRecord->data_len;

	return pRecord;
}

Header *read_header(size_t *loc, unsigned char *reader)
{
	*loc = 0;
	Header *header = malloc(sizeof(Header));

	memcpy(&header->id, reader, sizeof(header->id));
	header->id = ntohs(header->id);
	reader += sizeof(header->id);
	*loc += sizeof(header->id);

	unsigned short tag;
	memcpy(&tag, reader, sizeof(tag));
	tag = ntohs(tag);
	memcpy(&(header->tag), &tag, sizeof((tag)));
	reader += sizeof((header->tag));
	*loc += sizeof((header->tag));

	memcpy(&header->queryNum, reader, sizeof(header->queryNum));
	header->queryNum = ntohs(header->queryNum);
	reader += sizeof(header->queryNum);
	*loc += sizeof(header->queryNum);

	memcpy(&header->answerNum, reader, sizeof(header->answerNum));
	header->answerNum = ntohs(header->answerNum);
	reader += sizeof(header->answerNum);
	*loc += sizeof(header->answerNum);

	memcpy(&header->authorNum, reader, sizeof(header->authorNum));
	header->authorNum = ntohs(header->authorNum);
	reader += sizeof(header->authorNum);
	*loc += sizeof(header->authorNum);

	memcpy(&header->addNum, reader, sizeof(header->addNum));
	header->addNum = ntohs(header->addNum);
	reader += sizeof(header->addNum);
	*loc += sizeof(header->addNum);
	printf("%s", DIVIDING_LINE_LONG);
	if (tag == 32800)
	{
		printf("Authoritative response. \n");
	}
	else
	{
		printf("Non-authoritative response. \n");
	}
	printf("Iterative query. \n");
	printf("Server cannot do recursive queries. \n");
	printf("No error. \n");
	printf("%s", DIVIDING_LINE_SHORT);
	printf("[RESULT]\n");
	printf("tag         : 		0x%04x\n", tag);

	return header;
}

void resolve_tcp_response_packet()
{
	unsigned short length = 0;

	recv(server_socket, &length, sizeof(unsigned short), 0);
	length = ntohs(length);
	bzero(buf, length);
	recv(server_socket, buf, length, 0);

	gettimeofday(&end, NULL);
	printf("%s", DIVIDING_LINE_LONG);
	printf("Local server response in %lf seconds.\n", end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0);

	unsigned long loc = 0;
	unsigned char *reader = buf;

	Header *header = read_header(&loc, reader);
	reader += loc;

	int i;
	for (i = 0; i < header->queryNum; i++)
	{
		read_query(&loc, reader);
		reader += loc;
	}

	for (i = 0; i < header->answerNum; i++)
	{
		read_rr(&loc, reader);
		reader += loc;
	}

	for (i = 0; i < header->authorNum; i++)
	{
		read_rr(&loc, reader);
		reader += loc;
	}

	for (i = 0; i < header->addNum; i++)
	{
		read_rr(&loc, reader);
		reader += loc;
	}
}

int main(int argc, char **argv)
{
	if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		printf("socket() failed.\n");
		exit(1);
	}

	struct sockaddr_in server_add;
	memset(&server_add, 0, sizeof(struct sockaddr_in));
	server_add.sin_family = AF_INET;
	server_add.sin_port = htons(PORT);
	server_add.sin_addr.s_addr = inet_addr(LOCAL_SVR);

	connect(server_socket, (struct sockaddr *)&server_add, sizeof(server_add));

	int rd = 0;
	int query_num = 1;
	bzero(buf, 512);

	size_t loc = sizeof(unsigned short);

	Header *header = make_header(0, 0, rd, 0, query_num, 0, 0, 0);
	Query q1;
	int i;
	while (1)
	{
		char type[64];
		char name[64];
		printf("Please choose the query Type: \n");
		printf("  1. A \n  2. MX \n  3. CNAME \n");
		printf("Please input the number of your choice: ");
		scanf("%s", type);

		if (strcmp(type, "1") == 0)
		{
			q1.qtype = 1;
		}
		else if (strcmp(type, "2") == 0)
		{
			q1.qtype = 15;
		}
		else if (strcmp(type, "3") == 0)
		{
			q1.qtype = 5;
		}
		else
		{
			printf("Invalid input format, please try again. \n\n");
			continue;
		}
		printf("Please input the domain name: \n");
		scanf("%s", name);
		strcpy(q1.name, name);
		q1.qclass = 1;
		break;
	}

	RR **answers = NULL, **auths = NULL, **adds = NULL;
	loc = make_packet(loc, buf, header, q1, answers, auths, adds);
	unsigned short dns_packet_size = htons((unsigned short)(loc - 2));
	memcpy(buf, &dns_packet_size, sizeof(unsigned short));
	send(server_socket, buf, loc, 0);

	gettimeofday(&start, NULL);

	for (i = 0; i < query_num; i++)
		resolve_tcp_response_packet();

	close(server_socket);
	return 0;
}