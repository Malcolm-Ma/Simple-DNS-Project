#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <memory.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_TYPE_A                              1
#define DNS_TYPE_NS                             2
#define DNS_TYPE_CNAME                          5
#define DNS_TYPE_PTR                            12
#define DNS_TYPE_MX                             15

//Client

struct header_flags { //大小端字节序
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;

	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
};

struct header {
	unsigned short id;
	// struct header_flags *flags;
    unsigned short tag;
	unsigned short queries;
	unsigned short answers;
	unsigned short auth_rr;
	unsigned short add_rr;
};

struct query {
	unsigned char name[128];
	unsigned short type;
	unsigned short class;
};

struct record {
	unsigned char name[128];
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short len;
	unsigned char data[128];
};

//DNS Local Server的socket
int server_socket;

//Buffer
unsigned char buf[512];

//记录发送出请求和接收回应的时刻
struct timeval start, end;

//逆转换域名
unsigned char *get_data_name(unsigned char *data) {
	unsigned char *name = malloc(64);
	memcpy(name, data, strlen((const char *) data) + 1);

	//3www5baidu3com0 -> www.baidu.com
	int i = 0;
	for (; i < strlen((const char *) name); i++) {
		int num = name[i];
		int j;
		for (j = 0; j < num; j++) {
			name[i] = name[i + 1];
			i++;
		}
		name[i] = '.';
	}
	name[i - 1] = '\0';
	return name;
}

//读取域名  3www5baidu3com0
unsigned char *get_name(int *loc, unsigned char *reader) {
	unsigned char *name = malloc(64);
	int num = 0;

	*loc = 0;

	while (*reader != 0) {
		name[num++] = *reader;
		reader++;
	}
	name[num] = '\0';
	(*loc)++;

	return get_data_name(name);
}

char *ptr(char *ip) {
	char *suffix = "in-addr.arpa";

	char *result = malloc(64);
	bzero(result, 64);
	char temp[4][4] = {0};

	char string[64] = {0};
	memcpy(string, ip, strlen(ip));

	char *token = strtok(string, ".");
	int i;
	for (i = 0; i < 4; i++) {
		memcpy(temp[3 - i], token, strlen(token));
		strcat(temp[3 - i], ".");
		token = strtok(NULL, ".");
	}
	for (i = 0; i < 4; i++) {
		strcat(result, temp[i]);
	}
	strcat(result, suffix);

	return result;
}

//转换域名
void transform(unsigned char *query_name, unsigned char *hostname) {
	int loc = 0;
	char host[64] = {0};
	memcpy(host, hostname, strlen((const char *) hostname));
	strcat(host, ".");

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

size_t make_rr(size_t loc, unsigned char *buf, struct record *pRecord) {
	unsigned char *name = pRecord->name;
	uint16_t type = pRecord->type;
	uint16_t class = pRecord->class;
	uint32_t ttl = pRecord->ttl;
	uint16_t len = pRecord->len;
	unsigned char *data = pRecord->data;

	//Query Name
	unsigned char *query_name = &buf[loc];
	transform(query_name, name);
	loc += strlen((const char *) query_name) + 1;

	//Type
	type = htons(type);
	memcpy(&buf[loc], &type, sizeof(type));
	loc += sizeof(type);

	//Class
	class = htons(class);
	memcpy(&buf[loc], &class, sizeof(class));
	loc += sizeof(class);

	//TTL
	ttl = htonl(ttl);
	memcpy(&buf[loc], &ttl, sizeof(ttl));
	loc += sizeof(ttl);

	//Length
	len = htons(len);
	memcpy(&buf[loc], &len, sizeof(len));
	loc += sizeof(len);

	//Data
	memcpy(&buf[loc], data, pRecord->len);
	loc += pRecord->len;

	return loc;
}

//Header
struct header *make_header(uint16_t id, uint8_t qr, uint8_t rd, uint8_t rcode, uint16_t queries, uint16_t answers, uint16_t auth_rr, uint16_t add_rr) {
	struct header *header = malloc(sizeof(struct header));

	if (id > 0)
		header->id = id;
	else
		header->id = (uint16_t) clock(); //clock()的作用是获得时间，在这里的作用只是用作随机数

        header->tag = (unsigned short)0x0080;
	// header->flags = malloc(sizeof(struct header_flags));
	// header->flags->qr = qr;
	// header->flags->opcode = 0;
	// header->flags->aa = 0;
	// header->flags->tc = 0;
	// header->flags->rd = rd; //0迭代 1递归
	// header->flags->ra = 1;
	// header->flags->z = 0;
	// header->flags->rcode = rcode;

	header->queries = queries;
	header->answers = answers;
	header->auth_rr = auth_rr;
	header->add_rr = add_rr;

	return header;
}

//DNS packet
size_t make_packet(size_t loc, unsigned char *buf, struct header *header, struct query **queries, struct record **answers, struct record **auths, struct record **adds) {
	//Transaction ID
	unsigned short id = htons(header->id);
	memcpy(&buf[loc], &id, sizeof(id));
	loc += sizeof(id);

	//Flags
	unsigned short tag;
	memcpy(&tag, &(header->tag), sizeof((header->tag)));
	tag = htons(tag);
	memcpy(&buf[loc], &tag, sizeof(tag));
	loc += sizeof(tag);

	//Number of queries in packet
	unsigned short query_num = htons(header->queries);
	memcpy(&buf[loc], &query_num, sizeof(query_num));
	loc += sizeof(query_num);

	//Number of answers in packet
	unsigned short answer_num = htons(header->answers);
	memcpy(&buf[loc], &answer_num, sizeof(answer_num));
	loc += sizeof(answer_num);

	//Number of authoritative records in packet
	unsigned short auth_rr = htons(header->auth_rr);
	memcpy(&buf[loc], &auth_rr, sizeof(auth_rr));
	loc += sizeof(auth_rr);

	//Number of additional records in packet
	unsigned short add_rr = htons(header->add_rr);
	memcpy(&buf[loc], &add_rr, sizeof(add_rr));
	loc += sizeof(add_rr);

	int i;
	for (i = 0; i < header->queries; i++) {
		unsigned char *name = queries[i]->name;
		unsigned short type = queries[i]->type;
		unsigned short class = queries[i]->class;

		//Query Name
		unsigned char *query_name = &buf[loc];
		transform(query_name, name);
		loc += strlen((const char *) query_name) + 1;

		//Query Type
		type = htons(type);
		memcpy(&buf[loc], &type, sizeof(type));
		loc += sizeof(type);

		//Query Class
		class = htons(class);
		memcpy(&buf[loc], &class, sizeof(class));
		loc += sizeof(class);
	}

	for (i = 0; i < header->answers; i++)
		loc = make_rr(loc, buf, answers[i]);

	for (i = 0; i < header->auth_rr; i++)
		loc = make_rr(loc, buf, auths[i]);

	for (i = 0; i < header->add_rr; i++)
		loc = make_rr(loc, buf, adds[i]);

	return loc;
}

//得到类型名称
char *get_type_name(uint16_t type) {
	switch (type) {
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

//Resource Record
struct record *read_rr(size_t *loc, unsigned char *reader) {
	*loc = 0;
	int temp_loc = 0;
	struct record *pRecord = malloc(sizeof(struct record));

	//Record Name
    strcpy(pRecord->name, get_name(&temp_loc, reader));
	reader += temp_loc;
	*loc += temp_loc;
	printf("Name: <%s> ", pRecord->name);

	//Record Type
	memcpy(&pRecord->type, reader, sizeof(pRecord->type));
	pRecord->type = ntohs(pRecord->type);
	reader += sizeof(pRecord->type);
	*loc += sizeof(pRecord->type);
	printf("Type: <%s> ", get_type_name(pRecord->type));

	//Record Class
	memcpy(&pRecord->class, reader, sizeof(pRecord->class));
	pRecord->class = ntohs(pRecord->class);
	reader += sizeof(pRecord->class);
	*loc += sizeof(pRecord->class);

	//Record TTL
	memcpy(&pRecord->ttl, reader, sizeof(pRecord->ttl));
	pRecord->ttl = ntohl(pRecord->ttl);
	reader += sizeof(pRecord->ttl);
	*loc += sizeof(pRecord->ttl);
	printf("Time to live: <%u> ", pRecord->ttl);

	//Record Length
	memcpy(&pRecord->len, reader, sizeof(pRecord->len));
	pRecord->len = ntohs(pRecord->len);
	reader += sizeof(pRecord->len);
	*loc += sizeof(pRecord->len);

	//Record Data
	unsigned char *_data = malloc(pRecord->len);
	bzero(_data, pRecord->len);
	memcpy(_data, reader, pRecord->len);
    strcpy(pRecord->data, _data);
	if (pRecord->type == DNS_TYPE_A) {
		struct sockaddr_in t;
		memcpy(&t.sin_addr, pRecord->data, sizeof(struct in_addr));
		printf("Address: <%s> ", inet_ntoa(t.sin_addr));
	} else if (pRecord->type == DNS_TYPE_NS) {
		printf("Name Server: <%s> ", get_name(&temp_loc, reader));
	} else if (pRecord->type == DNS_TYPE_CNAME) {
		printf("CNAME: <%s> ", get_name(&temp_loc, reader));
	} else if (pRecord->type == DNS_TYPE_PTR) {
		printf("Domain Name: <%s> ", get_name(&temp_loc, reader));
	} else if (pRecord->type == DNS_TYPE_MX) {
		uint16_t preference;
		memcpy(&preference, pRecord->data, sizeof(preference));
		reader += sizeof(preference);
		printf("Preference: <%hu> Mail Exchange: <%s> ", ntohs(preference), get_name(&temp_loc, reader));
		reader -= sizeof(preference);
	}
	printf("\n");
	reader += pRecord->len;
	*loc += pRecord->len;

	return pRecord;
}

//Header
struct header *read_header(size_t *loc, unsigned char *reader) {
	*loc = 0;
	struct header *header = malloc(sizeof(struct header));

	//Transaction ID
	memcpy(&header->id, reader, sizeof(header->id));
	header->id = ntohs(header->id);
	reader += sizeof(header->id);
	*loc += sizeof(header->id);

	//Flags
	unsigned short tag;
	memcpy(&tag, reader, sizeof(tag));
	tag = ntohs(tag);
	unsigned short* tag_ptr = &tag;
	struct header_flags flags;
	struct header_flags* flag_ptr;
	flag_ptr =&flags;
	*flag_ptr = *(struct header_flags*)tag_ptr;
	


	//header->tag = malloc(sizeof((header->tag)));
	memcpy(&(header->tag), &tag, sizeof((tag)));
	reader += sizeof((header->tag));
	*loc += sizeof((header->tag));
	//printf("tag: <0x%04x> ", tag);

	//Queries
	memcpy(&header->queries, reader, sizeof(header->queries));
	header->queries = ntohs(header->queries);
	reader += sizeof(header->queries);
	*loc += sizeof(header->queries);

	//Answers
	memcpy(&header->answers, reader, sizeof(header->answers));
	header->answers = ntohs(header->answers);
	reader += sizeof(header->answers);
	*loc += sizeof(header->answers);

	//Authoritative
	memcpy(&header->auth_rr, reader, sizeof(header->auth_rr));
	header->auth_rr = ntohs(header->auth_rr);
	reader += sizeof(header->auth_rr);
	*loc += sizeof(header->auth_rr);

	//Additional
	memcpy(&header->add_rr, reader, sizeof(header->add_rr));
	header->add_rr = ntohs(header->add_rr);
	reader += sizeof(header->add_rr);
	*loc += sizeof(header->add_rr);

	if (flags.qr == 1) {
		if (flags.aa)
			printf("Authoritative response. ");
		else
			printf("Non-authoritative response. ");
	}

	if (flags.rd == 1)
		printf("Recursive query. ");
	else
		printf("Iterative query. ");

	if (flags.qr == 1) {
		if (flags.ra)
			printf("Server can do recursive queries. ");
		else
			printf("Server cannot do recursive queries. ");

		if (flags.rcode == 0)
			printf("No error. ");
		else if (flags.rcode == 2)
			printf("Server failure. ");
		else if (flags.rcode == 3)
			printf("No such name. ");
	}

	printf("\n");

	return header;
}

//Response
void resolve_tcp_response_packet() {
	uint16_t length = 0;

	recv(server_socket, &length, sizeof(uint16_t), 0);
	length = ntohs(length);
	bzero(buf, length);
	recv(server_socket, buf, length, 0);

	gettimeofday(&end, NULL);
	printf("Local server response in %lf seconds.\n", end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0);

	size_t loc = 0;
	unsigned char *reader = buf;

	//Header
	struct header *header = read_header(&loc, reader);
	reader += loc;

	//Queries
			int i;
	for (i = 0; i < header->queries; i++) {
		read_rr(&loc, reader);
		reader += loc;
	}

	//Answers
	for (i = 0; i < header->answers; i++) {
		read_rr(&loc, reader);
		reader += loc;
	}

	//Authoritative
	for (i = 0; i < header->auth_rr; i++) {
		read_rr(&loc, reader);
		reader += loc;
	}

	//Additional
	for (i = 0; i < header->add_rr; i++) {
		read_rr(&loc, reader);
		reader += loc;
	}
}

int main(int argc, char **argv) {
	//创建socket
	if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		printf("socket() failed.\n");
		exit(1);
	}

	//地址
	struct sockaddr_in server_add;
	memset(&server_add, 0, sizeof(struct sockaddr_in));
	server_add.sin_family = AF_INET;
	server_add.sin_port = htons(53);
	server_add.sin_addr.s_addr = inet_addr("127.0.0.2");

	connect(server_socket, (struct sockaddr *) &server_add, sizeof(server_add));

	//表明递归或迭代
	int rd = 0;
	int query_num = 1;
	bzero(buf, 512);

	size_t loc = sizeof(uint16_t);

	struct header *header = make_header(0, 0, rd, 0, query_num, 0, 0, 0);

	struct query **queries = malloc(sizeof(struct query) * query_num);

	char type[64] = {0};
	char name[64] = {0};
	int i;
	for (i = 0; i < query_num; i++) {
		start:
		printf("Type: ");
		scanf("%s", type);
		printf("Domain name: ");
		scanf("%s", name);
		queries[i] = malloc(sizeof(struct query));
		if (!strcmp(type, "A")) {
            strcpy(queries[i]->name, name);
			//queries[i]->name = name;
			queries[i]->type = 1;
		} else if (!strcmp(type, "CNAME")) {
			strcpy(queries[i]->name, name);
			queries[i]->type = 5;
		} else if (!strcmp(type, "PTR")) {
			//queries[i]->name = ptr(name);
			queries[i]->type = 12;
		} else if (!strcmp(type, "MX")) {
			strcpy(queries[i]->name, name);
			queries[i]->type = 15;
		} else {
			printf("Wrong type!\n");
			goto start;
		}
		queries[i]->class = 1;
	}

	struct record **answers = NULL, **auths = NULL, **adds = NULL;

	loc = make_packet(loc, buf, header, queries, answers, auths, adds);

	uint16_t dns_packet_size = htons((uint16_t) (loc - 2));

	//前两个字节表示packet的长度
	memcpy(buf, &dns_packet_size, sizeof(uint16_t));

	send(server_socket, buf, loc, 0);

	//记录时间
	gettimeofday(&start, NULL);

	for (i = 0; i < query_num; i++)
		resolve_tcp_response_packet();

	close(server_socket);
	return 0;
}
