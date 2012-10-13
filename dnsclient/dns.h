/* 
 * File:   dns.h
 * Author: Luke Plaster
 * Reference: http://www.ietf.org/rfc/rfc1035.txt?number=1035
 */

#pragma once

#define	DNS_FLAGS_RD			0x0100	// recursion desired
#define DNS_FLAGS_TC			0x0200	// truncation
#define DNS_FLAGS_AA			0x0400	// authoritative answer
#define DNS_FLAGS_RESPONSE		0x8000	// response

#define DNS_RCODE_NERROR		0
#define	DNS_RCODE_FORMATERR		1
#define	DNS_RCODE_SERVERERR		2
#define	DNS_RCODE_NAMEERR		3
#define	DNS_RCODE_NOTIMP		4
#define	DNS_RCODE_REFUSED		5

#define	DNS_TYPE_A				1
#define	DNS_TYPE_NS				2
#define	DNS_TYPE_CNAME			5
#define	DNS_TYPE_SOA			6
#define	DNS_TYPE_PTR			12
#define	DNS_TYPE_MX				15
#define	DNS_TYPE_TXT			16
#define	DNS_TYPE_AAAA			28

#define	DNS_CLASS_IN			1

#define DNS_STRING_OCTET_MAX	64

#define DNS_SECTION_SIZE_QR		4
#define DNS_SECTION_SIZE_RR		8
#define	DNS_SECTION_SIZE_RR_FULL 10

typedef struct
{
	unsigned short id;    // 16-bit identifier
	unsigned short flags;
	unsigned short qdcount; // question count
	unsigned short ancount; // answer count
	unsigned short nscount; // number of name servers in authority record section
	unsigned short arcount; // number of additional records
} DNS_HEADER;

typedef struct
{
	char qname[1];
	unsigned short qtype;
	unsigned short qclass;
} DNS_QUESTION;

typedef struct
{
	char name[1];
	unsigned short type :16;
	unsigned short u_class :16;
	unsigned int ttl :32;
	unsigned short rdlength :16;
	unsigned rdata[1];
} DNS_RESOURCE;

/* My custom encapsulation of the DNS packet structure */
typedef struct
{
	DNS_HEADER *base;
	unsigned int size;
	DNS_QUESTION *qdBase;
	unsigned int qdSize;
	char *anBase;
	unsigned int anSize;
	char *nsBase;
	unsigned int nsSize;
	char *arBase;
	unsigned int arSize;
} dnsPacket;

/* Creates a new DNS header without any additonal sections */
dnsPacket *dns_create();

/* Adds a question section block to the specified DNS header */
/* Returns: the index of the new question block on success, -1 on error */
int dns_add_question(dnsPacket *dns, char *qdomain, unsigned short qdomainSize, unsigned short qtype, unsigned short qclass);

/* Converts a standard fully qualified domain name into a DNS-friendly size prefixed string */
void dns_name_tokenise(char *original, char* dest);

/* Converts a tokenised DNS domain string to a dot-seperated FQDN */
int dns_name_untokenise(dnsPacket *dns, char *input, char *dest, int destSize, int destPos);

/* Creates a new dnsPacket structure and fills out some initial values */
/* Returns: the new dnsPacket encapsulation */
dnsPacket *dns_parse(char *mem, int memSize);

/* Locates the sections in the DNS packet and associates pointers to them in the dnsPacket structure */
void dns_find_sections(dnsPacket *dns);

/* Iterates through question records in a certain position and calls the specified callback with each record's contents */
void dns_iterate_qrs(dnsPacket *dns, char *ptr, unsigned short limit, 
					void (callback)(dnsPacket *dns, char *qname, unsigned short qtype, 
						unsigned short qclass));

/* Iterates through resource records in a certain position and calls the specified callback with each record's contents */
void dns_iterate_rrs(dnsPacket *dns, char *ptr, unsigned short limit,
					void (callback)(dnsPacket *dns, char *name, unsigned short type, 
						unsigned short u_class, unsigned int ttl, unsigned short rdlength, char *rdata));

/* Converts fields in an encapsulated dnsPacket to network byte ordering */
void dns_hton(dnsPacket *dns);

/* Converts fields in an encalsulation dnsPacket to host byte ordering */
void dns_ntoh(dnsPacket *dns);

/* Returns the name of a DNS type number */
char *dns_get_type_name(unsigned short type);

/* Returns the name of a DNS class number */
char *dns_get_class_name(unsigned short class);
