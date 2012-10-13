/* 
 * File:   output.c
 * Author: Luke Plaster
 */

#include "stdafx.h"
#include "dns.h"
#include "output.h"

void output_print_response(dnsPacket *dns)
{
	printf("Response received - ");
	switch (dns->base->flags & 0x000f)
	{
	case DNS_RCODE_NERROR:
		printf("no error\n");
		break;
	case DNS_RCODE_FORMATERR:
		printf("format error\n");
		break;
	case DNS_RCODE_SERVERERR:
		printf("server failure\n");
		break;
	case DNS_RCODE_NAMEERR:
		printf("name error\n");
		break;
	case DNS_RCODE_NOTIMP:
		printf("not implemented\n");
		break;
	case DNS_RCODE_REFUSED:
		printf("refused\n");
		break;
	default:
		printf("unknown\n");
	}

	if (dns->base->flags & DNS_FLAGS_AA)
		printf("Responding server is an authority for this zone\n");
}

void output_print_sections(dnsPacket *dns)
{
	if (dns->base->qdcount > 0)
	{
		printf("/--- Question Sections (%d)\t---/\n", dns->base->qdcount);
		dns_iterate_qrs(dns, (char *)dns->qdBase, dns->base->qdcount, &output_print_qr);
	}
	if (dns->base->ancount > 0)
	{
		printf("/--- Answer Sections (%d)\t---/\n", dns->base->ancount);
		dns_iterate_rrs(dns, (char *)dns->anBase, dns->base->ancount, &output_print_rr);
	}
	if (dns->base->nscount > 0)
	{
		printf("/--- Authority Sections (%d)\t---/\n", dns->base->nscount);
		dns_iterate_rrs(dns, (char *)dns->nsBase, dns->base->nscount, &output_print_rr);
	}
	if (dns->base->arcount > 0)
	{
		printf("/--- Additional Sections (%d)\t---/\n", dns->base->arcount);
		dns_iterate_rrs(dns, (char *)dns->arBase, dns->base->arcount, &output_print_rr);
	}
}

void output_print_qr(dnsPacket *dns, char *qname, unsigned short qtype, unsigned short qclass)
{
	char nameBuf[DNS_STRING_OCTET_MAX];
	dns_name_untokenise(dns, qname, nameBuf, sizeof(nameBuf), 0);
	printf("%-25s%-6s%-6s\n", nameBuf, dns_get_type_name(qtype), dns_get_class_name(qclass));
}

void output_print_rr(dnsPacket *dns, char *name, unsigned short type, unsigned short u_class, 
						unsigned int ttl, unsigned short rdlength, char *rdata)
{
	char nameBuf[DNS_STRING_OCTET_MAX], nameBuf2[DNS_STRING_OCTET_MAX], ipBuf[40];
	PCSTR rdataTxt = NULL;
	int nameLen, isIPv6 = 0;
	struct in_addr inaddr;

	// handle how the rdata field is displayed depending upon type
	switch (type)
	{
	case DNS_TYPE_MX:
		rdata += 2;
	case DNS_TYPE_CNAME:
	case DNS_TYPE_NS:
	case DNS_TYPE_SOA:
	case DNS_TYPE_PTR:
		dns_name_untokenise(dns, rdata, nameBuf2, sizeof(nameBuf2), 0);
		rdataTxt = nameBuf2;
		break;
	case DNS_TYPE_AAAA:
		isIPv6 = 1;
	default:
		inaddr.S_un.S_addr = *(unsigned long *)(rdata);
		rdataTxt = inet_ntop((isIPv6 > 0) ? AF_INET6 : AF_INET, rdata, ipBuf, sizeof(ipBuf));
		break;
	}

	nameLen = dns_name_untokenise(dns, name, nameBuf, sizeof(nameBuf), 0);
	printf("%-25s%-6s%-6s%-8d%-18s\n", nameBuf, dns_get_type_name(type), 
		dns_get_class_name(u_class), ttl, (rdataTxt != NULL) ? rdataTxt : NULL);
}
