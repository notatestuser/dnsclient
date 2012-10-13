/*
 * File: main.c
 * Author: Luke Plaster
 */

#include "stdafx.h"
#include "dns.h"
#include "udp.h"
#include "output.h"
#include "commands.h"

#define DNS_PORT			53
#define DNS_IDENTIFIER		0xbeef

char *DNS_DEFAULT_LOOKUP = "www.lancs.ac.uk";
char *DNS_LOOKUP_SERVER  = "148.88.8.4";

int main(int argc, char *argv[])
{
	dnsPacket *dns, *dnsresponse;
	int iResult, iReceived;
	char *qdomain, *qserver, *response;
	unsigned short qtype = 1, qclass = 1;

	qdomain = ((qdomain = command_arg_get(0, '-', argc, argv)) != NULL) ? qdomain : DNS_DEFAULT_LOOKUP;
	qserver = ((qserver = command_arg_get(1, '-', argc, argv)) != NULL) ? qserver : DNS_LOOKUP_SERVER;

	// create our empty DNS packet
	dns = dns_create();

	// set the required header fields
	dns->base->id = DNS_IDENTIFIER;

	// use recursive query?
	if (command_opt_set("-r", argc, argv))
	{
		dns->base->flags |= DNS_FLAGS_RD;
		printf("+ Using recursive querying\n");
	}

	// use a different query type?
	if (command_opt_set("-cname", argc, argv))
	{
		qtype = DNS_TYPE_CNAME;
		printf("+ Using CNAME query type\n");
	}
	else if (command_opt_set("-ns", argc, argv))
	{
		qtype = DNS_TYPE_NS;
		printf("+ Using NS query type\n");
	}
	else if (command_opt_set("-mx", argc, argv))
	{
		qtype = DNS_TYPE_MX;
		printf("+ Using MX query type\n");
	}
	else if (command_opt_set("-ptr", argc, argv))
	{
		qtype = DNS_TYPE_PTR;
		printf("+ Using PTR query type\n");
	}
	else if (command_opt_set("-aaaa", argc, argv))
	{
		qtype = DNS_TYPE_AAAA;
		printf("+ Using AAAA query type\n");
	}

	// add our question section
	dns_add_question(dns, qdomain, strlen(qdomain), qtype, qclass);
	dns_hton(dns);

	// initialize the network
	network_init(qserver, DNS_PORT);
	network_connect_udp();

	// send the packet out
	printf("Looking up %s using %s...\n", qdomain, qserver);
	iResult = network_send((char *)dns->base, dns->size);
	assert(iResult > 0);
	
	// block until a response is ready
	response = network_receive(&iReceived);
	assert(iReceived > 0);

	// load up the response packet
	dnsresponse = dns_parse(response, iReceived);
	assert(dnsresponse->base->flags & DNS_FLAGS_RESPONSE && dnsresponse->base->id == DNS_IDENTIFIER);

	output_print_response(dnsresponse);
	output_print_sections(dnsresponse);
}
