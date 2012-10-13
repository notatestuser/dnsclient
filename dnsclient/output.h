/* 
 * File:   output.h
 * Author: Luke Plaster
 */

#pragma once

#include "dns.h"

void output_print_response(dnsPacket *dns);
void output_print_sections(dnsPacket *dns);
void output_print_qr(dnsPacket *dns, char *qname, unsigned short qtype, unsigned short qclass);
void output_print_rr(dnsPacket *dns, char *name, unsigned short type, unsigned short u_class, 
						unsigned int ttl, unsigned short rdlength, char *rdata);