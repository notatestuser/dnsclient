/*
 * File: dns.c
 * Author: Luke Plaster
 */

#include "stdafx.h"
#include "dns.h"

dnsPacket *dns_create()
{
	dnsPacket *dns;
	DNS_HEADER *dnsBase;
	unsigned int uiPacketSize;

	// allocate heap space for the DNS header
	//uiPacketSize = (sizeof(DNS_HEADER) + (sizeof(DNS_QUESTION) * qdcount));
	uiPacketSize = sizeof(DNS_HEADER);
	dnsBase = (DNS_HEADER *)calloc(uiPacketSize, 1);

	// allocate heap space for the encapsulation structure
	dns = (dnsPacket *)calloc(1, sizeof(dnsPacket));

	// assign fields in the encap struct
	dns->size = uiPacketSize;
	dns->base = dnsBase;

	return dns;
}

int dns_add_question(dnsPacket *dns, char *qdomain, unsigned short qdomainSize, unsigned short qtype, unsigned short qclass)
{
	DNS_QUESTION *qdBase;
	unsigned int qdSize, qnameSizeReal, uiOldSize;
	
	// find the size of this question block
	qnameSizeReal = (qdomainSize); // include enough space for the leading NULL
	qdSize = sizeof(DNS_QUESTION) + qnameSizeReal;
	uiOldSize = dns->size;
	dns->size += qdSize;

	// reallocate the dnsBase block to accomodate the new question block
	dns->base = (DNS_HEADER *)realloc(dns->base, dns->size);
	if (dns->base == NULL)
		return -1;

	// calculate a pointer to the beginning of the question section (if it isn't set in the encapsulation)
	qdBase = (dns->qdSize == 0) ? (DNS_QUESTION *)((DWORD_PTR)(dns->base) + sizeof(DNS_HEADER)) : dns->qdBase;
	dns->qdBase = qdBase;
	dns->qdSize += qdSize;

	// set the qtype and qclass fields - the qname will require a little more messing with
	qdBase->qtype = htons(qtype);
	qdBase->qclass = htons(qclass);
	
	// move everything after the qname array forward (depending upon string size)
	memcpy((void *)((DWORD_PTR)(&qdBase->qtype) + (DWORD_PTR)(qnameSizeReal)), &qdBase->qtype, (sizeof(qdBase->qtype) + sizeof(qdBase->qclass)));
	
	// convert the domain name input into DNS-friendly size prefixed goodness
	dns_name_tokenise(qdomain, qdBase->qname);
	
	return ++dns->base->qdcount;
}

void dns_name_tokenise(char *original, char* dest)
{
	const char delim = '.';
	char *section, *originalCopy;
	unsigned int uiBytePos = 0;
	size_t strLen;

	originalCopy = (char *)calloc((strlen(original) + 1), 1);
	strcpy(originalCopy, original);

	section = strtok(originalCopy, &delim);
	while (section != NULL)
	{
		strLen = strlen(section);
		dest[uiBytePos] = (char)strLen;
		memcpy(&dest[uiBytePos + 1], section, strLen);
		uiBytePos += (strLen + 1);

		section = strtok(NULL, &delim);
	}

	dest[uiBytePos] = '\0';

	free(originalCopy);
}

int dns_name_untokenise(dnsPacket *dns, char *input, char *dest, int destSize, int destPos)
{
	const char delim = '.';
	int i, j, strLen, tokenCount = 0, recursed = 0;
	char *dnsBase, *compressionTgt;

	j = (destPos > 0) ? destPos : 0;

	strLen = strlen(input);
	for (i = 0; i < min(strLen, ((destSize - destPos) - 1)); i++)
	{
		if (--tokenCount < 0)
		{
			if (input[i] & 0xc0)
			{
				// recursively resolve 'compressed' pointers to text elsewhere in the packet
				dnsBase = (char *)dns->base;
				compressionTgt = (char *)&dnsBase[ntohs(*((unsigned short *)(&input[i]))) & 0x3fff];
				j += dns_name_untokenise(dns, compressionTgt, dest, destSize, j);
				i++;
				recursed = 1;
				break;
			}
			else
			{
				tokenCount = input[i];
				if (i > 0 || destPos > 0)
				{
					dest[j] = delim;
					j++;
				}
			}
		}
		else
		{
			dest[j] = input[i];
			j++;
		}
	}

	if (!recursed)
		dest[j] = '\0';

	return strLen;
}

dnsPacket *dns_parse(char *mem, int memSize)
{
	dnsPacket *dns;
	void *newMem;

	// alloc memory for entire packet and copy
	newMem = calloc(memSize, 1);
	memcpy(newMem, mem, memSize);

	// alloc memory for encapsulation structure
	dns = (dnsPacket *)calloc(1, sizeof(dnsPacket));

	// set initial dnsPacket fields
	dns->base = (DNS_HEADER *)newMem;
	dns->size = memSize;

	// convert network to host byte ordering
	dns_ntoh(dns);

	// calculate pointers to each section
	dns_find_sections(dns);

	return dns;
}

void dns_find_sections(dnsPacket *dns)
{
	int 
		iSectionType = 0, // 0 = qd, 1 = an, 2 = ns, 3 = ar
		iLastSectionType = -1,
		iBytePos = sizeof(DNS_HEADER), 
		iStartPos, 
		bExpectingString = 1,
		bNewSection = 1;
	unsigned short
		sectionCounts[4],
		sectionCountTgts[4];
	char *byte, *startByte = NULL;
	iStartPos = iBytePos;

	// copy section counts from DNS header in a way that I can iterate through
	sectionCountTgts[0] = dns->base->qdcount;
	sectionCountTgts[1] = dns->base->ancount;
	sectionCountTgts[2] = dns->base->nscount;
	sectionCountTgts[3] = dns->base->arcount;

	// zero out the sectionCounts array
	memset(sectionCounts, 0, sizeof(sectionCounts));
	
	// grab a pointer to qdBase even if there are no question blocks
	dns->qdBase = (DNS_QUESTION *)((DWORD_PTR)(dns->base) + iBytePos);

	while (iBytePos < dns->size)
	{
		byte = (char *)((DWORD_PTR)(dns->base) + (DWORD_PTR)(iBytePos));
		
		if (bExpectingString > 0)
		{
			if (iSectionType != iLastSectionType)
			{
				// starting a new block
				bNewSection = 1;
				iStartPos = iBytePos;
				startByte = (iStartPos != iBytePos) ? (char *)((DWORD_PTR)(dns->base) + iStartPos) : byte;
			}
			
			if (*byte == NULL)
				bExpectingString = 0;
			else if (*byte & 0xc0)
				// 'compressed' string offset
				iBytePos++;
			else
				iBytePos += *byte;
		}
		else
		{
			bExpectingString = 1;
			switch (iSectionType)
			{
			case 0:
				iBytePos += (DNS_SECTION_SIZE_QR - 1);
				dns->qdSize = (iBytePos - iStartPos) + 1;
				break;
			case 1:
			case 2:
			case 3:
				iBytePos += DNS_SECTION_SIZE_RR;
				// add the rdata length to iBytePos
				iBytePos += (unsigned short)*(char *)((DWORD_PTR)(dns->base) + iBytePos);

				if (iSectionType == 1)
				{
					dns->anSize = (iBytePos - iStartPos) + 1;
					dns->anBase = startByte;
				}
				else if (iSectionType == 2)
				{
					dns->nsSize = (iBytePos - iStartPos) + 1;
					dns->nsBase = startByte;
				}
				else if (iSectionType == 3)
				{
					dns->arSize = (iBytePos - iStartPos) + 1;
					dns->arBase = startByte;
				}

				break;
			}

			bNewSection = 0;
			sectionCounts[iSectionType]++;
		}

		iLastSectionType = iSectionType;
		// all sections of this type found?
		if (!bNewSection && sectionCounts[iSectionType] >= sectionCountTgts[iSectionType])
		{
			do
			{
				iSectionType++;
			}
			while (sectionCountTgts[iSectionType] == 0);
		}
		if (iSectionType > 3)
			break;

		iBytePos++;
	}
}

void dns_iterate_qrs(dnsPacket *dns, char *ptr, unsigned short limit, 
					void (callback)(dnsPacket *dns, char *qname, unsigned short qtype, 
						unsigned short qclass))
{
	int iStrLen, i;
	char *curBase;

	curBase = ptr;
	for (i = 0; i < limit; i++)
	{
		iStrLen = strlen(curBase);
		callback(dns, curBase, ntohs(*(unsigned short *)(&curBase [iStrLen + 1])), ntohs(*(unsigned short *)(&curBase[iStrLen + 3])));
		curBase = curBase + iStrLen + DNS_SECTION_SIZE_QR;
	}
}

void dns_iterate_rrs(dnsPacket *dns, char *ptr, unsigned short limit,
					void (callback)(dnsPacket *dns, char *name, unsigned short type, 
						unsigned short u_class, unsigned int ttl, unsigned short rdlength, char *rdata))
{
	int iStrLen, i;
	unsigned short nextrdlen;
	char *curBase;

	curBase = ptr;
	for (i = 0; i < limit; i++)
	{
		iStrLen = strlen(curBase);
		nextrdlen = ntohs(*(unsigned short *)(&curBase[iStrLen + 8]));
		callback(dns, curBase, ntohs(*(unsigned short *)(&curBase[iStrLen])), ntohs(*(unsigned short *)(&curBase[iStrLen + 2])), 
			ntohl(*(unsigned int *)(&curBase[iStrLen + 4])), nextrdlen, (&curBase[iStrLen + 10]));
		curBase = curBase + iStrLen + DNS_SECTION_SIZE_RR_FULL + nextrdlen;
	}
}

void dns_hton(dnsPacket *dns)
{
	dns->base->id = htons(dns->base->id);
	dns->base->flags = htons(dns->base->flags);
	dns->base->qdcount = htons(dns->base->qdcount);
	dns->base->ancount = htons(dns->base->ancount);
	dns->base->arcount = htons(dns->base->arcount);
	dns->base->nscount = htons(dns->base->nscount);
}

void dns_ntoh(dnsPacket *dns)
{
	dns->base->id = ntohs(dns->base->id);
	dns->base->flags = ntohs(dns->base->flags);
	dns->base->qdcount = ntohs(dns->base->qdcount);
	dns->base->ancount = ntohs(dns->base->ancount);
	dns->base->arcount = ntohs(dns->base->arcount);
	dns->base->nscount = ntohs(dns->base->nscount);
}

char *dns_get_type_name(unsigned short type)
{
	switch (type)
	{
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_CNAME:
		return "CNAME";
	case DNS_TYPE_MX:
		return "MX";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_PTR:
		return "PTR";
	case DNS_TYPE_SOA:
		return "SOA";
	case DNS_TYPE_TXT:
		return "TXT";
	case DNS_TYPE_AAAA:
		return "AAAA";
	default:
		return "???";
	}
}

char *dns_get_class_name(unsigned short class)
{
	switch (class)
	{
	case DNS_CLASS_IN:
		return "IN";
	default:
		return "???";
	}
}
