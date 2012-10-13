/* 
 * File:   network.c
 * Author: Luke Plaster
 */

#include "stdafx.h"
#include "udp.h"

int wsaInitialized = 0;
WSADATA wsaData;
SOCKET serverSocket;
struct sockaddr_in soin;
char recvBuf[BUFFER_SIZE];
unsigned int recvBytes = 0;

struct sockaddr_in *network_init(char *sIP, unsigned short usPort)
{
	int iResult;
	
	// initialize winsock if hasn't already been
	if (!wsaInitialized)
	{
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0)
			return NULL;
		wsaInitialized = 1;
	}

	// create the sockaddr struct
	memset((void *)&soin, 0, sizeof(soin));
	soin.sin_family = AF_INET;
	soin.sin_addr.s_addr = inet_addr(sIP);
	soin.sin_port = htons(usPort);

	return &soin;
}

void network_connect_udp()
{
	char buffer[BUFFER_SIZE];
	memset(buffer, 0, sizeof(buffer));

	// create the socket
	if ((serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("error: unable to initialize socket");
		return;
	}

	// attempt a connection
	if (connect(serverSocket, (const struct sockaddr *)&soin, sizeof(soin)) != 0)
	{
		return;
	}
}

int network_send(char *buf, int bufLen)
{
	return send(serverSocket, buf, bufLen, 0);
}

char *network_receive(int *recvLen)
{
	*recvLen = recv(serverSocket, recvBuf, BUFFER_SIZE, 0);
	return recvBuf;
}

void network_close()
{
	closesocket(serverSocket);
}
