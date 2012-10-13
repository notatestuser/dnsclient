/* 
 * File:   udp.h
 * Author: Luke Plaster
 */

#pragma once

#define BUFFER_SIZE  1024
#define TIMEOUT_SEC  10
#define TIMEOUT_USEC 0

struct sockaddr_in *network_init(char *sIP, unsigned short usPort);
void network_connect_udp();
int network_send(char *buf, int bufLen);
char *network_receive(int *recvLen);
void network_close();
