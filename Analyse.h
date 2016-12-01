#ifndef _SKYSY_ARPATTACK_ANALYSE_H
#define _SKYSY_ARPATTACK_ANALYSE_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

/* 网络层协议 */
static int NetworkLayerProtocol[4] = {0x0800, 0x86dd, 0x0806, 0x0835};
static char* NetworkLayerProtocolName[4] = {"IP\0", "IPV6\0", "ARP\0", "RARP\0"};

/* 传输层层协议 */
static int TranlateLayerProtocal[6] = {1, 2, 6, 17, 88, 89};
static char* TranlateLayerProtocolName[6] = {"ICMP\0", "IGMP\0", "TCP\0", "UDP\0", "IGRP\0", "OSPF\0"};

struct PacketInformation
{
    int      protocol;
    char     protocolName[10];
    uint8_t  souMac[6];
    uint8_t  desMac[6];
    uint8_t  souIp[4];
    uint8_t  desIp[4];
    int      souPort;
    int      desPort;
    int      len;
};

/* 分析包内容 */
void AnalysePacket(uint8_t* packet, int plen, struct PacketInformation* inf);

void PrintPacketInformation(struct PacketInformation* inf);

#endif