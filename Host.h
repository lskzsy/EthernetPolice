
#ifndef _SKYSY_ARPATTACK_HOST_H
#define _SKYSY_ARPATTACK_HOST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>

#include "Arp.h"

struct Host{
    uint8_t ipaddr[4];
    uint8_t macaddr[6];  
};

void PrintHostList();

/* 获寻找局域网内某个主机的Mac地址 */
int FindHost(pcap_t *adhandle, uint8_t* desIp, uint8_t* myip, uint8_t* mymac);

/* 获寻找局域网内某个主机的IP地址，因为大部分局域网RARP协议已经停用，所以这个函数慎用 */
int FindHostByMac(pcap_t *adhandle, uint8_t* desMac, uint8_t* myip, uint8_t* mymac);

/* 获寻找局域网内所有主机的Mac地址 */
int FindAllHost(pcap_t *adhandle, const uint8_t* netSeg, uint8_t* myip, uint8_t* mymac);

/* 已搜索的情况下可以直接查找记录，获取mac或者ip */
int GetHostMacByIp(const uint8_t* ip, uint8_t* mac);

int GetHostIpByMac(const uint8_t* mac, uint8_t* ip);



#endif