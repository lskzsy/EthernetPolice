#ifndef _SKYSY_ARPATTACK_ARP_H
#define _SKYSY_ARPATTACK_ARP_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

/* private */

void FillArpData(uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast, uint8_t* data);

void FillRArpData(uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast, uint8_t* data);

/* public */

/* 为isBoardcast时，广播Arp包，isBoardcast为0时单播， op为1为请求包，op为2为响应包 */
int SendArpData(pcap_t* adhandle, uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast);

int SendRArpData(pcap_t* adhandle, uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast);

#endif
