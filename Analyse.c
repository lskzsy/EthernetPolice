#ifndef _SKYSY_ARPATTACK_ANALYSE_C
#define _SKYSY_ARPATTACK_ANALYSE_C

#include "Analyse.h"

void AnalysePacket(uint8_t* packet, int plen, struct PacketInformation* inf)
{   
    memset((void*)inf, 0, sizeof((void*)inf));
    int protocol = 0;
    memcpy(inf->souMac, packet + 6, 6);
    memcpy(inf->desMac, packet, 6);
    protocol = packet[12] * 0x100 + packet[13]; /* 获取网络层协议标识 */
    inf->len = plen;
    
    /* 分析网络层协议 */
    switch (protocol) {
    case 0x0800:
        memcpy(inf->souIp, packet + 26, 4);
        memcpy(inf->desIp, packet + 30, 4);
        inf->protocol = protocol;
        strncpy(inf->protocolName, NetworkLayerProtocolName[0], strlen(NetworkLayerProtocolName[0]));
        break;
    case 0x0806:
        memcpy(inf->souIp, packet + 28, 4);
        memcpy(inf->desIp, packet + 38, 4);
        inf->protocol = protocol;
        strncpy(inf->protocolName, NetworkLayerProtocolName[2], strlen(NetworkLayerProtocolName[2]));
        return;
    case 0x0835:
        memcpy(inf->souIp, packet + 28, 4);
        memcpy(inf->desIp, packet + 38, 4);
        inf->protocol = protocol;
        strncpy(inf->protocolName, NetworkLayerProtocolName[3], strlen(NetworkLayerProtocolName[3]));
        return;
    case 0x86dd:
        inf->protocol = protocol;
        strncpy(inf->protocolName, NetworkLayerProtocolName[1], 5);
        return;
    default:
        inf->protocol = protocol;
        return;
    }

    protocol = packet[23]; /* 获取传输层协议标识 */

    /* 分析传输层协议 */
    switch (protocol) {
    case 1:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[0], 5);
        return;
    case 2:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[1], 5);
        return;
    case 6:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[2], strlen(TranlateLayerProtocolName[2]));
        inf->souPort = packet[34] * 0x100 + packet[35];
        inf->desPort = packet[36] * 0x100 + packet[37];
        break;
    case 17:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[3], strlen(TranlateLayerProtocolName[3]));
        return;
    case 88:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[4], 5);
        return;
    case 89:
        inf->protocol = protocol;
        strncpy(inf->protocolName, TranlateLayerProtocolName[5], 5);
        return;
    default:
        inf->protocol = protocol;
        return;
    }

    /* 分析TCP包是否是HTTP协议 */
    for (int i = 54, bc = 0; i < plen; i++) {
        if(packet[i] == (uint8_t)' ') {
            bc++;
        }

        if(bc == 2) {
            //printf("%c%c%c%c\n", packet[i + 1], packet[i + 2], packet[i + 3], packet[i + 4]);
            if(packet[i + 1] == 'H' && packet[i + 2] == 'T' && packet[i + 3] == 'T' && packet[i + 4] == 'P') {
                inf->protocol = 0x0100;
                strncpy(inf->protocolName, "HTTP\0", 5);
            }
            break;
        }
    }
}

void PrintPacketInformation(struct PacketInformation* inf)
{
    switch (inf->protocol) {
    case 0x0100:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d SouPort: %d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3], inf->souPort,
                    inf->protocolName, inf->len
                    );
        printf("DesIp: %d.%d.%d.%d DesPort: %d\n", inf->desIp[0], inf->desIp[1], inf->desIp[2], inf->desIp[3], inf->desPort);
        break;
    case 1:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 2:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 6:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d SouPort: %d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3], inf->souPort,
                    inf->protocolName, inf->len
                    );
        printf("DesIp: %d.%d.%d.%d DesPort: %d\n", inf->desIp[0], inf->desIp[1], inf->desIp[2], inf->desIp[3], inf->desPort);
        break;
    case 17:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 88:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 89:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 0x0800:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 0x0806:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 0x0835:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x SouIp: %d.%d.%d.%d Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->souIp[0], inf->souIp[1], inf->souIp[2], inf->souIp[3],
                    inf->protocolName, inf->len
                    );
        break;
    case 0x86dd:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x Protocol: %s DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->protocolName, inf->len
                    );
        break;
    default:
        printf("SouMac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x Protocol: %.4x DataLen: %d\n", 
                    inf->souMac[0], inf->souMac[1], inf->souMac[2], inf->souMac[3], inf->souMac[4], inf->souMac[5],
                    inf->protocol, inf->len
                    );
        break;
    }
}

#endif