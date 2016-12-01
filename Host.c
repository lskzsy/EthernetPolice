
#ifndef _SKYSY_ARPATTACK_HOST_C
#define _SKYSY_ARPATTACK_HOST_C

#include "Host.h"

struct Host _host[256]      = {};    /* 本网段下，所有主机的Mac和IP */
int         _hostArr[256]   = {};    /* 本网段下，存在哪些主机，被分配的地址标记为1 */
int         myHost          = 0;     /* 标记本地主机 */
int         _hostCount      = 0;     /* 主机数量 */

void PrintHostList()
{
    for (int i = 0; i < 256; i++) {
        if (_hostArr[i]) {
            printf("IP:%d.%d.%d.%d  MAC:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
                _host[i].ipaddr[0], _host[i].ipaddr[1], _host[i].ipaddr[2], _host[i].ipaddr[3],
                _host[i].macaddr[0], _host[i].macaddr[1], _host[i].macaddr[2],
                _host[i].macaddr[3], _host[i].macaddr[4], _host[i].macaddr[5]); 
        }
    }

     printf("Host Count:%d\n", _hostCount);
}

int FindHostByMac(pcap_t *adhandle, uint8_t* desMac, uint8_t* myip, uint8_t* mymac)
{
    int flag = 0;
    uint8_t desIp[8] = {0x00, 0x00, 0x00, 0x00};
    uint8_t gateway[4];
    uint8_t gwMac[6];
    time_t beginTime, endTime, timeout = 1;
    struct pcap_pkthdr *header;
    const uint8_t    *captured;

    memcpy(gateway, myip, 3);

    gateway[3] = 0x01;
    GetHostMacByIp(gateway, gwMac);

    printf("正在搜索MAC: %2x:%2x:%2x:%2x:%2x:%2x ...", desMac[0], desMac[1], desMac[2], desMac[3], desMac[4], desMac[5]);
    
    /* 通过RARP查找主机IP地址 */    
    (void)SendRArpData(adhandle, gwMac, gateway, desMac, desIp, 3, 0);

    time(&beginTime);
    while (1) {
        time(&endTime);

        if (endTime - beginTime > timeout) {
            printf("未找到\n");
            return 0;
        }

        while (pcap_next_ex(adhandle, &header, &captured) != 1) {
            (void)0;
        }

        if (captured[12] == 0x08 && captured[13] == 0x06 && captured[21] == 0x04) {
            flag = 1;
            for (int j = 0; j < 6; j++) {
                if (captured[22 + j] != desMac[j]) {
                    flag = 0;
                    break;
                }       
            }

            if (flag) {
                memcpy(_host[captured[31]].ipaddr, captured + 28, 4);
                memcpy(_host[captured[31]].macaddr, desMac, 6);
                _hostArr[captured[31]] = 1;
                _hostCount++;

                printf("%lds\n", endTime - beginTime);
                break;
            }
        }
    }

    return 1;
}

int FindHost(pcap_t *adhandle, uint8_t* desIp, uint8_t* myip, uint8_t* mymac)
{
    int flag = 0;
    int i = desIp[3];
    uint8_t desMac[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t gateway[4];
    time_t beginTime, endTime, timeout = 1;         /* 用于计时，请求包发出1S后未收到回复默认超时 */
    struct pcap_pkthdr *header;                     /* PCAP头 */
    const uint8_t    *captured;                     /* PCAP截获的数据包 */

    memcpy(gateway, desIp, 3);

    gateway[3] = 0x01;

    printf("正在搜索IP: %d.%d.%d.%d ...", desIp[0], desIp[1], desIp[2], desIp[3]);
    
    /* 如果查找的是网关，使用真实身份发包，如果查找的是其他主机，则以网关身份发包 */
    if (desIp[3] == 0x01) {
        (void)SendArpData(adhandle, desMac, desIp, mymac, myip, 1, 1);
    } else {
        (void)SendArpData(adhandle, desMac, desIp, mymac, gateway, 1, 1);
    }
    
    time(&beginTime);
    while (1) {
        time(&endTime);

        if (endTime - beginTime > timeout) {
            printf("未找到\n");
            return 0;
        }

        while (pcap_next_ex(adhandle, &header, &captured) != 1) {
            (void)0;
        }

        if (captured[12] == 8 && captured[13] == 6 && captured[21] == 0x02) {
            flag = 1;
            for (int j = 0; j < 4; j++) {
                if (captured[28 + j] != desIp[j]) {
                    flag = 0;
                    break;
                }       
            }

            /* Ruqest之后知道找到符合的响应包跳出循环 */
            if (flag) {
                memcpy(_host[i].ipaddr, desIp, 4);
                memcpy(_host[i].macaddr, captured + 22, 6);
                _hostArr[i] = 1;
                _hostCount++;

                printf("%lds\n", endTime - beginTime);
                break;
            }
        }
    }

    return 1;
}

int FindAllHost(pcap_t *adhandle, const uint8_t* netSeg, uint8_t* myip, uint8_t* mymac) 
{
    int flag = 0;
    uint8_t desMac[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t desIp[4];
    uint8_t gateway[4];
    time_t beginTime, endTime, timeout = 1;
    struct pcap_pkthdr *header;
    const uint8_t    *captured;

    memcpy(desIp, netSeg, 3);
    memcpy(gateway, netSeg, 3);

    gateway[3] = 0x01;

    for (uint8_t i = 0x01; i < 0xff; i++) {
        memcpy(desIp + 3, &i, 1);
        printf("正在搜索IP: %d.%d.%d.%d ...", desIp[0], desIp[1], desIp[2], desIp[3]);
        if (i == myip[3]) {
            myHost = i;
            memcpy(_host[i].ipaddr, myip, 4);
            memcpy(_host[i].macaddr, mymac, 6);
            _hostArr[i] = 1;
            _hostCount++;
            printf("0s\n");
            i++;
            continue;
        }
        
        (void)SendArpData(adhandle, desMac, desIp, mymac, gateway, 1, 1);

        time(&beginTime);
        while (1) {
            time(&endTime);

            if (endTime - beginTime > timeout) {
                printf("未找到\n");
                break;
            }

            while (pcap_next_ex(adhandle, &header, &captured) != 1) {
                (void)0;
            }

            if (captured[12] == 8 && captured[13] == 6 && captured[21] == 0x02) {
                flag = 1;
                for (int j = 0; j < 4; j++) {
                    if (captured[28 + j] != desIp[j]) {
                        flag = 0;
                        break;
                    }       
                }

                if (flag) {
                    memcpy(_host[i].ipaddr, desIp, 4);
                    memcpy(_host[i].macaddr, captured + 22, 6);
                    _hostArr[i] = 1;
                    _hostCount++;

                    printf("%lds\n", endTime - beginTime);
                    break;
                }
            }
        }
    }

    return _hostCount;
}

int GetHostMacByIp(const uint8_t* ip, uint8_t* mac)
{
    if (_hostArr[ip[3]] == 1) {
        memcpy(mac, _host[ip[3]].macaddr, 6);
        return 1;
    }

    return 0;
}

int GetHostIpByMac(const uint8_t* mac, uint8_t* ip)
{
    int flag = 0;

    for (int i = 0x01; i < 0xff; i++) {
        if (_hostArr[i] == 1) {
            flag = 1;
            for (int j = 0; j < 6; j++) {
                if (_host[i].macaddr[j] != mac[j]) {
                    flag = 0;
                    break;
                }
            }

            if (flag) {
                memcpy(ip, _host[i].ipaddr, 4);
                return 1;
            }
        }
    }

    return 0;
}

#endif