#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>

#include <pcap.h>

#include "Host.h"
#include "Arp.h"
#include "Attack.h"
#include "Argconfigure.h"


void GetMacFromDevice(uint8_t mac[6], const char *devicename);
void GetIpFromDevice(uint8_t ip[4], const char *devicename);
int charToInt(char c);

int main(int argc, const char* argv[])
{
    uint8_t mac[6];                     /* Mac */
    uint8_t ip[4];                      /* IP */
    uint8_t netseg[3];                  /* 网段 */
    uint8_t gateway[4];                 /* 网关 */
    pcap_t *adhandle;                   /* PCAP句柄 */
    char errbuf[PCAP_ERRBUF_SIZE];
    int DefaultTimeout = 100;
    int status;
    struct Configure conf = {0};        /* 配置信息 */

    /* 解析参数，有效参数返回0，存在无效参数返回-1 */
    status = ConfigureByArgs(argc, argv, &conf);
    if(status == -1) {
        exit(0);
    }
    
    /* 用户必须输入网卡 */
    if (conf.adapter[0] == '\0') {
        printf("网卡不能为空，请使用-h查看帮助\n");
        exit(0);
    }

    adhandle = pcap_open_live(conf.adapter, 65536, 1, DefaultTimeout, errbuf);
    if (adhandle == NULL) {
        printf("%s\n", errbuf);
        exit(-1);
    }

    if (!(conf.localIp[0] + conf.localIp[1] + conf.localIp[2] + conf.localIp[3])) {
        GetIpFromDevice(ip, conf.adapter);
    } else {
        memcpy(ip, conf.localIp, 4);
    }

    memcpy(netseg, ip, 3);

    if (!(conf.localMac[0] + conf.localMac[1] + conf.localMac[2] + conf.localMac[3] + conf.localMac[4] + conf.localMac[5])) {
        GetMacFromDevice(mac, conf.adapter);
    } else {
        memcpy(mac, conf.localMac, 6);
    }

    if (!(conf.gateway[0] + conf.gateway[1] + conf.gateway[2] + conf.gateway[3])) {
        memcpy(gateway, ip, 3);
        gateway[3] = 0x01;
    } else {
        memcpy(gateway, conf.gateway, 4);
    }

    /*
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    printf("%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    */

    FindHost(adhandle , gateway, ip, mac);

    switch(conf.op) {
    case 0:
        ArpCheat(adhandle, netseg, mac, ip, 0);
        break;
    case 1:
        ArpCheat(adhandle, netseg, mac, ip, 1);
        break;
    case 2:
        break;
    case 3:
        break;
    default:
        printf("操作模式错误，请使用-h查看帮助\n");
        break;
    }

    return 0;
}

/* OS X系统编译这部分代码 */
#ifdef __APPLE__

void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
    FILE* stream;
    char buf[256];
    char shellJob[256];

    memset(buf, 0, sizeof(buf));
    memset(shellJob, 0, sizeof(shellJob));

    sprintf(shellJob, "ifconfig %s | grep ether", devicename);

    if ((stream = popen(shellJob, "r")) == NULL) {
        printf("Shell error\n");
        exit(0);
    }

    fgets(buf, sizeof(buf), stream);
    mac[0] = charToInt(buf[7]) * 0x10 + charToInt(buf[8]);
    mac[1] = charToInt(buf[10]) * 0x10 + charToInt(buf[11]);
    mac[2] = charToInt(buf[13]) * 0x10 + charToInt(buf[14]);
    mac[3] = charToInt(buf[16]) * 0x10 + charToInt(buf[17]);
    mac[4] = charToInt(buf[19]) * 0x10 + charToInt(buf[20]);
    mac[5] = charToInt(buf[22]) * 0x10 + charToInt(buf[23]);
}

void GetIpFromDevice(uint8_t ip[4], const char *devicename)
{
    FILE* stream;
    char buf[256];
    char shellJob[256];
    int value = 0;

    memset(buf, 0, sizeof(buf));
    memset(shellJob, 0, sizeof(shellJob));

    sprintf(shellJob, "ifconfig %s | grep 'inet '", devicename);
    if ((stream = popen(shellJob, "r")) == NULL) {
        printf("Shell error\n");
        exit(0);
    }

    fgets(buf, sizeof(buf), stream);
    for (int i = 6, j = 0; i < strlen(buf); i++) {
        if (buf[i] == '.') {
            ip[j] = value;
            value = 0;
            j++;
            continue;
        }

        if (buf[i] == ' ') {
            ip[j] = value;
            break;
        }

        value *= 10;
        value += charToInt(buf[i]);
    }
}

#endif

/* Linux系统编译这部分代码 */
#ifdef __linux__

void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
    int err;
    int sock;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        perror( "socket error1\n"); 
        return; 
    } 

    strcpy(ifr.ifr_name, devicename); 
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    { 
        perror("ioctl error!\n"); 
        return; 
    } 

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    err = close(sock);
    assert(err != -1);
    return;
}

void GetIpFromDevice(uint8_t ip[4], const char *devicename)
{
    int err;
    int sock;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        perror( "socket error1\n"); 
        return; 
    } 

    strcpy(ifr.ifr_name, devicename); 
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0) 
    { 
        perror("ioctl error!\n"); 
        return; 
    } 

    memcpy(ip, ifr.ifr_addr.sa_data + 2, 4);

    err = close(sock);
    assert(err != -1);
    return;
}

#endif