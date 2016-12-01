#ifndef _SKYSY_ARPATTACK_ARGCONFIGURE_H
#define _SKYSY_ARPATTACK_ARGCONFIGURE_H

#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

struct Configure {
    char adapter[10];      /* 网卡 */
    uint8_t localIp[4];    /* 本地Ip地址 */
    uint8_t localMac[6];   /* 本地Mac地址 */
    uint8_t gateway[4];    /* 网关 */
    int op;                /* 操作模式 0为阻塞模式，1为转发模式，2为DNS劫持模式，3为打印主机*/
};

/* 解析参数函数 */
int ConfigureByArgs(int argc, const char* argv[], struct Configure* conf);

/* 帮助函数 */
void PrintArgHelp();

int charToInt(char c);

#endif