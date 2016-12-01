#ifndef _SKYSY_ARPATTACK_ARGCONFIGURE_C
#define _SKYSY_ARPATTACK_ARGCONFIGURE_C

#include "Argconfigure.h"

int charToInt(char c);

int ConfigureByArgs(int argc, const char* argv[], struct Configure* conf)
{
    int argLen = 0;
    int value = 0;

    for (int i = 1; i < argc; i++) {
        argLen = strlen(argv[i]);

        switch (argv[i][1]) {
        case 'a':
            /* 获取输入的网卡 */
            sprintf(conf->adapter, "%s", argv[i] + 2);
            break;
        case 'i':
            value = 0;
            /* 获取输入的IP */
            for (int j = 2, k = 0; j < argLen; j++) {
                if (argv[i][j] == '.') {
                    conf->localIp[k] = value;
                    value = 0;
                    k++;
                    continue;
                }

                value *= 10;
                value += charToInt(argv[i][j]);
            }
            conf->localIp[3] = value;
            break;
        case 'm':
            /* 获取输入的Mac地址 */
            conf->localMac[0] = charToInt(argv[i][2]) * 0x10 + charToInt(argv[i][3]);
            conf->localMac[1] = charToInt(argv[i][5]) * 0x10 + charToInt(argv[i][6]);
            conf->localMac[2] = charToInt(argv[i][8]) * 0x10 + charToInt(argv[i][9]);
            conf->localMac[3] = charToInt(argv[i][11]) * 0x10 + charToInt(argv[i][12]);
            conf->localMac[4] = charToInt(argv[i][14]) * 0x10 + charToInt(argv[i][15]);
            conf->localMac[5] = charToInt(argv[i][17]) * 0x10 + charToInt(argv[i][18]);
            break;
        case 'g':
            /* 获取输入的网关 */
            value = 0;
            for (int j = 2, k = 0; j < argLen; j++) {
                if (argv[i][j] == '.') {
                    conf->gateway[k] = value;
                    value = 0;
                    k++;
                    continue;
                }

                value *= 10;
                value += charToInt(argv[i][j]);
            }
            conf->gateway[3] = value;
            break;
        case 'o':
            if (argv[i][2] == 't') {
                conf->op = 1;
            }
            if (argv[i][2] == 'h') {
                conf->op = 2;
            }
            if (argv[i][2] == 'p') {
                conf->op = 3;
            }

            if (conf->op == 0) {
                conf->op = -1;
            }
            break;
        case 'c':
            break;
        case 'u':
            break;
        case 'h':
            PrintArgHelp();
            return -1;
        default:
            printf("参数-%c错误，请使用-h查看帮助\n", argv[i][1]);
            return -1;
        }
    }

    return 0;
}

void PrintArgHelp()
{
    printf("参数帮助文档：\n");
    printf("\t\t-a 网卡 (必填参数)\n");
    printf("\t\t-i IP地址 (默认从网卡读取)\n");
    printf("\t\t-m Mac地址 (默认从网卡读取)\n");
    printf("\t\t-g 网关地址 (默认为x.x.x.1)\n");
    printf("\t\t-o 操作模式 (默认为阻塞模式)\n");
    printf("\t\t   transmit为转发模式，hijackDNS为劫持DNS模式\n");
    printf("\t\t   printHost为打印局域网下所有主机\n");
    printf("\t\t-c 欺骗目标IP (若填写该参数，程序将只对目标IP进行限制)\n");
    printf("\t\t-u 返回IP地址 (开启DNS劫持必填参数)\n");
    printf("\t\t-h 帮助文档\n\n");
    printf("eg. EthernetPolice -aen0 -i192.168.0.2 -mff:ff:ff:ff:ff:ff -g192.168.0.1 -ohijackDNS -u114.114.114.114\n");
}

int charToInt(char c)
{
    int hex = 0;
    if (c < '0' || c > '9') {
        hex = c - 'a';
    }
    if (hex) {
        return hex + 10;
    }
    return (int)(c - '0');
}

#endif