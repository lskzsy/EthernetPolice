#ifndef _SKYSY_ARPATTACK_ATTACK_H
#define _SKYSY_ARPATTACK_ATTACK_H
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include "Arp.h"
#include "Host.h"
#include "Analyse.h"

void ArpCheat(pcap_t *adhandle, uint8_t* netseg, uint8_t* mymac, uint8_t* myip, int op);

#endif