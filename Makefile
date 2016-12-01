Arpattack: main.o Arp.o Host.o Attack.o Analyse.o Argconfigure.o
	cc main.o Arp.o Host.o Attack.o Analyse.o Argconfigure.o -o EthernetPolice -lpcap -Wall
	rm main.o Arp.o Host.o Attack.o Analyse.o Argconfigure.o

main.o: main.c
	cc -c main.c 
Arp.o: Arp.c Arp.h
	cc -c Arp.c
Host.o: Host.c Host.h
	cc -c Host.c
Attack.o: Attack.c Attack.h
	cc -c Attack.c
Analyse.o: Analyse.c Analyse.h
	cc -c Analyse.c
Argconfigure.o: Argconfigure.c Argconfigure.h
	cc -c Argconfigure.c

clean:
	rm main.o Arp.o Host.o Attack.o Analyse.o Argconfigure.o

install:
	sudo mv EthernetPolice /usr/local/bin