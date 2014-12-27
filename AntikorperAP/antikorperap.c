/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * Author: Josu Barrientos <josu_barrientos@hotmail.com>
 *
 * AntikorperAP is a complemental Access Point Scanner for Antikorper
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
//Tipos de definiciones de paquetes ethernet
#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */

//Cabecera radiotap 802.11
struct radiotap_header {
uint8_t it_rev;
uint8_t it_pad;
uint16_t it_len;
};

const u_char *bssid;
struct radiotap_header *rtaphdr;//puntero tipo estructura
char ssid[20];
char macAP[17];
//ssid y bssid del ap autorizado
char *ssidof;
char *bssidof;
char *macinter;

FILE *fp;//Puntero a fichero
time_t mytime; //Variable date

//Leer string truncados
char *read_string();

//Función ciclica para tratar paquetes
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

    const u_char *bssid;
    const u_char *essid;
    int offset = 0;

    //Cargamos cabecera radiotap
    rtaphdr = (struct radiotap_header *) packet;
    offset=rtaphdr->it_len;

    //Se utiliza el offset para ver si es un Beacon
    if(packet[offset] == 0x80)
    {

        // bssid = packet + offset + 10; // BSSID starts here in beacons
        bssid = packet + 36;// BSSID starts here in beacons
        essid = packet + 64;// ESSID starts here and ends with a simple 0x1

        unsigned int i = 0;
        while(essid[i] > 0x1)//Construimos el ESSID con Bucle hasta que se encuentre 0x1
        {

        ssid[i] = essid[i];// ssid[] string
        i++;

        }

        ssid[i] = NULL;//Añadimos el caracter nulo para eliminar restos de la asignación HEX

        sprintf(macAP,"%02X:%02X:%02X:%02X:%02X:%02X\n",bssid[0], bssid[1], bssid[2],bssid[3], bssid[4], bssid[5]);

        //printf("SSID %s ",ssid);
        //printf("BSSID %s\n",macAP);

        cicloanalisis(ssid,macAP);

    }
}

int main(int argc,char **argv)
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    //struct bpf_program fp;        /* to hold compiled program to perform the filter */
    bpf_u_int32 pMask;            /* Mascara de subred propia */
    bpf_u_int32 pNet;             /* Dirección IP propia*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;
    int op=0;


    terminaldata();

    printf("Introduce SSID de la red (iwconfig)\n");
    ssidof=read_string();

    printf("Introduce BSSID de la red (iwconfig)\n");
    getchar();
    bssidof=read_string();

    printf("Introduce dirección MAC del interfaz (iwconfig)\n");
    getchar();
    macinter=read_string();

    system("clear");

     while(op!=4 && op!=1 )
    {

        terminaldata();

        printf("\n");
        printf("***************MENU***************\n");
        printf("1º Arrancar Scan de entorno      \n");
        printf("2º Visualizar registro            \n");
        printf("3º About AntikorperAP             \n");
        printf("4º Salir                          \n");

        scanf("%d",&op);
        if(op==2)
        {

            system("nano registroAP.txt");
            system("clear");

        }

        if(op==3)
        {
            system("clear");
            about();
            getchar();
            system("clear");
        }

        if(op==4)
        {
            system("clear");
            return 0;

        }

    }

    system("clear");
    terminaldata();

    // Se carga lista de dispositivos de red disponibles
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    //Se printa la lista de dispositivos para que el usuario elija
    printf("\nLista de dispositivos disponibles en el sistema:\n\n");
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (Sorry, No description available for this device)\n");
    }

    // Solicita interfaz
    printf("\n¡¡Asegurese de que el interfaz esta en modo Monitor!!\n");
    printf("\nIntroduzca nombre de interfaz desde el que capaturar tráfico : ");
    getchar();
    fgets(dev_buff, sizeof(dev_buff)-1, stdin);

    // Clear off the trailing newline that fgets sets
    dev_buff[strlen(dev_buff)-1] = 0;

    //Analiza si se ha intorducido interfaz
    if(strlen(dev_buff))
    {
        dev = dev_buff;

        printf("\n ---A solicitado capturar en interfaz [%s] ---\n\n Iniciando Captura...\n",dev);
    }
    //Si no se ha introducido nada devuelve error
    if(dev == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    // Obtiene direccion de red y mascara
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // Se habre el interfaz para su captura
    descr = pcap_open_live(dev, 3000, 1,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Por paquete recibido se llama a la función callback
    pcap_loop(descr,-1, callback, NULL);

    printf("\nSalida de loop\n");
    return 0;
}

void cicloanalisis(char *data1,char *data2)
{                   //ssid      //bssid
        //mismos nombres
       if(strstr(data1,ssidof)!=NULL)
       {

            //diferentes macs
            if(strstr(data2,bssidof)==NULL)
            {

                printf("Rogue AP en %s\n",data2);
                savefile(ssid);
                actuador();
            }

       }
}

void savefile(char *data)
{

    /* open the file */
    fp = fopen("registroAP.txt", "a");
    if (fp == NULL)
    {
        printf("I couldn't open for appending.\n");
        exit(0);
    }

    mytime = time(NULL);

    /* write to the file */
    fprintf(fp,"%s %s\n", data,ctime(&mytime));

    /* close the file */
    fclose(fp);

}

char *read_string(void) {
  char *big = NULL, *old_big;
  char s[11] = {0};
  int len = 0, old_len;

  do {
    old_len = len;
    old_big = big;
    scanf("%10[^\n]", s);
    if (!(big = realloc(big, (len += strlen(s)) + 1))) {
      free(old_big);
      fprintf(stderr, "Out of memory!\n");
      return NULL;
    }
    strcpy(big + old_len, s);
  } while (len - old_len == 10);
  return big;
}

void terminaldata()
{

    printf("********************************************************\n");
    printf("*********************ANTIKORPER*************************\n");
    printf("********************************************************\n");

}

void about()
{


     printf("This program is free software; you can redistribute it and/or modify\n");
     printf("it under the terms of the GNU General Public License as published by\n");
     printf("the Free Software Foundation; either version 2 of the License, or\n");
     printf("(at your option) any later version.\n");
     printf("\n");
     printf("This program is distributed in the hope that it will be useful,\n");
     printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
     printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
     printf("GNU General Public License for more details.\n");
     printf("\n");
     printf("You should have received a copy of the GNU General Public License\n");
     printf("along with this program; if not, write to the Free Software\n");
     printf("Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,\n");
     printf("MA 02110-1301, USA.\n");
     printf("\n");
     printf("Author: Josu Barrientos <josu_barrientos@hotmail.com>\n");
     printf("\n");
     printf("Antikorper is an automatic Wireless Intrusion Detection System\n");

    getchar();

}

void actuador()
{

    char cmd[100];
    sprintf(cmd, "aireplay-ng --deauth 10 -a %s -h %s mon0 -D > /dev/null",bssidof,macinter);
    printf("%s",cmd);
    system(cmd);

}
