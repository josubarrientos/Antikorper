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
 * Antikorper is an automatic Wireless Intrusion Detection System
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define MACSIZE 10
//Tipos de definiciones de paquetes ethernet
#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
	};

//Lista enlazada
typedef struct ElementoLista{
    char * dato;
    struct ElementoLista *siguiente;
}Elemento;

typedef struct Listadir{
    Elemento *inicio;
    Elemento *fin;
    int tamano;
}Lista;

Lista *lista;

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr_t;

 arphdr_t *arpheader = NULL;       /* Puntero a ARP header */

const struct sniff_ethernet *ethernet; /* ethernet header */
const struct sniff_ip *ip; /* IP header */
const struct sniff_tcp *tcp; /* TCP header */
const char *payload; /* Packet payload */

FILE *fp;//Puntero a fichero
time_t mytime; //Variable date

//Variables de volcado
char fuenteMAC[MACSIZE];
char destinoMAC[MACSIZE];

/*Datos de Access Point*/
char *ipAP;
char *macAP;
char *etherAP;

//Variables ARP
char ipARPFuente[15];
char ipARPDestino[15];
char macARPFuente[17];
char macARPDestino[17];

/*inicializa la lista*/
void incializacion(Lista *lista);
/*En caso de error devuelve -1 sino 0*/
int InsercionEnListaVacia(Lista *lista, char *dato);
/*insertar en inicio de la lista*/
int InsercionInicioLista(Lista *lista, char *dato);
 /*muestra la lista entera*/
void visualizacion(Lista *lista);
//Arranque de la lista enlazada
void arrancarlista();
//Leer string truncados
char *read_string();

//Una lista enlazada sin ningun elemento se llama lista vacía.
//Su puntero inicial tiene el valor NULL
//Si un la lista es de 1 solo elemento, el campo siguiente apunta a NULL

//Función ciclica para tratar paquetes
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

    static int count = 1;

    //printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    ethernet = (struct sniff_ethernet*)(packet); /*Puntero a cabecera ethernet*/
    /* ethernet headers are always exactly 14 bytes */
    arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */

    //sha[] para mac fuente, spa[] para ip fuente, tha[] para mac destino y tpa[] para ip destino
    if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {

    sprintf(ipARPFuente,"%d.%d.%d.%d",arpheader->spa[0],arpheader->spa[1],arpheader->spa[2],arpheader->spa[3]);
    sprintf(macARPFuente,"%02X:%02X:%02X:%02X:%02X:%02X",arpheader->sha[0],arpheader->sha[1],arpheader->sha[2],arpheader->sha[3],arpheader->sha[4],arpheader->sha[5]);
    sprintf(ipARPDestino,"%d.%d.%d.%d",arpheader->tpa[0],arpheader->tpa[1],arpheader->tpa[2],arpheader->tpa[3]);
    sprintf(macARPDestino,"%02X:%02X:%02X:%02X:%02X:%02X",arpheader->tha[0],arpheader->tha[1],arpheader->tha[2],arpheader->tha[3],arpheader->tha[4],arpheader->tha[5]);
    //printf("IP Fuente: %s tamaño %d\n",ipARPFuente,sizeof(ipARPFuente));
    //printf("MAC Fuente: %s tamaño %d\n",macARPFuente,sizeof(macARPFuente));
    //printf("IP Destino: %s\n",ipARPDestino);
    //printf("MAC Destino: %s\n",macARPDestino);

    arppoisoning(ipARPFuente,macARPFuente);

    }

    // Convertir valores HEX a cadena
    sprintf(fuenteMAC,"%02X:%02X:%02X:%02X:%02X:%02X",ethernet->ether_shost[0],
                ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3],
                ethernet->ether_shost[4], ethernet->ether_shost[5]);
    //printf("\n Fuente = %s\n", fuenteMAC);

    if(cicloanalisis(lista,fuenteMAC)!=1)/*Evalua si las direcciones MAC estan autorizadas*/
   {

        savefile(fuenteMAC,0);

        printf("Hay usuarios no autorizados en la red MAC: %s\n",fuenteMAC);

        actuador(fuenteMAC);

    }

    // Convertir valores HEX a cadena
    sprintf(destinoMAC,"%02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_dhost[0],
                ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3],
                ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
    //printf("\n Destino = %s\n", destinoMAC);

    /* Evaluar tipo de paquete*/
    /*if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(ethernet->ether_type),
                ntohs(ethernet->ether_type));
    }else  if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(ethernet->ether_type),
                ntohs(ethernet->ether_type));
    }else {
        printf("Ethernet type %x not IP", ntohs(ethernet->ether_type));

    }*/

}

int main(int argc,char **argv)
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    //struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* Mascara de subred propia */
    bpf_u_int32 pNet;             /* Dirección IP propia*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;
    int op=0;

    terminaldata();

    mac_loader(); /*Carga direcciones MAC de fichero*/

    /*BSSID address is the ethernet port +/- 1, i.e. 00-04-01-ad-cf-45 for ethernet and 00-04-01-ad-cf-46 for BSSID*/
    printf("________________________________________________________");
    printf("\nNOTA: En algunas tarjetas la BSSID es la ethernet +/- 1\n");
    printf("¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯\n\n");
    printf("Introduce Gateway/IP Access Point de la red (comando arp)\n");
    ipAP=read_string();

    printf("Introduce direccióm MAC de Access Point (comando arp)\n");
    getchar();
    macAP=read_string();
    getchar();

    printf("Introduce BSSID de Access Point (comando iwconfig)\n");
    etherAP=read_string();
    getchar();
    system("clear");



    while(op!=6 && op!=3 )
    {

        terminaldata();

        printf("\n");
        printf("***************MENU***************\n");
        printf("1º Visualizar clientes autorizados\n");
        printf("2º Modificar clientes autorizados \n");
        printf("3º Arrancar Antikorper            \n");
        printf("4º Visualizar registro            \n");
        printf("5º About Antikorper               \n");
        printf("6º Salir                          \n");

        scanf("%d",&op);

        if(op==1)
        {
            visualizacion(lista);
            getchar();
            system("clear");
        }

        if(op==2)
        {

            system("nano authomac.txt");
            system("clear");

        }

        if(op==4)
        {

            system("nano registroIntru.txt");
            system("clear");

        }

         if(op==5)
        {

            system("clear");
            about();
            getchar();
            system("clear");

        }

        if(op==6)
        {
            system("clear");
            return 0;

        }

    }

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
    printf("\nIntroduzca nombre de interfaz desde el que capaturar tráfico : ");
    getchar();
    fgets(dev_buff, sizeof(dev_buff)-1, stdin);

    // Clear off the trailing newline that fgets sets
    dev_buff[strlen(dev_buff)-1] = 0;

    system("clear");

    //Analiza si se ha intorducido interfaz
    if(strlen(dev_buff))
    {
        dev = dev_buff;
        printf("\n ---A solicitado capturar en interfaz [%s] ---\n\n Iniciando Captura...",dev);
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
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Filtros disponibles
    /*if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }*/

    // Set the filter compiled above
    /*if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }*/

    // Por paquete recibido se llama a la función callback
    pcap_loop(descr,-1, callback, NULL);

    printf("\nSalida de loop\n");
    return 0;
}

/*Inicializar una lista*/
void incializacion(Lista *lista)
{
    lista->inicio = NULL;
    lista->fin= NULL;
    lista->tamano = 0;
}

/*Insercion al inicio de una lista*/
int InsercionInicioLista(Lista *lista, char *dato)
{
    Elemento *nuevo_elemento;
    if((nuevo_elemento = (Elemento *)malloc(sizeof(Elemento)))==NULL)
        return -1;
    if((nuevo_elemento->dato = (char *)malloc(50*sizeof(char)))==NULL)
        return -1;
    strcpy(nuevo_elemento->dato, dato);

    nuevo_elemento->siguiente = lista->inicio;
    lista->inicio=nuevo_elemento;
    lista->tamano++;
    return 0;
}

/*visualizar lista entera*/
void visualizacion(Lista *lista)
{
    Elemento *actual;
    actual = lista->inicio;
    actual = actual->siguiente;
    while(actual != NULL){
            printf("%s",actual->dato);
            actual = actual->siguiente;
        }

    printf("\nPulse una tecla para volver\n");
    getchar();
    printf("\n\n");
}

int cicloanalisis(Lista *lista,char *data)
{

    int exist=0;
    Elemento *actual;
    actual = lista->inicio;
    actual = actual->siguiente;
     while(actual != NULL)
     {
        if(strcmp(actual->dato, data)==0)
        {
            //exit=1 si hay intruso
            exist=1;

        }
        actual = actual->siguiente;
     }

    return exist;

}

void mac_loader()
{

    FILE *f = fopen("authomac.txt", "r");
    char *nom;
    char cadena[17];
    Elemento *actual;
    if ((lista = (Lista *) malloc (sizeof (Lista))) == NULL)
        return -1;
    if ((nom = (char *) malloc (50)) == NULL)
        return -1;
    actual = NULL;

    incializacion(lista);

    if (f==NULL)
    {
       perror ("Error al abrir fichero.txt");
       return -1;
    }

    while (fgets(cadena, 18, f) != NULL)
    {

      InsercionInicioLista (lista, cadena);

    }

    //visualizacion(lista);


}

void arppoisoning(char *datoip,char *datomac)
{
    //Evalua si las IP del ARP y del AP coinciden
    if(strcmp(datoip,ipAP)==0)
    {

        //Evalua si las MAC del ARP y del AP son diferentes
        if(strcmp(datomac,macAP)!=0)
        {
            savefile(datomac,1);
            actuador(datomac);
            printf("\nARP Poisoning en maquina %s\n",datomac);

        }

    }


}

void actuador(char *data)
{

    //sprintf(comando,"aireplay-ng -0 0 -a %s -c %s mon0 --ignore-negative-one",macAP2,data);

    char cmd[100];
    //printf("datata %s",etherAP);
    sprintf(cmd, "sudo aireplay-ng -0 5 -a %s -c %s mon0 --ignore-negative-one > /dev/null",etherAP,data);
    //printf("%s",cmd);
    system(cmd);


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

void savefile(char *data,int tipo)
{

    /* open the file */
    fp = fopen("registroIntru.txt", "a");
    if (fp == NULL)
    {
        printf("I couldn't open for appending.\n");
        exit(0);
    }

    mytime = time(NULL);

    if(tipo==0)
    {

    /* write to the file */
    fprintf(fp,"Intruso en dirección %s %s", data,ctime(&mytime));

    }else
    {

    fprintf(fp,"ARP Poisoning desde %s %s", data,ctime(&mytime));

    }

    /* close the file */
    fclose(fp);

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
