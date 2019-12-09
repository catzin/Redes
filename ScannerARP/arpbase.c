#include <sys/socket.h>
#include<stdio.h>
#include<stdlib.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include<string.h> 
#include<mysql/mysql.h>
#include <sys/time.h>

unsigned char etterARP[2] = {0x08,0x06};
unsigned char MacOrigen[6],Ipdestino[4],IpOrigen[4],MacDestino[6];
unsigned char HW[2] = {0x00,0x01};
unsigned char PR[2] = {0x08,0x00};
unsigned char opCodeSol[2] = {0x00,0x01};
unsigned char opCodeResp[2] = {0x00,0x02};
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char tramaEnviar[1514];
unsigned char tramaRecibir[1514];
unsigned char LDH[1] = {0x06};
unsigned char LDP[1] = {0x04};

int obtenerDatos(int ds);
void estructuraTramaARPsol(unsigned char *trama);
void imprimeTrama(unsigned char *paq, int len);
void recibeARPres(int ds ,unsigned char *trama);
void obtenerIPdestino(void);
void enviarTrama(int ds,int index,unsigned char *trama);

void imprimeIp();


int main(){

    int indice;
    int contador;
    int packet_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    char ipbase[20];
    char macbase[20];
    char consulta[250];

    //conexion  /* mysql -h localhost -u root -p*/
    //gcc -o base arp3.c `mysql_config --cflags --libs`   

     MYSQL conexion;
     mysql_init(&conexion);

     if(mysql_real_connect(&conexion,"localhost","root","root","ARPres",0,NULL,0)){
        printf("\n Conexion exitosa!");
    }
    else{
        perror("\n Fallo en la conexion");

    }  

    if(packet_socket == -1){
        perror("\n no mams este wey");
    }

    else{ 

        indice = obtenerDatos(packet_socket);
        obtenerIPdestino();

        for(int k = 0; k < 254; k++){

            Ipdestino[3] = k;

        
            estructuraTramaARPsol(tramaEnviar);
            printf("Trama enviada:\n");
            imprimeTrama(tramaEnviar,60);
            enviarTrama(packet_socket,indice,tramaEnviar);
            printf("Trama recibida:\n\n");
            recibeARPres(packet_socket,tramaRecibir);

            if(MacDestino[0] != 0){

            snprintf(ipbase,sizeof(ipbase),"%d.%d.%d.%d",Ipdestino[0],Ipdestino[1],Ipdestino[2],Ipdestino[3]);
            snprintf(macbase,sizeof(macbase),"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",MacDestino[0],MacDestino[1],MacDestino[2],MacDestino[3],MacDestino[4],MacDestino[5]);

            sprintf(consulta,"INSERT into Respuestas values ('%s','%s')",ipbase,macbase);
            mysql_query(&conexion,consulta);

           
            memset(macbase,0,20);
            memset(MacDestino,0,6);
        

            }
           

        
        }
            
    
    }

         
    return 0;

 
}

void obtenerIPdestino(void){
     char ip[50];
     scanf("%s",ip);

     if(inet_aton(ip,(struct in_addr *)Ipdestino) == 0){
         perror("\n No mams we, duermte otro rato we , alch");
     }
      

}

void imprimeIp(){
    for(int i = 0; i < 4; i++){
        printf("%d",Ipdestino[i]);
    }
}

int obtenerDatos(int ds){

    int index;
    struct ifreq nic ;
    printf("\nInserta el nombre\n");
    //El nombre se guarda en atributo de la struct ifr_name
    scanf("%s",nic.ifr_name); 
    printf("\n\n");

       /*--ioctl con la peticion SIOCGIFHWADDR
       --> Regresa el índice de la interfaz en la variable --> ifr_ifindex.*/
    if(ioctl(ds,SIOCGIFINDEX,&nic) == -1){
        perror("Error al obtener indice\n");
        exit(1);
    }
    else{

        index =  nic.ifr_ifindex;

        /* argumentos : descriptor de socket , codigo de solicitud(petición), 
        puntero a al bloque de memoria donde esta la struct nic*/

        if(ioctl(ds,SIOCGIFHWADDR,&nic) == -1){
        perror("Error al obtener indice\n");
        exit(1);

        /*en ifr_hwaddr.sa_data -> se guarda la direccón fisica de interfaz de red
        si no hay ningun error en el ioctl con la peticion SIOCGIFHWADDR*/ 
    }
    else{

        /*args de memcpy : * destino, *void origen , n bytes a copiar */
        /* ifr_hwaddr -> es un sock_addr  y sock_addr.sa_data --> es un arreglo char de 14 bits de direccion
        de protocolo  y ahí está nuestra direc. fisica de interfaz de red.  */

        memcpy(MacOrigen,nic.ifr_hwaddr.sa_data+0,6); // aqui solo copiamos esa direc de sa_data a macOrigen

        printf("\n\n");
        
        /*en ifr_addr.sa_data -> se guarda la dirección IP de interfaz de red
        si no hay ningun error en el ioctl con la peticion SIOCGIFADDR, a partir del byte 2*/ 
        if(ioctl(ds,SIOCGIFADDR,&nic) == -1){
            perror("\n Error al obtener la IP");
        }

        else{

            memcpy(IpOrigen,nic.ifr_addr.sa_data+2,6);
        }
  
    }
    
    }

    return index;
}

void estructuraTramaARPsol(unsigned char *trama){
  
    memcpy(trama+0,MACbroad,6);
    //Encabezado mac
    memcpy(trama+6,MacOrigen,6);
    memcpy(trama+12,etterARP,2);
    //Mensaje ARP
    memcpy(trama+14,HW,2);
    memcpy(trama+16,PR,2);
    memcpy(trama+18,LDH,1);
    memcpy(trama+19,LDP,1);
    memcpy(trama+20,opCodeSol,2);
    //mensaje de ARP
    memcpy(trama+22,MacOrigen,6);
    memcpy(trama+28,IpOrigen,4);

    memset(trama+32,0x00,6); //THA
    memcpy(trama+38,Ipdestino,4);

   /*RecibeTrama lleva el filtro 

   if(!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,etherARP,2)&& !memcmp(trama+20,opcodeResp) && !memcmp(trama+28,IpDestino,4));
   
   */

}

void imprimeTrama(unsigned char *paq, int len){

    for(int i = 0;i < len; i++){

        if(i%16==0)
            printf("\n");
        printf("%.2x ",paq[i]);
    }

    printf("\n");
}


void enviarTrama(int ds, int index, unsigned char *trama){

    int tam;
    struct sockaddr_ll nic;

    memset(&nic,0x00,sizeof(nic)); //preguntar que pedo

    nic.sll_family=AF_PACKET;
    nic.sll_protocol=htons(ETH_P_ALL);
    nic.sll_ifindex=index;

    tam = sendto(ds,trama,60,0,(struct sockaddr *)&nic,sizeof(nic));
    if(tam==-1){

        perror("\n Erros al enviar");
        exit(1);
    }
    
    else{

        perror("Exito al enviar\n");
    }
    
}

void recibeARPres(int ds ,unsigned char *trama){

    int bandera = 0;
    int tam = 0;
    struct timeval start,end;
    long mtime = 0,seconds,useseconds;

    gettimeofday(&start,NULL);


    while(mtime < 1500){

        tam = recvfrom(ds,trama,1514,0,NULL,0);

        if(tam == -1 ){
            perror("\n Error al recibir");
            exit(1);
        }

        else{

            if(!(memcmp(trama+0,MacOrigen,6))&& !(memcmp(trama+12,etterARP,2)) && !(memcmp(trama+20,opCodeResp,2)) && !(memcmp(trama+28,Ipdestino,4))){

              imprimeTrama(trama,tam);
              memcpy(MacDestino,trama+6,6);

              break;

            }
    
        }


        gettimeofday(&end,NULL);

        seconds = end.tv_sec - start.tv_sec;
        useseconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 +useseconds/1000.0)+0.5;


    }

}



// mPDF  ---> con materialize   - - -> tenemos 10