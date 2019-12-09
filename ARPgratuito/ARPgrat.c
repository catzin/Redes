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
#include<sys/time.h>

unsigned char etherARP[2] = {0x08,0x06};
unsigned char MacOrigen[6],Ipdestino[4],IpOrigen[4],MacDestino[6];
unsigned char HW[2] = {0x00,0x01};
unsigned char PR[2] = {0x08,0x00};
unsigned char opCodeSol[2] = {0x00,0x01};
unsigned char opCodeResp[2] = {0x00,0x02};
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char tramaresp[1514];
unsigned char tramaEnviar[1514];
unsigned char tramaRecibir[1514];
unsigned char tramaSolARPgrat[1514];
unsigned char LDH[1] = {0x06};
unsigned char LDP[1] = {0x04};
unsigned char macCero[6] = {0x00,0x00,0x00,0x00,0x00,0x00};


//ARP grat
unsigned char ipCero[4]={0x0,0x0,0x0,0x0};
unsigned char macInfractor[4];//sha
unsigned char ipOrigengrat[4];
unsigned char macDestinograt[4];
unsigned char ipDestinograt[4];
unsigned char macRegistrada[6];
char *ipAux; //para ip en cadena
char *macAux; //para mac en cadena
char *macbase;


//Datos Conexion
MYSQL *conn;
MYSQL_RES*res;
MYSQL_ROW row;

int obtenerDatos(int ds);
void estructuraTramaARPsol(unsigned char *trama);
void imprimeTrama(unsigned char *paq, int len);
void recibeARPres(int ds ,int indice,unsigned char *tramaRecibida,unsigned char *tramaRespuesta);
void obtenerIPdestino(void);
void enviarTrama(int ds,int index,unsigned char *trama);
void imprimeIp();
void formatoIp();
char *result(char *ip);
void conexionBD();
int filtroARPgrat(unsigned char * trama);
void DatosARPgrat(unsigned char *trama);
char *ipToString(unsigned char *ip);
char *macToString(unsigned char *mac);
char *mapearIP(char *ip);
void charToUnsigned();
void respuestaARPgrat(int ds,int indice,unsigned char *trama);
void solicitudARPgrat(int ds,int indice,unsigned char *trama);
//para compilar
//conexion  /* mysql -h localhost -u root -p*/
//gcc -o servidor ARPgrat.c `mysql_config --cflags --libs`  

int main(int argc, char *argv[]){

    int indice;
    int contador;
    int packet_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    char ipBase[20];
  
    if(packet_socket == -1){

        perror("\n Duermete otro rato we \n");
    }

    else{ 

        conexionBD();
        indice = obtenerDatos(packet_socket);
        recibeARPres(packet_socket,indice,tramaRecibir,tramaresp);
   }


       return 0;
}
void charToUnsigned(){

        unsigned int iMac[6];
        unsigned char mac[6];

        sscanf(macbase,"%x:%x:%x:%x:%x:%x",&iMac[0],&iMac[1],&iMac[2],&iMac[3],&iMac[4],&iMac[5]);

        for(int i = 0; i < 6; i++){
            mac[i]=(unsigned char)iMac[i];
        }
        
        memcpy(macRegistrada,mac,6);



}

void conexionBD(){

   char *server = "localhost";
   char *user = "root";
   char  *password ="";
   char *database = "ARPres";

   conn = mysql_init(NULL);


   if(!mysql_real_connect(conn,server,user,password,database,0,NULL,0)){

       fprintf(stderr,"%s\n",mysql_error(conn));

       perror("\n No se puede conectar a la base de datos!");
   }
   else{
       printf("Conexion Exitosa!\n");
   }

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

    if(ioctl(ds,SIOCGIFINDEX,&nic) == -1){
        perror("Error al obtener indice\n");
        exit(1);
    }
    else{

        index =  nic.ifr_ifindex;
        if(ioctl(ds,SIOCGIFHWADDR,&nic) == -1){
        perror("Error al obtener indice\n");
        exit(1);

    }
    else{

     
        memcpy(MacOrigen,nic.ifr_hwaddr.sa_data+0,6); // aqui solo copiamos esa direc de sa_data a macOrigen

        printf("\n\n");
        
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
    memcpy(trama+12,etherARP,2);
    //Mensaje ARP

    memcpy(trama+14,HW,2);
    memcpy(trama+16,PR,2);
    memcpy(trama+18,LDH,1);
    memcpy(trama+19,LDP,1);
    memcpy(trama+20,opCodeSol,2);

    //mensaje de ARP
    memcpy(trama+22,MacOrigen,6);
    memcpy(trama+28,ipCero,4);

    memset(trama+32,0x00,6); //THA
    memcpy(trama+38,Ipdestino,4);

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

int filtroARPgrat(unsigned char *trama){

    int bandera = 0;


        if(!memcmp(trama+12,etherARP,2) && !memcmp(trama+28,trama+38,4) || !memcmp(trama+12,etherARP,2)&& !memcmp(trama+28,ipCero,4)){

            bandera = 1;

        }
        else{
            bandera = 0;
        }

       
    
    return bandera; 

}


void DatosARPgrat(unsigned char *trama){

    memcpy(macInfractor,trama+6,6); //Mac Infractor//origen
    memcpy(ipOrigengrat,trama+28,4); //Ip origen //spa
    memcpy(macDestinograt,trama+32,6); // Mac destino //THA
    memcpy(ipDestinograt,trama+38,4); //Ip destino o 0.0.0.0 //tpa
}

char *ipToString(unsigned char *ip){
     char *ipAux = (char*)malloc(sizeof(char)*20);
     sprintf(ipAux,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
     strcat(ipAux,"\0");

     return ipAux;

}

char *macToString(unsigned char *mac){

    char *macx = (char*)malloc(sizeof(char)*30);
    sprintf(macx,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    strcat(macx,"\0");

    return macx;
}


void respuestaARPgrat(int ds,int indice,unsigned char *trama){

    memcpy(trama+0,macInfractor,6);
    memcpy(trama+6,macRegistrada,6);
    memcpy(trama+12,etherARP,2);
    memcpy(trama+14,HW,2);
    memcpy(trama+16,PR,2);
    memcpy(trama+18,LDH,1);
    memcpy(trama+19,LDP,1);
    memcpy(trama+20,opCodeResp,2);
    memcpy(trama+22,macRegistrada,6);
    memcpy(trama+28,IpOrigen,4); //ip a defender
    memcpy(trama+32,macInfractor,6);//
    memcpy(trama+38,IpOrigen,4);
}
void solicitudARPgrat(int ds,int indice,unsigned char *trama){
    memcpy(trama+0,MACbroad,6);
    memcpy(trama+6,macRegistrada,6);
    memcpy(trama+12,etherARP,2);
    memcpy(trama+14,HW,2);
    memcpy(trama+16,PR,2);
    memcpy(trama+18,LDH,1);
    memcpy(trama+19,LDP,1);
    memcpy(trama+20,opCodeSol,2);
    memcpy(trama+22,macRegistrada,6);
    memcpy(trama+32,macCero,6);
    memcpy(trama+28,IpOrigen,4); // IP defender
    memcpy(trama+38,IpOrigen,4); // IP defender
    
}

void recibeARPres(int ds ,int index,unsigned char *tramaRecibida,unsigned char* tramaRespuesta){

    int bandera = 0;
    int tam = 0;
    struct timeval start,end;
    long mtime = 0,seconds,useseconds;

    gettimeofday(&start,NULL);

    unsigned char aux [4];
    unsigned char aux2[4];
    while(1){

        tam = recvfrom(ds,tramaRecibida,1514,0,NULL,0);

        if(tam == -1 ){
            perror("\n Error al recibir");
            exit(1);
        }

        else{
            
            bandera =  filtroARPgrat(tramaRecibida);
            if( bandera && !memcmp(tramaRecibida,MACbroad,6)){

                printf("--------- ¡ Solicitud ARP Gratutito Karnal !------------\n");
               
                imprimeTrama(tramaRecibida,60);

                

                if(!memcmp(tramaRecibida+28,ipCero,4)){
                    // si la ip oigen es la 0 entonces :
                    memcpy(ipDestinograt,tramaRecibida+38,4);
                    memcpy(macDestinograt,tramaRecibida+6,6);
                    ipAux = ipToString(ipDestinograt);
                    printf("%s\n",ipAux);
                    //mapearIP(ipAux) y obtener mac asociada;
                    //si es diferente de null, la ip esta en la base y guardo la mac asociada a esa ip
                    //mac de la trama en Cadena
                    macbase = mapearIP(ipAux);
                    
                    
                    if(macbase != NULL){
                             
                        if(!strcmp(macDestinograt,macbase)){

                            printf("A la ip si le corresponde esa mac");

                        }

                        else{

                            memcpy(macDestinograt,tramaRecibida+6,6);

                            printf("no le corresponde\n!!");
                            
                            //mac de la base a unsignedChar la guarda en "macRegistrada"
                            charToUnsigned();
                            memcpy(IpOrigen,ipDestinograt,4);
                            memcpy(macInfractor,macDestinograt,4);

                            

                            respuestaARPgrat(ds,index,tramaRespuesta);
                            enviarTrama(ds,index,tramaRespuesta);

                            solicitudARPgrat(ds,index,tramaSolARPgrat);
                            enviarTrama(ds,index,tramaSolARPgrat);

                        
                            printf("La respuestas es:\n");
                            imprimeTrama(tramaRespuesta,60);
                            
                            //printf("respuesta!\n");
                           
                        }

                    }

                   


                    
                }

                else{

                    
                    
                    //copiamos 
                    memcpy(ipDestinograt,tramaRecibida+28,4);
                    memcpy(macDestinograt,tramaRecibida+6,6);

                    ipAux = ipToString(ipDestinograt);
                    printf("ip origen agarrada:\n");
                    printf("%s\n",ipAux);
                   
                    macbase = macToString(macDestinograt);

                    printf("mac que agarra:\n");
                    printf("%s\n",macbase);
                    printf("\n\n");


                    if(macbase !=NULL){

                        char *macDes = macToString(macDestinograt);

                         if(!strcmp(macDes,macbase)){

                            printf("A la ip si le corresponde esa mac");

                        }

                        else{
                            
                            memcpy(macDestinograt,tramaRecibida+6,6);
                            printf("no le corresponde!!\n");
                            
                            //mac de la base a unsignedChar la guarda en "macRegistrada"
                            charToUnsigned();
                            memcpy(IpOrigen,ipDestinograt,4);
                           

                            respuestaARPgrat(ds,index,tramaRespuesta);
                            enviarTrama(ds,index,tramaRespuesta);

                            /*solicitudARPgrat(ds,index,tramaSolARPgrat);
                            enviarTrama(ds,index,tramaSolARPgrat);*/

                          
                            printf("La trama es respuesta!\n");
                            imprimeTrama(tramaRespuesta,60);
                            


                        }


                    }



                }
                  
             
              //break;

            }
    
        }


        gettimeofday(&end,NULL);

        seconds = end.tv_sec - start.tv_sec;
        useseconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 +useseconds/1000.0)+0.5;


    }

}


//METODOS SQL

char *mapearIP(char *ip){

    char consulta[250];
    char *dato = (char*)malloc(sizeof(char)*20);

    sprintf(consulta,"SELECT mac FROM Respuestas WHERE ip = '%s'",ip);
    mysql_query(conn,consulta);

    res = mysql_use_result(conn);
    row = mysql_fetch_row(res);

    if(row != NULL){
        strcpy(dato,row[0]);

    }
    else{
        dato = NULL;
    }

    return dato;
    

}

