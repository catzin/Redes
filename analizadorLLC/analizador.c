#include <stdio.h>
#include "tramas.h"
#include "Dibujar.h"

void aberTumacBB(unsigned char *trama);
void longitud(unsigned char *trama);
void analizarTrama(unsigned char *trama);
void DSAP_SSAP(unsigned char *trama);
int tipoTrama(unsigned char *trama);
void Caso_1byte(unsigned char *trama);
void Caso_2bytes(unsigned char *trama ,int opc);
//FUNCIONES DE ANALISIS

void imprimeTrama(unsigned char *paq, int len){

    for(int i = 0;i < len; i++){

        if(i%16==0)
            printf("\n");

        printf("%s %.2x %s",MARRON,paq[i],END);
    }

    printf("\n\n");
}

int main(void){

    borrarPantalla();

    for(int i = 0; i < 44; i++){

        if(i == 15 || i == 19 || i == 23){
            printf("%s --------------------------> LA TRAMA :%d <------------------------------ %s ",PURPURA_CLARO,i+1,END);
            imprimeTrama(tramas[i],192);
            analizarTrama(tramas[i]);
        }

        else{
            printf("%s --------------------------> LA TRAMA : %d <---------------------%s ",PURPURA_CLARO,i+1,END);
            imprimeTrama(tramas[i],50);
            analizarTrama(tramas[i]);
        }

    } 
    return 0;
}



void aberTumacBB(unsigned char *trama){

    int i,j;
    imprime(PURPURA_CLARO_NEG,"MAC DESTINO: ");
    for(i = 0; i < 6; i++){
        printf("%s%.2X:%s",VERDE,trama[i],END);
    }
    printf("\n");
    imprime(PURPURA_CLARO_NEG,"MAC ORINGEN: ");
    for(j = 6; j < 12; j++ ){
        printf("%s%.2X:%s",VERDE,trama[j],END);
    }
    printf("\n");

}

void longitud(unsigned char *trama){
    
    int len =  (trama[12]<<8) + trama[13];

    printf("%s La longitud es : %d < 1500 %s \n",AZUL_CLARO,len,END);
    printf("\n");
}


// I_G   y  C_R - -> trama[14] y trama[15]
void DSAP_SSAP(unsigned char *trama){

    printf("%s ----------------> DSAP y SSAP: <------------------------ %s \n",PURPURA_CLARO,END);

    if((trama[14]&0x01)==1)
        imprime(PURPURA_CLARO_NEG,"IG = 0: SAP de grupo");
    else
        imprime(PURPURA_CLARO_NEG,"\n IG =1: SAP individual.");
    	
    if((trama[15]&0x01)==1){
        printf("%s C/R = 1 : respuesta %s \n",PURPURA_CLARO,END);
    }
    else{
        printf("%s C/R = 0 : comando %s \n ",PURPURA_CLARO,END);
    }
    	
    


    switch(trama[14] & 0xFE){

        case 0x00:printf("%s \t     Protocolo: NULL LSAP %s",PURPURA_CLARO,END);break;
        case 0x02:printf("%s \t     Protocolo: individual LLC Sublayer Management Function\n %s",PURPURA_CLARO,END);break;
        case 0x03:printf("%s \t     Protocolo: Group LLC Sublayer Management Functionn\n %s",PURPURA_CLARO,END);break;
        case 0x04:printf("%s \t     Protocolo: IBM SNA Path Control (individual)\n %s",PURPURA_CLARO,END);break;
        case 0x05:printf("%s \t     Protocolo: IBM SNA Path Control (group)\n %s",PURPURA_CLARO,END);break;
        case 0x06:printf("%s \t     Protocolo: ARPANET Internet Protocol (IP)\n %s",PURPURA_CLARO,END);break;
        case 0x08:printf("%s \t     Protocolo: SNA\n %s",PURPURA_CLARO,END);break;
        case 0x0C:printf("%s \t     Protocolo: SNA\n %s",PURPURA_CLARO,END);break;
        case 0x0E:printf("%s \t     Protocolo: PROWAY (IEC955) Network Management & Initialization\n %s",PURPURA_CLARO,END);break;
        case 0x18:printf("%s \t     Protocolo: Texas Instruments\n %s",PURPURA_CLARO,END);break;
        case 0x42:printf("%s \t     Protocolo: IEEE 802.1 Bridge Spanning Tree Protocol\n %s",PURPURA_CLARO,END);break;
        case 0x4E:printf("%s \t     Protocolo: EIA RS-511 Manufacturing Message Service\n %s",PURPURA_CLARO,END);break;
        case 0x7E:printf("%s \t     Protocolo: SO 8208 (X.25 over IEEE 802.2 Type 2 LLC)\n %s",PURPURA_CLARO,END);break;
        case 0x80:printf("%s \t     Protocolo: Xerox Network Systems (XNS)\n %s",PURPURA_CLARO,END);break;
        case 0x86:printf("%s \t     Protocolo: Nestar\n %s",PURPURA_CLARO,END);break;
        case 0x8E:printf("%s \t     Protocolo: PROWAY (IEC 955) Active Station List Maintenance\n %s",PURPURA_CLARO,END);break;
        case 0x98:printf("%s \t     Protocolo: ARPANET Address Resolution Protocol (ARP)\n %s",PURPURA_CLARO,END);break;
        case 0xBC:printf("%s \t     Protocolo: Banyan VINES\n %s",PURPURA_CLARO,END);break;
        case 0xAA:printf("%s \t     Protocolo: SubNetwork Access Protocol (SNAP)\n %s",PURPURA_CLARO,END);break;
        case 0xE0:printf("%s \t     Protocolo: Novell NetWare\n %s",PURPURA_CLARO,END);break;
        case 0xF0:printf("%s \t     Protocolo: IBM NetBIOS\n %s",PURPURA_CLARO,END);break;
        case 0xF4:printf("%s \t     Protocolo: IBM LAN Management (individual)\n %s",PURPURA_CLARO,END);break;
        case 0xF5:printf("%s \t     Protocolo: IBM LAN Management (group)\n %s",PURPURA_CLARO,END);break;
        case 0xF8:printf("%s \t     Protocolo: IBM Remote Program Load (RPL)\n %s",PURPURA_CLARO,END);break;
        case 0xFA:printf("%s \t     Protocolo: Ungermann-Bass\n %s",PURPURA_CLARO,END);break;
        case 0xFE:printf("%s \t     Protocolo: ISO Network Layer Protocol\n %s",PURPURA_CLARO,END);break;
        case 0xFF:printf("%s \t     Protocolo: Global LSAP\n %s",PURPURA_CLARO,END);break;
        default:printf("Oye we , no mams , ve a tirar esa madre\n");break;

    }

}



int tipoTrama(unsigned char *trama){

    switch(trama[16] & 0x03){

        case 0:printf("%s Trama de informacion %s \n",PURPURA_CLARO,END);return 0;break;
        case 1:printf("%s Trama de supervisión %s \n",PURPURA_CLARO,END);return 1;break;
        case 2:printf("%s Trama de información %s\n",PURPURA_CLARO,END);return 2;break;
        case 3:printf("%s Trama no numerada %s \n",PURPURA_CLARO,END);return 3;break;
    }

}

void Caso_1byte(unsigned char *trama){
        if((trama[16]&0xFF)==16){ //0x10 = 00010000
            printf("\tRequiere un respuesta inmediata\n");
        }
        else{
            printf("%s Tipo de trama no numerada: %s ",PURPURA_CLARO,END);
        }
            switch((trama[16]&0xFF)){ //0xEC = 236 = 11101100 
                case 0x93:printf("%s  Set normal response SNRM %s \n",VERDE,END); //10010011
                    break;
                case 0x6F:printf("%s  Set normal response extended mode SNRME  %s",VERDE,END); //1101111
                    break;
                case 0x01F:printf("%s Set asincronous response SARM %s",VERDE,END); //00011111
                    break;
                case 0x5F:printf("%s Set asincronous response extended mode SARME %s",VERDE,END);//01011111
                    break;
                case 0x3F:printf("%s Set asincronous balance mode SABM %s",VERDE,END);//00111111
                    break;
                case 0x7F:printf("%s Set asincronous balance extended mode SABME %s",VERDE,END);//01111111
                    break;
                case 0x17:printf("%s Set inicialitation mode SIM %s",VERDE,END);//00010111
                    break;
                case 0x53:printf("%s Disconect DIST %s",VERDE,END); //01010011
                    break;
                case 0x33:printf("%s Unnumbered poll up %s",VERDE,END); //00110011
                    break;
                case 0x9F:printf("%s Reset %s",VERDE,END); //10011111
                    break;
                case 0x13:printf("%s Unnumered informacion ui %s ",VERDE,END); //00010011
                    break;
                case 0xBF:printf("%s Exchange identification xid %s",VERDE,END); //10111111
                    break;
                case 0xF3:printf("%s Test %s",VERDE,END); // 11110011
                    break;
                case 0x73:printf("%s Unnumbered Acknowledgment UA %s",VERDE,END); //01110011
                    break;
                case 0x0F:printf("%s Disconect mode DM %s",VERDE,END); //00001111
                    break;
                case 0x43:printf("%s Request disconect RD %s",VERDE,END); //01000011
                    break;
                case 0x07:printf("%s Request initialitacion mode RIM %s",VERDE,END); //00000111
                    break;
                case 0x03:printf("%s Unnumered informacion ui %s",VERDE,END); //00000011
                    break;
                case 0xAF:printf("%s Exchange identification xid %s",VERDE,END); //10101111
                    break;
                case 0xE3:printf("%s Test %s",VERDE,END); //11100011
                    break;
                default: printf("%s No aparace en la tabla %s",VERDE,END);
                    break;
            }
        
        if(trama[16]&0x04 == 1) 
            printf("\n %s POLL/FINAL: F %s",VERDE,END);
        else 
            printf("\n %s POLL/FINAL: P %s",VERDE,END);

}


void Caso_2bytes(unsigned char *trama ,int opc){//opc 0 informacion 1 supervicion
    int p;
    if(opc)
    {
        switch((trama[16]&0x0C)){
            case 0:printf("%s Receiver ready (rr) %s",VERDE,END);
                break;
            case 4:printf("%s Receiver not ready (rnr) %s",VERDE,END);
                break;
            case 8:printf("%s Retransmicion (rej) %s",VERDE,END);
                break;
            case 12:printf("%s Retransmicion selectiva (srej) %s",VERDE,END);
                break;
        }
        printf("%s Número de secuencia que se espera recibir: %d %s \n",VERDE,((trama[17]&0xFE)>>1),END);
    }
    else{                                               //byte1
        printf("%s Número de secuencia de envio: %d %s \n",VERDE,((trama[16]&0xFE)>>1),END); //0xFE=254=11111110
        printf("%s Número de secuencia que se espera recibir: %d %s \n",VERDE,((trama[17]&0xFE)>>1),END);//(byte2)/2)
        printf("\n");
    }   //byte 2
    p=(trama[17]&0x01);
    if ( p == 0)
        printf("%s POLL/FINAL: 0 %s \n",VERDE,END); 
    else{      //SSAP
        if ( (trama[15]&0x01) == 1 )
            printf("%s POLL/FINAL: F %s \n",VERDE , END);
        else
            printf("%s POLL/FINAL: P %s \n",VERDE,END);
            
    }

}


void analizarTrama(unsigned char *trama){

    int tipo = 0;

    longitud(trama);
    printf("%s ----------------> Encabezado mac: <---------------- %s \n",PURPURA_CLARO,END);
    aberTumacBB(trama);
    DSAP_SSAP(trama);
    printf("\n");
    printf("%s -----------------------> Control: <---------------- %s \n",PURPURA_CLARO,END);
    tipo = tipoTrama(trama);


    if(tipo == 0 ||  tipo == 2){
        Caso_2bytes(trama,0);
        printf("\n");
    }

    if(tipo == 1){
        Caso_2bytes(trama,1);
        printf("\n");
    }

        if(tipo == 3){

        Caso_1byte(trama);
        printf("\n");
    }




}


