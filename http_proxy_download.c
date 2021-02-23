/* 2018A7PS0172H Abhinav_Sukumar_Rao */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>


struct sockaddr_in serv_addr;
int sockfd = 0;

const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char * base64_encode(const char *src, char *dest, int len, int *olen)
{
    int j = 0;
    *olen = len;
    if(len %3){
        *olen += 3 - (len%3);
    }
    *olen = 4*((*olen)/3);

    for(int i = 0; i < len; i+=3){
        int enc = src[i]; //first 8 bytes
        if(i+1 < len){
        enc = ((enc << 8) | (src[i+1]));
        }else{enc = (enc << 8);}
        if(i+2 < len){
        enc = ((enc << 8) | (src[i+2]));
        }else{enc = (enc << 8);}
        dest[j] = base64_table[((enc >> (24-6)) & 0x3f)];
        dest[j+1] = base64_table[((enc >> (24-12)) & 0x3f)];
        dest[j+2] = (i+1 < len)? base64_table[((enc >> (24-18)) & 0x3f)]: '=';
        dest[j+3] = (i+2 < len)? base64_table[((enc & 0x3f))] : '=';
        j+=4;
    }
    dest[j]= '\0';
    return dest;
}

char *b64encode(char *username, char*userpass, char *dest, int *olen){
    char plainstring[100];
    strcpy(plainstring,username);
    strcat(plainstring,":");
    strcat(plainstring,userpass);
    return base64_encode(plainstring,dest,strlen(plainstring),olen);

}


int sock_init(int *sockfd, char **argv){
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("socket error\n");
        return 2;
    }
    memset(&serv_addr, '0', sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[3]));
    if (inet_pton(AF_INET, argv[2], &serv_addr.sin_addr) <= 0)
    {
        printf("\n inet_pton error occured \n");
        return 3;
    }
    if (connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\n Error: Connect Failed\n");
        return 4;
    }
    return 0;
}



int connectHTTP(char **argv, int* sockfd, char* url, char* recvBuff, char *b64, int imageFlag ){
    char connectionString[1000];
    int n;

    sprintf(connectionString,
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Connection: Close\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-Alive\r\n\r\n",
    url,url,b64);

    sock_init(sockfd, argv);
    if(send(*sockfd, connectionString, strlen(connectionString), 0) == -1){
        perror("Error in connection: ");
        return 5;
    }
    int flag = 0;
    char *Headerp = NULL;
    flag = 0;

    FILE *fp = fopen(argv[6],"w+");
    char resp[20000], *rp = resp;
    while((n = recv(*sockfd, recvBuff, 20000, 0)) > 0)
    {
        //fwrite(recvBuff, n,1,stdout);
        recvBuff[n] = '\0';
        if (flag >= 1) 
        {
            //
            fwrite(recvBuff,n,1,fp);
            fflush(fp);
            if(flag == 2){
            memcpy(rp, recvBuff, n);
            rp+=n;
            flag = 3;
            }
        }
        else if(strstr(recvBuff,"close\r\n") != NULL){
            Headerp = strstr(recvBuff,"close\r\n")+9;
            fwrite(Headerp,n - (Headerp - recvBuff),1,fp);
            fflush(fp);
            flag = 1;
        }
        if(imageFlag == 1 && strstr(recvBuff,"<IMG") != NULL)
        {
            Headerp = strstr(recvBuff,"<IMG");
            memcpy(rp, Headerp, n-(Headerp-recvBuff));
            rp+=n-(Headerp-recvBuff);
            flag = 2;
        }
    }
        fclose(fp);
    if(imageFlag){
    char URL[200] = {'/'},*urlp = URL+1;
    if(strstr(resp,"SRC") != NULL){
        Headerp = strstr(resp,"SRC");//retrieve image
        Headerp+=5; //start from quote
        while(*Headerp != '\"'){
            *urlp = *Headerp;
            Headerp++; urlp++;
        }
        urlp = '\0';
    }
    //puts(URL);
    flag = 0;


    sock_init(sockfd, argv);
    //GET
    sprintf(connectionString,
    "GET %s%s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Connection: Close\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-Alive\r\n\r\n",
    url,URL,url,b64);
    if(send(*sockfd, connectionString, strlen(connectionString), 0) == -1){
        perror("Error in connection: ");
        return 5;
    }

    fp = fopen(argv[7],"w+");
    rp = recvBuff;
    memset(recvBuff,'\0',20000);
    while((n = recv(*sockfd, recvBuff, 20000, 0)) > 0)
    {
        if(flag == 1){
                    fwrite(recvBuff,n,1,fp);
        }
        else if(strstr(recvBuff,"GIF") != NULL)
        {
            Headerp = strstr(recvBuff,"GIF");
            fwrite(Headerp, (n-(Headerp-recvBuff)),1,fp);
            flag = 1;
        }

    }
    fclose(fp);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int n = 0;
    char recvBuff[20001];
    
    char base64encoded[100]; //add b64 code laters
    if (argc != 8)
    {
        printf("\n Usage: %s <url> <ip of server> <port> <username> <password> <response> <image>\n", argv[0]);
        return 1;
    }
    int olen,imageFlag;
    imageFlag = (strstr(argv[1],"info.in2p3.fr") != NULL);
    b64encode(argv[4],argv[5], base64encoded, &olen);

    memset(recvBuff, '0', sizeof(recvBuff));
    sock_init(&sockfd, argv);
    

    char connectionString[1000];
    char host[1000]; //strcpy(host,url)

    sprintf(connectionString,
    "HEAD %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Connection: Close\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-Alive\r\n\r\n",
    argv[1],argv[1],base64encoded);
    if(send(sockfd, connectionString, strlen(connectionString), 0) == -1){
        perror("Error in connection: ");
        return 5;
    }
    int urllen = 0;
    char*p;
    while((n = recv(sockfd, recvBuff, 20000, 0)) > 0)
    {
        //fwrite(recvBuff,n,1,stdout);
        p = strstr(recvBuff,"HTTP");
        if(p != NULL){  
            while(*p !=' ')p++;
            if(*(++p) == '3'){
                p = strstr(recvBuff,"http");
                char*q = strstr(p, "\r\n");
                urllen = q-p;
            }
            else{
                p = NULL;
            }
        }
    }
    if(p != NULL){
    strncpy(host,p,urllen);
    host[urllen] = '\0';
    }
    else{
        strcpy(host,argv[1]);
    }
    if(connectHTTP(argv,&sockfd,host,recvBuff,base64encoded,imageFlag))
    {
        printf("ConnectHTTP error");
        return 5;
    }
    
    /* set up openSSL*/
    return 0;
}