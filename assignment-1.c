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
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char * base64_encode(const char *src, int len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; 
	olen += olen / 72; 
	olen++; 
	if (olen < len)
		return NULL; 
	out = malloc(olen);

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	return out;
}
char *b64encode(char *username, char*userpass){
    char plainstring[100];
    strcpy(plainstring,username);
    strcat(plainstring,":");
    strcat(plainstring,userpass);
    return base64_encode(plainstring,strlen(plainstring));

}
int main(int argc, char **argv)
{
    int sockfd = 0, n = 0;
    char recvBuff[1024];
    struct sockaddr_in serv_addr;

    if (argc != 6)
    {
        printf("\n Usage: %s <ip of server> <port> <username> <password> <url>\n", argv[0]);
        return 1;
    }
    memset(recvBuff, '0', sizeof(recvBuff));
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("socket error\n");
        return 2;
    }
    memset(&serv_addr, '0', sizeof(struct sockaddr_in));

    serv_addr.sin_family = AF_INET;
    //inet_aton(argv[1], &serv_addr.sin_addr);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
    {
        printf("\n inet_pton error occured \n");
        return 3;
    }
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\n Error: Connect Failed\n");
        return 4;
    }

    char connectionString[1000];
    //strcat(connectionString, argv[5]);

    char HTTPHEADER[100] = " HTTP/1.1\r\nHost: ";
    
    char host[80]; //strcpy(host,argv[5]);
    //strcat(HTTPHEADER,host);

    //char tailProxyAuth[100] = "\r\nProxy-Authorization: basic ";
    char base64encoded[100] =  "Y3NmMzAzOmNzZjMwMw=="; //add b64 code later
    
    //strcat(connectionString,HTTPHEADER);
    //strcat(connectionString,tailProxyAuth);
    //strcat(connectionString,base64encoded);
    //strcat(connectionString,"\r\nProxy-Connection: Keep-Alive\r\n\r\n");
    
    
    sprintf(connectionString,
    "CONNECT %s HTTP/1.1\r\n"
    "Host: %s:443\r\n"
    "Proxy-Authorization: basic %s\r\n\r\n",
    argv[5],argv[5],base64encoded);

    puts(connectionString);
    if(send(sockfd, connectionString, strlen(connectionString), 0) == -1){
        perror("Error in connection: ");
        return 5;
    }
    if((n = read(sockfd, recvBuff, sizeof(recvBuff) - 1)) > 0)
    {
        recvBuff[n] = 0;
        if (fputs(recvBuff, stdout) == EOF)
        {
            printf("\n Error: Fputs error\n");
            return 6;
        }
    }
    char response200[100] = "HTTP/1.1 200 Connection established";
    if(strncmp(recvBuff,response200,strlen(response200)) != 0){
        perror("Sed response: ");
        return 7;
    }
    if (n < 0)
    {
        printf("\n Read Error \n");
        return 8;
    }
    char getString[100];
    sprintf(getString, 
    "GET http://bits-pilani.ac.in/ HTTP/1.1\r\n"
    "Host: bits-pilani.ac.in\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-alive\r\n\r\n",
    base64encoded
    );
    puts(getString);
    if(send(sockfd, getString,strlen(getString), 0) == -1){
        perror("Error sending get request: ");
    }
    if((n = read(sockfd, recvBuff, sizeof(recvBuff) - 1)) > 0)
    {
        recvBuff[n] = 0;
        if (fputs(recvBuff, stdout) == EOF)
        {
            printf("\n Error: Fputs error\n");
            return 6;
        }
    }
    return 0;
}