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
int connectHTTP(int sockfd, char* url, char* recvBuff, char *b64){
    char connectionString[1000];
    char HTTPHEADER[100] = " HTTP/1.1\r\nHost: ";
    char host[80]; //strcpy(host,url);
    int n;

    sprintf(connectionString,
    "CONNECT %s:443 HTTP/1.1\r\n"
    "Host: %s:443\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-Alive\r\n\r\n",
    url,url,b64);

    puts(connectionString);
    
    if(send(sockfd, connectionString, strlen(connectionString), 0) == -1){
        perror("Error in connection: ");
        return 5;
    }
    while((n = recv(sockfd, recvBuff, 1024 - 1, 0)) > 0)
    {
        recvBuff[n] = 0;
        if (fputs(recvBuff, stdout) == EOF)
        {
            printf("\n Error: Fputs error\n");
            return 6;
        }
        if(strstr(recvBuff,"\r\n\r\n") != NULL)break;
    }

    char response200[100] = "HTTP/1.1 200 Connection established";
    if(strstr(recvBuff,response200) == NULL){
        perror("Sed response: ");
       // return 7;
    }
    if (n < 0)
    {
        printf("\n Read Error \n");
        return 8;
    }
    return 0;
}
void SSLinit(){
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}
int secureGETHTTPS(SSL_CTX* ctx, SSL* ssl, BIO* bio,char* hostname, char*b64)
{
    BIO_get_ssl(bio, &ssl); /* session */
    if(!ssl){
        perror("Error");
        return 1;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); /* robustness */
    char connectName[100];
    sprintf(connectName,"%s:443",hostname);
    puts(connectName);
    //BIO_set_conn_hostname(bio, connectName); /* prepare to connect */
    if (BIO_do_connect(bio) <= 0) {
        perror("Error in connect: ");
        return 2;
    }
      /* verify truststore, check cert */
    if (!SSL_CTX_load_verify_locations(ctx,
                                      "/etc/ssl/certs/ca-certificates.crt", 
                                      "/etc/ssl/certs/")) 
    perror("SSL_CTX_load_verify_locations error: ");

    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK)
    fprintf(stderr,
            "##### Certificate verification error (%i) but continuing...\n",
            (int) verify_flag);

  /* now fetch the homepage as sample data */
    char getString[100];
    sprintf(getString, 
    "GET / HTTP/1.1\r\n"
    "Host: http://%s/\r\n"
    "Proxy-Authorization: basic %s\r\n"
    "Proxy-Connection: Keep-alive\r\n\r\n",
    hostname,b64
    );
    puts(getString);
    BIO_puts(bio, getString);

  /* read HTTP response from server and print to stdout */
    char response[100000];
    memset(response, '\0', sizeof(response));
    size_t buffSize = 100;
    int n = 0;
    while (n = BIO_read(bio, response, buffSize) >= 0) 
    {
        puts(response);
        if(strstr(response,"</html>") != NULL)break;
    }
}
int main(int argc, char **argv)
{
    int sockfd = 0, n = 0;
    char recvBuff[1024];
    struct sockaddr_in serv_addr;
    char base64encoded[100] =  "Y3NmMzAzOmNzZjMwMw=="; //add b64 code laters
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
    /*
    if(connectHTTP(sockfd,argv[5],recvBuff,base64encoded))
    {
        printf("ConnectHTTP error");
        return 5;
    }
    */
    /* set up openSSL*/

    SSLinit();
    
    SSL *ssl;
    char hostname[100];
    sprintf(hostname,"%s",argv[5]);
    
    SSL_CTX  *ctx = SSL_CTX_new(TLSv1_2_client_method());
    if(!ctx){
        printf("Error in ctx");
        return 6;
    }
    
    BIO* bio = BIO_new_ssl_connect(ctx);
    if(!bio){
        printf("Error in bio");
        return 6;
    }
    
    BIO_get_ssl(bio, &ssl); 
    if(!ssl){
        perror("Error");
        return 1;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); 
    
    if (BIO_do_connect(bio) <= 0) {
        perror("Error in connect: ");
        return 2;
    }

    secureGETHTTPS(ctx,ssl,bio, hostname, base64encoded);

    return 0;
}