# Simple Beacon Server & Client
## Overview
This is an implementation of a Linux server and client remote access tool written in C. It uses OpenSSL to encrypt all communication between the client and the server. The server beacons out at set intervals unless in an established session with the client. It offers a variety of ways to interact with the box. While the RAT is fully functioning in its current state (per its original design goals) there are many planned improvements to enable users to have a richer experience as well as a greater confidence in the RATs reliability/robustness.

## Prepare Environment
Create a python virtual environment and install meson.
```bash
virtualenv -p python3 venv
source venv/bin/activate
pip install meson pytest 
```
## Build
### Server Build
The build process is the same for both the server and client. 
```bash
cd server

# Using the host default compiler
meson builddir
cd builddir
ninja
```
### Client Build
```bash
cd client

# Using the host default compiler
meson builddir
cd builddir
ninja
```
## Usage
### Server Usage
The server is meant to be deployed to a remote box as a root daemon process. By default it will beacon out every 5 seconds. Once you catch an intial beacon you can change the beacon window from the client by invoking the `win` command. The server will continue to call out to the specified port and address at the designated interval unless already in a session. When a sesion with the client is exited the server "should" revert to beaconing behavior, however if the client forcibly shuts down the connection, issues can arise. The `bye` command is the most appropriate way of ending a session with the server. 
```bash
IMAP_SERVER=127.0.0.1 IMAP_PORT=993 PATH=$PATH:. sbs
```
#### Invocation Variables Explanation:
1. The IMAP_SERVER environment variable is the address to beacon out to.
2. The IMAP_PORT environment variable is the port to beacon out to.
3. It is important that we update the path so that we may run the RAT without having to use the `./sbs` syntax. This avoids odd looking process names that can truly stick out. The PATH variable must also include the previous path in order to have a functioning shell via the `cmd` command within the RAT. If you decide to rename the binary before uploading/running it would be important to scrub the code base for any references to 'sbs' as this name is utilized by the `new` command within the RAT.  

#### Hard-Coded Variables Explanation:
1. The name of the binary is important. If you want to change it you must change the `newconn` portion of the code as it calls for binary by name. 
2. The server must currently remain on disk if you would like to be able to spawn new sessions. You could always delete the binary from disk and only put it down when you are going to need multiple sessions. 
3. In order to change the authentication string utilized you must change the value listed in the header file for the server.

### Client Usage
The client is meant to be run locally on your box as root and will setup a listener and catch the server beacons. Once in a session it will use the supplied authentication string to allow you to enter a session with the server. The command interface will be presented below. 
```bash
./sbc -a "ASimplePasswordForASimpleTool" -p 993
[+] Client has started listening on 0.0.0.0:993.
[*] Awaiting connections from server.
```
#### Invocation Variables Explanation:
1. -a: Specifies the authentication string to utilize when connecting to the server.
2. -p: Specifies which port to listen on for beacons.
   
#### Hard-Coded Variable Explanation:
1. The OpenSSL Certificates must be in the proper location for the binary to run. Check the location in the `client.h` file.

#### Command Loop Interface
```bash
./sbc -a "ASimplePasswordForASimpleTool" -p 993
[+] Client has started listening on 0.0.0.0:993.
[*] Awaiting connections from server.
[+] Established connection with server at 127.0.0.1:54704.
[+] Connected with TLS_AES_256_GCM_SHA384 encryption
[+] Server is ready for authentication.
[*] Authenticating with: ASimplePasswordForASimpleTool
[*] Authentication message sent.
[+] Successfully authenticated! Entering session.
=====================================
   Simple Beacon Client Help Menu
=====================================
sbc> new -- Spawn a new beacon.
sbc> cmd -- Enter a shell.
sbc> get -- Get a file.
sbc> put -- Put up a file.
sbc> tun -- Start a tunnel.
sbc> win -- Change the beacon time.
sbc> bye -- Exit the client.
=====================================
sbc> 
```
Each command will prompt the user for input. Ctrl-C **is not** the prefered method for exiting the client as it will revert the server back to the set beacon time. You will have to wait for the next beacon to come back before you can begin another session. The `new` command will kick off a child daemon with the specified environment variables. It will die when the client dies if the client uses the `bye` command. If not the child process may live depending on the state of the original client. It is best to have multiple sessions on the box with the original client used as a last resort and all other sessions used to run commands. If a child process hangs it is fine to Ctrl-C out of the process but ensure you `kill -9` the process that spawned on the server via another shell. 

## Design Discussion
The design of this RAT is far from complete. The current design goal was to have a minimally functional RAT that was able to beacon out, spawn additional instances of itself, give the user basic command line access, upload and download basic files, start TCP tunnels, and change the amount of time in between each of its beacons. The messages that are sent to the server are typeically coded by the enum number associated with each command found in the `server.h` file. I use these messages to synchronize and alert the server and client about several things:
1. These messages indicate which function the client/server are trying to carry out.  
2. They indicate whether or not the client/server experienced an error while processing a request/response.
3. They ensure the expected transfer size of data being passed over the wire and ensure the remote buffers are prepared to read/write the appropriate amount of data.

## Limitations
It is probably apparent that the current implementation is a fairly limited RAT. This project for me has been an opportunity to get more familiar with the C programming language and specifically socket programming in C. That being said there are some key limitations that I have identified which I plan on remedying at some point in the near future.
- The shell interface only passes commands to popen. This limitation means that no interactive commands can be run successfully through this inteface. Any command expecting user input will hang the terminal and the user will have no choice but to Ctrl-C. I have a plan to improve this interface via calls to `openpty()` and `epoll()` the file descriptors (see below).
- Both the get/put file commands only work for regular text files. The work around for a user is to base64 encode a file first and then pass the encoded data over the wire. The user can then decode the file manually once it has reached its destination. While this will work it can very clearly be implemented in the codes logic. This fix action is listed below as well. 
- The server is only able to send beacons. In the future a slight redesign of the control flow logic will make it possible to have the server listen for connections rather than beacon. At the current moment this is outside the scope of my planned improvements.
- The tunnels spawned are only able to handle tcp connections. I do not plan on implementing UDP nor Raw tunnels at the current moment, however this addition would be very useful down the road. If a user were to absolutely need UDP they may be able to point their tcp tunnel to either the server or the client itself depending on the direction of the tunnel and use socat on either end of the tunnel to convert the UDP traffic to a TCP stream between the client and server and then back to UDP on the other side.

## Planned Improvements
- Better error handling and unexpected input handling. Currently input errors are very crudely handled. Some can be gracefully recovered from, however others cause more or may even require that you reconnect to the server. While this is something you could work around operationally. It is not the desired tool functionality. The tool should work for the user not the other way around. 
- Improve the messaging mechanisms. Right now there are various sized buffers that should be changed to a single size that is shared in a header file. Furthermore it would be a better idea to build out a `struct` for a message and codify the error codes and their respective messages in one location. This should improve readability and help to increase the maintainability of this code. 
- Move shared functions to their own library. The `readall`, `writeall`, `ssl_writeall`, and `ssl_readall` commands are virtually identical. It would be better to have these commands in one location so that updates to the code base are uniform across both the server and the client. The errors can be handled by the calling functions rather than within the code. 
- Improve the shell interface to use a pty. Calls to `openpty` and then `epoll` to alert on the file descriptors when ready should work. 
- Include logic that converts a file to chunks, converts those chunks to base64 encoded values, passes them over and then decodes them on the appropriate side. This will allow us to transfer binary files with ease. 
- Update the logic to allow the name of the binary to be adjusted on disk without having to worry about `newconn` working. A solution may be to use the current pid to get the running name of the binary and use that value to kick off new sessions. 
- Update the logic to allow for the client certs to be looked for rather than have a strict location they must be located.
- Ensure that if a clinet Ctrl-C's out of a client the server will not indefinitely hang. This behavior is mostly correct now, however some intermittent issues have been identified. 
- Add a parsing function to allow users to pass commands with their parameters on one line (ex. `tun forward 55555 192.168.1.200 22`). Currently for each command there is a menu interface that asks for each parameter individually. In the future I would like to be able to run the command in one line and parse out the variables rather than asking individually.


