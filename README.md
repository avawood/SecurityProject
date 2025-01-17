# 🔐🙅‍♀️Security Final Project 🙅‍♂️🔐
## Acknowledgements
- basic http client / server skeleton taken from https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/, as recommended on the assignment page

## Dependecy list
- Make sure to run the base installation script for necessary dependencies
```
sudo ./base_install
```

## 1) Setting Up the Server
- To set up the server filesystem, go into the ```server/scripts``` directory. There, run ```create-filesystem```, which will create a filesystem directory at ```server/filesystem```. This directory contains one folder per user, and will also create a file in the coresponding directory containing the user's ```hashed_password```, as well as a ```pending``` directory to store pending messages. This script will also generate a mailbox corresponding to this current `$USER`. 
Permissions will be set during docker setup.

- To set up the root CA, intermediate CA, certificate revocation list, and web server certificate that will be used by the server, go into the ```server/scripts``` directory. There, run ```ca-setup```, which will create a CA directory at ```server/CA```. This directory will store private keys for the root and intermediate CAs, as well as the certificate for the web server.

🏃🏽‍♀️💨:
```
cd server/scripts
./create-filesystem
./ca_setup
```

## 2) Setting Up the Client
- To set up the client, go into the ```client/scripts``` directory. There, run ```make_client <name>```, which will create the directory ```<username>``` within ```SecurityProject```. Inside of this newly generated folder, there will be the directories ```keys```, ```certs```, `src`, and ```csr```. The keys directory will store the client's private key, which will automatically be generated and placed there. The certs directory will store the client's cert, as well as the ca-chain cert that it will use to verify the server's cert. The ```csr``` directory will hold any csr's that have been generated in order to be sent to the server. The `src` directory contains code for compiling and running the https client. The ```ca-chain.cert.pem``` from the server will automatically be copied into the ```certs ``` directory.
Permissions will be set during docker setup.

🏃🏽‍♀️💨:
```
cd client/scripts
./make_client starshine
```

## System Components
These four scripts comprise the main functions of this project. Run from within a user's directory, which was generated by ```make_client <name>```
### getcert
The user logs in with a username and password, sends a certificate request, and receives a certificate. The user will supply a **-u** username and a **-p** password. A csr will be generated to be sent to the server. The returned certificate will be saved in `certs/<username>.cert.pem`

🏃🏽‍♀️💨: `./getcert -u starshine -p secretPassword`

### changepw
The user logs in with a username and a password, sends a new password that will be updated in the server's database, and receives a new certificate. The user will supply a **-u** username, **-o** old password, and a **-n** new password. A csr will be generated to be sent to the server. The returned certificate will be saved in `certs/<username>.cert.pem`

🏃🏽‍♀️💨:`./changepw -u starshine -o secretPassword -n betterPassword`

### sendmsg
A user logs in with a client-side certificate, sends a list of recipient names, receives their certificates, encrypts the message to those certificates, digitally signs it, and uploads it. The user will supply a **-u** username, **-m**** message and **-c** certificate filename, which should be stored in the `certs/` directory. Use the -r flag for each recipient.
For example, if the certificate is at `certs/mycert.cert.pem`, 

🏃🏽‍♀️💨:`./sendmsg -u starshine -m "Hello World!" -c mycert.cert.pem -r Ava -r Mark -r Monica -r Yasemin`

### recvmsg
A user logs in with a client-side certificate and receives a single encrypted message which is then deleted from the server. The recipient uses the sender's certificate to verify the signature on the message, decrypt the message, and finally display the message. The user will supply a **-u** username and a **-c** certificate filename, which should be stored in the `certs/` directory.
For example, if the certificate is at `certs/mycert.cert.pem`,

🏃🏽‍♀️💨:`./recvmsg -u starshine -c mycert.cert.pem`

## Helper Scripts
### Server
- ```make_client_cert```: Given a csr (must be .csr.pem), will generate a TLS+encryption+signing certificate and verify it. If a certificate already exists for this user, it will be revoked and then recreated. The certificate will be saved to ```intermediate/certs/<username>.cert.pem```, as well as ```filesystem/<username>/certificate.cert.pem``` for easy access.

🏃🏽‍♀️💨: ```./make_client_cert starshine ../testing/starshine.csr.pem```.  We assume that this is being run from within the server dir.


### Client
- ```make_csr```: Given a username and the path to a private key file (must be .csr.pem), will generate a csr. This is just a helper script - ```getcert``` and ```changepw``` will need to use this to generate the csr that they will send to the server. (See https://piazza.com/class/keud2qcwhr14d?cid=543)
The output will be stored in ```client/csr/mycsr.csr.pem```

🏃🏽‍♀️💨: ```./make_csr starshine ../keys/mykey.key.pem```

## Permissions
- ```server/make-mailbox-users```: Will create users "addleness" "analects" "annalistic"... Will also create a group `mailergroup`.
- ```client/scripts/make_client_permissions```: Given a username as the first positional argument, will change the ownership of the corresponding client directory to that user. Will set the permissions on that folder to `u=,g=,o=rwx`. Needs to be invoked as root
- ```server/scripts/create-filesystem-perms```: Will change the group ownership of the `filesystem` directory to `mailergroup`. Sets permissions such that only `mailergroup` has read, write access to `filesystem`. Will change the group of the `https_server` executable to `mailergroup`. Will setgid for `https_server`. Needs to be invoked as root.

## Testing: Basic Functionality
    cd test_cases
    ./run_tests

All results should be in very_secure_results.txt!

## Docker 🐳
**Be sure to download Docker!**

Docker commands might have to be used with sudo

### To build a containerized server 🐳:
    docker pull ubuntu                          # Pull the latest ubuntu image
    cd server_docker
    ./build-server                              # Creates the server_jail folder
    docker build -t server:latest .             # Creates the docker images for the server
    cd ..

    ## Run the server image in a container on port 8080 ##
    docker run -d -p 8080:8080 --name server server:latest

The server should be up and running!

### To build a containerized client 🐳:
    ./build-client <username>                   # Creates client folder
    docker build -t <username>:latest .         # Build docker image
                                                # Be sure to replace <username>
    
    ##              Run the client in its own container on docker               ##
    docker run -d -it --name <username> --network=host <username>:latest /bin/bash

### To run as containerized client:
    docker exec -it <username> /bin/sh

### To remove containers:
    docker stop <username>                      # Clean up client containers
    docker rm <username>                        # Make sure to do these for
    docker rmi <username>                       # all clients created

    docker stop server                          # Clean up server container
    docker rm server
    docker rmi server

    docker rmi ubuntu                           # Clean up ubuntu image

### To clean up extra files:
    ./clean-client <username>
    cd server_docker
    ./clean-server
    cd ..