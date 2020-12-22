# 🔐🙅‍♀️Security Final Project 🙅‍♂️🔐
## Acknowledgements
- cryptographic helper functions courtesy of Brad Conte are stored in ```crypto```
- basic http client / server skeleton taken from https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/, as recommended on the assignment page

## 1) Setting Up the Server
- To set up the server filesystem, go into the ```server/scripts``` directory. There, run ```create-filesystem```, which will create a filesystem directory at ```server/filesystem```. This directory contains one folder per user, and will also create a file in the coresponding directory containing the user's ```hashed_password```, as well as a ```pending``` directory to store pending messages.

- To set up the root CA, intermediate CA, certificate revocation list, and web server certificate that will be used by the server, go into the ```server/scripts``` directory. There, run ```ca-setup```, which will create a CA directory at ```server/CA```. This directory will store private keys for the root and intermediate CAs, as well as the certificate for the web server.

🏃🏽‍♀️💨:
```
cd server/scripts
./create-filesystem
./ca_setup
```

## 2) Setting Up the Client
- To set up the client, go into the ```client/scripts``` directory. There, run ```make_client <name>```, which will create the directory ```<name``` within ```SecurityProject```. Inside of this newly generated folder, there will be the directories ```keys```, ```certs```, `src`, and ```csr```. The keys directory will store the client's private key, which will automatically be generated and placed there. The certs directory will store the client's cert, as well as the ca-chain cert that it will use to verify the server's cert. The ```csr``` directory will hold any csr's that have been generated in order to be sent to the server. The `src` directory contains code for compiling and running the https client. The ```ca-chain.cert.pem``` from the server will automatically be copied into the ```certs ``` directory.

🏃🏽‍♀️💨:
```
cd client/scripts
./make_client starshine
```

## System Components
### starting the server
Start the server by going to the ```server``` directory and running ``https_server <server_cert_filepath> <server_private_key_filepath> <server_cert_chain_filepath>``

🏃🏽‍♀️💨: `./https_server CA/intermediate/certs/www.finalproject.com.cert.pem CA/intermediate/private/www.finalproject.com.key.pem CA/intermediate/certs/ca-chain.cert.pem`

The following four scripts comprise the main functions of this project. Run from within a user's directory, which was generated by ```make_client <name>```
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

