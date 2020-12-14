# Security Final Project
## Acknowledgements
- cryptographic helper functions courtesy of Brad Conte are stored in ```crypto```
- basic http client / server skeleton taken from https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/, as recommended on the assignment page

## 1) Setting Up the Server
- To set up the server filesystem, go into the ```server/scripts``` directory. There, run ```create-filesystem```, which will create a filesystem directory at ```server/filesystem```. This directory contains one folder per user, and will also create a file in the coresponding directory containing the user's ```hashed_password```, as well as a ```pending``` directory to store pending messages.

- To set up the root CA, intermediate CA, certificate revocation list, and web server certificate that will be used by the server, go into the ```server/scripts``` directory. There, run ```ca-setup```, which will create a CA directory at ```server/CA```. This directory will store private keys for the root and intermediate CAs, as well as the certificate for the web server.

## 2) Setting Up the Client
- To set up the client, go into the ```client/scripts``` directory. There, run ```client_setup```, which will create the directories ```client/keys```, ```client/certs```, ```client/csr```. The keys directory will store the client's private key, which will automatically be generated and placed there. The certs directory will store the client's cert, as well as the ca-chain cert that it will use to verify the server's cert. The ```csr``` directory will hold any csr's that have been generated in order to be sent to the server. The ```ca-chain.cert.pem``` from the server will automatically be copied into the ```certs ``` directory.

## Server Script Descriptions
- ```make_client_cert```: Given a csr (must be .csr.pem), will generate a TLS+encryption+signing certificate and verify it. If a certificate already exists for this user, it will be revoked and then recreated. The certificate will be saved to ```intermediate/certs/<username>.cert.pem```, as well as ```filesystem/<username>/certificate.cert.pem``` for easy access.
To run: ```./make_client_cert starshine ../testing/starshine.csr.pem```.  We assume that this is being run from within the scripts dir.

## Client Script Descriptions
- ```make_csr```: Given a username and the path to a private key file (must be .csr.pem), will generate a csr. This is just a helper script - ```getcert``` and ```changepw``` will need to use this to generate the csr that they will send to the server. (See https://piazza.com/class/keud2qcwhr14d?cid=543)
The output will be stored in ```client/csr/<username>.csr.pem```
Run like ```./make_csr starshine ../keys/mykey.key.pem```
