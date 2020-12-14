# SecurityProject
## Acknowledgements
- cryptographic helper functions courtesy of Brad Conte are stored in ```crypto```
- basic http client / server skeleton taken from https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/, as recommended on the assignment page

## Setting up the server
- To set up the server filesystem, go into the ```server/scripts``` directory. There, run ```create-filesystem```, which will create a filesystem directory at ```server/filesystem```. This directory contains one folder per user, and will also create a file in the coresponding directory containing the user's ```hashed_password```, as well as a ```pending``` directory to store pending messages.

- To set up the root CA, intermediate CA, and web server certificate that will be used by the server, go into the ```server/scripts``` directory. There, run ```ca-setup```, which will create a CA directory at ```server/CA```. This directory will store private keys for the root and intermediate CAs, as well as the certificate for the web server.

## Script descriptions
- ```make_client_cert``` takes a username and the path to a private key file (must be .pem), will generate a certificate using the intermediate CA and verify it. The certificate will be placed in the ```CA``` directory under ```intermediate/certs/<username>.cert.pem```. This certificate will also be placed in the filesystem under ```<username>/certificate.cert.pem``` for easy access.
