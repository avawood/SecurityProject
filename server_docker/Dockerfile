# Get the base Ubuntu image from Docker Hub
FROM ubuntu:latest

# Update apps on the base image
RUN apt-get -y update && apt-get install -y

# Install the Clang compiler
RUN apt-get -y install clang

RUN apt-get install libssl-dev

RUN apt-get -y install openssl

# Copy the current folder which contains C++ source code to the Docker image under /usr/src
COPY server_jail /

# Specify the working directory
WORKDIR /

# Run the output program from the previous step
CMD ["./https_server", "CA/intermediate/certs/www.finalproject.com.cert.pem", "CA/intermediate/private/www.finalproject.com.key.pem", "CA/intermediate/certs/ca-chain.cert.pem"]