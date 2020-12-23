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

RUN useradd -ms /bin/bash server
RUN useradd -ms /bin/bash curruser

# make everything only executable
RUN umask 711

#set perms on individual mailboxes
RUN for DIR in filesystem/*; do chmod u=rwx,g=,o= $DIR $DIR/hashed_password DIR/pending; chown server $DIR $DIR/hashed_password $DIR/pending; done

# The mailergroup was made in make-mailbox users. Only this group will have access to the filesystem.
RUN chown server filesystem
RUN chmod u=rwx,g=,o= filesystem  

#similar permissions set for tmp
RUN chown server tmp
RUN chmod u=rwx,g=rx,o=rx tmp

# Now, set the group and setgid for https_server to mailergroup
RUN chown server https_server
RUN chmod 111 https_server
RUN chmod u+s https_server

USER curruser

# Specify the working directory
WORKDIR /

# Run the output program from the previous step
CMD ["./https_server", "CA/intermediate/certs/www.finalproject.com.cert.pem", "CA/intermediate/private/www.finalproject.com.key.pem", "CA/intermediate/certs/ca-chain.cert.pem"]