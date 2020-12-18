#include <memory>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <iterator>
#include <fstream>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

using namespace std;

namespace my
{

    template <class T>
    struct DeleterOf;
    template <>
    struct DeleterOf<BIO>
    {
        void operator()(BIO *p) const { BIO_free_all(p); }
    };
    template <>
    struct DeleterOf<BIO_METHOD>
    {
        void operator()(BIO_METHOD *p) const { BIO_meth_free(p); }
    };
    template <>
    struct DeleterOf<SSL_CTX>
    {
        void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
    };

    template <class OpenSSLType>
    using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

    my::UniquePtr<BIO> operator|(my::UniquePtr<BIO> lower, my::UniquePtr<BIO> upper)
    {
        BIO_push(upper.get(), lower.release());
        return upper;
    }

    class StringBIO
    {
        std::string str_;
        my::UniquePtr<BIO_METHOD> methods_;
        my::UniquePtr<BIO> bio_;

    public:
        StringBIO(StringBIO &&) = delete;
        StringBIO &operator=(StringBIO &&) = delete;

        explicit StringBIO()
        {
            methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
            if (methods_ == nullptr)
            {
                throw std::runtime_error("StringBIO: error in BIO_meth_new");
            }
            BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
                std::string *str = reinterpret_cast<std::string *>(BIO_get_data(bio));
                str->append(data, len);
                return len;
            });
            bio_.reset(BIO_new(methods_.get()));
            if (bio_ == nullptr)
            {
                throw std::runtime_error("StringBIO: error in BIO_new");
            }
            BIO_set_data(bio_.get(), &str_);
            BIO_set_init(bio_.get(), 1);
        }
        BIO *bio() { return bio_.get(); }
        std::string str() && { return std::move(str_); }
    };

    [[noreturn]] void print_errors_and_exit(const char *message)
    {
        fprintf(stderr, "%s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    [[noreturn]] void print_errors_and_throw(const char *message)
    {
        my::StringBIO bio;
        ERR_print_errors(bio.bio());
        throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
    }

    //Additions so that we can verify client-side certs:
    SSL *get_ssl(BIO *bio)
    {
        SSL *ssl = nullptr;
        BIO_get_ssl(bio, &ssl);
        if (ssl == nullptr)
        {
            my::print_errors_and_exit("Error in BIO_get_ssl");
        }
        return ssl;
    }
    //end additions

    std::string receive_some_data(BIO *bio)
    {
        char buffer[1024];
        int len = BIO_read(bio, buffer, sizeof(buffer));
        if (len < 0)
        {
            my::print_errors_and_throw("error in BIO_read");
        }
        else if (len > 0)
        {
            return std::string(buffer, len);
        }
        else if (BIO_should_retry(bio))
        {
            return receive_some_data(bio);
        }
        else
        {
            my::print_errors_and_throw("empty BIO_read");
        }
    }

    std::vector<std::string> split_headers(const std::string &text)
    {
        std::vector<std::string> lines;
        const char *start = text.c_str();
        while (const char *end = strstr(start, "\r\n"))
        {
            lines.push_back(std::string(start, end));
            start = end + 2;
        }
        return lines;
    }

    std::string receive_http_message(BIO *bio)
    {
        std::string headers = my::receive_some_data(bio);
        char *end_of_headers = strstr(&headers[0], "\r\n\r\n");
        while (end_of_headers == nullptr)
        {
            headers += my::receive_some_data(bio);
            end_of_headers = strstr(&headers[0], "\r\n\r\n");
        }
        std::string body = std::string(end_of_headers + 4, &headers[headers.size()]);
        headers.resize(end_of_headers + 2 - &headers[0]);
        size_t content_length = 0;
        for (const std::string &line : my::split_headers(headers))
        {
            if (const char *colon = strchr(line.c_str(), ':'))
            {
                auto header_name = std::string(&line[0], colon);
                if (header_name == "Content-Length")
                {
                    content_length = std::stoul(colon + 1);
                }
            }
        }
        while (body.size() < content_length)
        {
            body += my::receive_some_data(bio);
        }
        return headers + "\r\n" + body;
    }

    void send_http_response(BIO *bio, const std::string &body)
    {
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        response += "\r\n";

        BIO_write(bio, response.data(), response.size());
        BIO_write(bio, body.data(), body.size());
        BIO_flush(bio);
    }

    my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio)
    {
        if (BIO_do_accept(accept_bio) <= 0)
        {
            return nullptr;
        }
        return my::UniquePtr<BIO>(BIO_pop(accept_bio));
    }

    string get_file(string filepath)
    {
        streampos size;
        char *memblock;

        string data = "";

        ifstream file(filepath, ios::in | ios::binary | ios::ate);
        if (file.is_open())
        {
            size = file.tellg();
            memblock = new char[size];
            file.seekg(0, ios::beg);
            file.read(memblock, size);
            file.close();

            data = memblock;
            delete[] memblock;
        }
        return data;
    }

    void get_cert(BIO *bio, const std::string &username, const std::string &csr)
    {
        //write the csr to file
        string csr_path = "tmp/mycsr.csr.pem";
        std::ofstream out(csr_path);
        out << csr;
        out.close();

        //Get a cert from this csr
        pid_t pid;
        int ret = 1;
        int status;
        pid = fork();
        if (pid == -1)
        {
            printf("can't fork, error occured\n");
            exit(EXIT_FAILURE);
        }
        else if (pid == 0)
        {
            string make_client_cert_prog = "scripts/make_client_cert";
            char *argv_list[] = {(char *)make_client_cert_prog.c_str(), (char *)username.c_str(), (char *)csr_path.c_str(), NULL};
            execv((char *)make_client_cert_prog.c_str(), argv_list);
            exit(0);
        }
        else
        {
            if (waitpid(pid, &status, 0) > 0)
            {
                if (WIFEXITED(status) && !WEXITSTATUS(status))
                    printf("client cert generation successful\n");
                else if (WIFEXITED(status) && WEXITSTATUS(status))
                {
                    if (WEXITSTATUS(status) == 127)
                    {
                        // execv failed
                        printf("execv failed\n");
                    }
                    else
                        printf("program terminated normally,"
                               " but returned a non-zero status\n");
                }
                else
                    printf("program didn't terminate normally\n");
            }
            else
            {
                printf("waitpid() failed\n");
            }
            //Send the cert that was generated!
            string client_cert_contents = get_file("CA/intermediate/certs/" + username + ".cert.pem");
            my::send_http_response(bio, client_cert_contents);
        }
    }

} // namespace my

bool check_pw(string username, string password)
{
    pid_t pid;
    int ret = 1;
    int status;
    pid = fork();
    if (pid == -1)
    {
        printf("can't fork, error occured\n");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        string check_pw_prog = "scripts/check_pw";
        char *argv_list[] = {(char *)check_pw_prog.c_str(), (char *)username.c_str(), (char *)password.c_str(), NULL};
        execv((char *)check_pw_prog.c_str(), argv_list);
        exit(0);
    }
    else
    {
        if (waitpid(pid, &status, 0) > 0)
        {
            if (WIFEXITED(status) && !WEXITSTATUS(status))
                printf("we successfully checked the password...\n");
            else if (WIFEXITED(status) && WEXITSTATUS(status))
            {
                if (WEXITSTATUS(status) == 127)
                {
                    // execv failed
                    printf("execv failed\n");
                }
                else
                    printf("bad password hash.\n");
                return false;
            }
            else
                printf("program didn't terminate normally\n");
        }
        else
        {
            printf("waitpid() failed\n");
        }
    }
    return true;
}

bool change_pw(string username, string password)
{
    pid_t pid;
    int ret = 1;
    int status;
    pid = fork();
    if (pid == -1)
    {
        printf("can't fork, error occured\n");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        string change_pw_prog = "scripts/change_pw";
        char *argv_list[] = {(char *)change_pw_prog.c_str(), (char *)username.c_str(), (char *)password.c_str(), NULL};
        execv((char *)change_pw_prog.c_str(), argv_list);
        exit(0);
    }
    else
    {
        if (waitpid(pid, &status, 0) > 0)
        {
            if (WIFEXITED(status) && !WEXITSTATUS(status))
                printf("we successfully changed the password...\n");
            else if (WIFEXITED(status) && WEXITSTATUS(status))
            {
                if (WEXITSTATUS(status) == 127)
                {
                    // execv failed
                    printf("execv failed\n");
                }
                else
                    printf("bad password hash.\n");
                return false;
            }
            else
                printf("program didn't terminate normally\n");
        }
        else
        {
            printf("waitpid() failed\n");
        }
    }
    return true;
}

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
#endif

    if (SSL_CTX_use_certificate_file(ctx.get(), "CA/intermediate/certs/www.finalproject.com.cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        my::print_errors_and_exit("Error loading server certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "CA/intermediate/private/www.finalproject.com.key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        my::print_errors_and_exit("Error loading server private key");
    }

    if (SSL_CTX_load_verify_locations(ctx.get(), "CA/intermediate/certs/ca-chain.cert.pem", nullptr) != 1)
    {
        my::print_errors_and_exit("Error setting up trust store");
    }

    //Addition: require the client to send a certificate
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept("8080"));
    if (BIO_do_accept(accept_bio.get()) <= 0)
    {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port 8080)");
    }

    static auto shutdown_the_socket = [fd = BIO_get_fd(accept_bio.get(), nullptr)]() {
        close(fd);
    };
    signal(SIGINT, [](int) { shutdown_the_socket(); });

    while (auto bio = my::accept_new_tcp_connection(accept_bio.get()))
    {
        bio = std::move(bio) | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0));
        try
        {
            std::string request = my::receive_http_message(bio.get());
            printf("Got request:\n");
            printf("%s\n", request.c_str());

            //parse the first line to get either getcert, changepw, sendmsg, recvmsg
            std::istringstream f(request);
            std::string first_line;
            std::getline(f, first_line);
            std::istringstream iss(first_line);
            std::vector<std::string> results(std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>());
            std::string programName = results[1].substr(1);

            cout << "Program name: " << programName << endl;

            //Take a look at the certificate provided:
            auto ssl = my::get_ssl(bio.get());
            X509 *cert = SSL_get_peer_certificate(ssl);
            bool verifyOK = false;
            bool foundCert = false;
            if (cert == nullptr)
            {
                printf("No certificate was presented by the client\n");
            }
            else
            {
                printf("We found a certificate!:)\n");
                foundCert = true;
                char buf[256];
                X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
                printf("issuer= %s\n", buf);
                long verify_result = SSL_get_verify_result(ssl);
                printf("verify results:%ld\n", verify_result);
                if (verify_result == X509_V_OK)
                {
                    printf("Verification OK!");
                    verifyOK = true;
                }
                else
                {
                    printf("Certificate not verified!");
                }
            }
            X509_free(cert);

            //log the client in.
            //The client only needs to login with a certificate for recvmsg and sendmsg.
            if ((programName == "SENDMSG" || programName == "RECVMSG") && (verifyOK == false || foundCert == false))
            {
                my::send_http_response(bio.get(), "This client-side certificate could not be verified, or the client did not provide a certificate.\n");
            }
            else
            {
                //Successful login: actually perform the operations.
                if (programName == "GETCERT" || programName == "CHANGEPW")
                {
                    std::istringstream f(request);
                    std::string line;
                    //skip headers
                    while (std::getline(f, line))
                    {
                        if (line == "\r")
                        {
                            break;
                        }
                    }
                    string username;
                    std::getline(f, username);
                    string password;
                    std::getline(f, password);
                    //Check username, password with our hashed passwords...
                    bool passwordOk = check_pw(username, password);
                    if (passwordOk == false)
                    {
                        my::send_http_response(bio.get(), "The username and password do not match.\n");
                    }
                    else
                    {
                        if (programName == "CHANGEPW")
                        {
                            string newPassword;
                            std::getline(f, newPassword);
                            change_pw(username, newPassword);
                        }
                        string csr = "";
                        while (std::getline(f, line))
                        {
                            csr += line + "\n";
                        }
                        my::get_cert(bio.get(), username, csr);
                    }
                }
                else if (programName == "RECVMSG")
                {
                    my::send_http_response(bio.get(), "TODO: RECVMSG!\n");
                }
                else if (programName == "SENDMSG")
                {
                    my::send_http_response(bio.get(), "TODO: SENDMSG!\n");
                }
                my::send_http_response(bio.get(), "Please call either GETCERT, CHANGEPW, RECVMSG, or SENDMSG.\n");
            }
        }
        catch (const std::exception &ex)
        {
            printf("Worker exited with exception:\n%s\n", ex.what());
        }
    }
    printf("\nClean exit!\n");
}
