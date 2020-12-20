#include <memory>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <iostream>
//namespace fs = std::filesystem;
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

    void send_http_request(BIO *bio, const std::string &line, const std::string &host)
    {
        std::string request = line + "\r\n";
        request += "Host: " + host + "\r\n";
        request += "\r\n";

        BIO_write(bio, request.data(), request.size());
        BIO_flush(bio);
    }

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

    void verify_the_certificate(SSL *ssl, const std::string &expected_hostname)
    {
        int err = SSL_get_verify_result(ssl);
        if (err != X509_V_OK)
        {
            const char *message = X509_verify_cert_error_string(err);
            fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
            exit(1);
        }
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert == nullptr)
        {
            fprintf(stderr, "No certificate was presented by the server\n");
            exit(1);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1)
        {
            fprintf(stderr, "Certificate verification error: X509_check_host\n");
            exit(1);
        }
#else
        // X509_check_host is called automatically during verification,
        // because we set it up in main().
        (void)expected_hostname;
#endif
    }
    //will return a string containing this file's contents
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

    int get_cert(BIO *bio, string username, string password, bool changePw, string newPassword)
    {
        //Body
        //getcert args
        string body = "";
        body += username + "\n";
        body += password + "\n";
        if (changePw == true)
        {
            body += newPassword + "\n";
        }
        string csr_path = "csr/mycsr.csr.pem";
        string csr = get_file(csr_path);
        body += csr;

        //Headers
        std::string request = "";
        if (changePw == true)
        {
            request += "POST /CHANGEPW HTTP/1.0 \r\n";
        }
        else
        {
            request += "POST /GETCERT HTTP/1.0 \r\n";
        }
        request += "Host: www.finalproject.com \r\n";
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        request += "\r\n";

        //Send the message
        BIO_write(bio, request.data(), request.size());
        BIO_write(bio, body.data(), body.size());
        BIO_flush(bio);

        //Receive the message
        std::string response = my::receive_http_message(bio);
        printf("%s", response.c_str());

        std::istringstream f(response);
        std::string line;
        //read headers
        while (std::getline(f, line))
        {
            if (line == "\r")
            {
                break;
            }
        }

        //read the cert
        string mycert = "";
        while (std::getline(f, line))
        {
            mycert += line + "\n";
        }

        //write the cert to file
        string cert_path = "certs/mycert.cert.pem";
        std::ofstream out(cert_path);
        out << mycert;
        out.close();
        return 0;
    }

    int send_msg(BIO *bio, string username, string message, string rcpts)
    {
        cout << "test" << endl;
        cout << "username: " << username << endl << "message: " << message << endl << "rcpts: " << rcpts << endl;
    }
} // namespace my

int main(int argc, char **argv)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

    std::string current_exec_name = argv[0]; // Name of the current exec program
    std::vector<std::string> all_args;

    if (argc > 1)
    {
        all_args.assign(argv + 1, argv + argc);
    }

    // If sendmsg or recvmsg, set up a client-side certificate.
    string programName = all_args[0];
    if (programName == "SENDMSG" || programName == "RECVMSG")
    {
        string certificateFile = all_args[2];
        string certificatePath = "certs/" + certificateFile;
        string pkeyPath = "keys/mykey.key.pem";
        cout << "Logging in with certificate: " << certificatePath << endl;
        cout << "Using private key: " << pkeyPath << endl;

        if (SSL_CTX_use_certificate_file(ctx.get(), certificatePath.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            my::print_errors_and_exit("Error loading client certificate");
        }
        if (SSL_CTX_use_PrivateKey_file(ctx.get(), pkeyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            my::print_errors_and_exit("Error loading client private key");
        }
    }

    //Set up other client settings
    if (SSL_CTX_load_verify_locations(ctx.get(), "certs/ca-chain.cert.pem", nullptr) != 1)
    {
        my::print_errors_and_exit("Error setting up trust store");
    }

cout << "stop point" << endl;
    auto bio = my::UniquePtr<BIO>(BIO_new_connect("localhost:8080"));
    if (bio == nullptr)
    {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(bio.get()) <= 0)
    {
        my::print_errors_and_exit("Error in BIO_do_connect");
    }
    auto ssl_bio = std::move(bio) | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
    SSL_set_tlsext_host_name(my::get_ssl(ssl_bio.get()), "www.finalproject.com");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(my::get_ssl(ssl_bio.get()), "www.finalproject.com");
#endif
    if (BIO_do_handshake(ssl_bio.get()) <= 0)
    {
        my::print_errors_and_exit("Error in BIO_do_handshake");
    }
    my::verify_the_certificate(my::get_ssl(ssl_bio.get()), "www.finalproject.com");

    //Actually send the request
    if (programName == "GETCERT")
    {
        my::get_cert(ssl_bio.get(), all_args[1], all_args[2], false, "");
    }
    else if (programName == "CHANGEPW")
    {
        my::get_cert(ssl_bio.get(), all_args[1], all_args[2], true, all_args[3]);
    }
    else if (programName == "RECVMSG")
    {
        cout << "TODO: RECVMSG" << endl;
        my::send_http_request(ssl_bio.get(), "POST /RECVMSG HTTP/1.1", "www.finalproject.com");
        std::string response = my::receive_http_message(ssl_bio.get());
        printf("%s", response.c_str());
    }
    else if (programName == "SENDMSG")
    {
cout << "TIME TO SEND message" << endl;
        /*
        cout << "TODO: SENDMSG" << endl;
        my::send_http_request(ssl_bio.get(), "POST /SENDMSG HTTP/1.1", "www.finalproject.com");
        std::string response = my::receive_http_message(ssl_bio.get());
        printf("%s", response.c_str());
        */
        my::send_msg(ssl_bio.get(), all_args[1], all_args[3], all_args[4]);
cout << "message has been sent" << endl;
    }
}
