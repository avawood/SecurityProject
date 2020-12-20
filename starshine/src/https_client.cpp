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

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

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

    int send_msg(BIO *bio, string username, string message, std::vector<std::string> rcpts)
    {
// TODO: DELETE sanity check
        // SANITY CHECKING
        cout << "username: " << username << endl;
        cout << "rpts: ";
        for (auto ele : rcpts){
            cout << ele << ", ";
        }
        cout << endl;
        cout << "message: " << message << endl;
        // END SANITY CHECK


        // First Request
        // Request Body: Only contains rcpts
        string req1_body = "";
        for (int pos = 0; pos < rcpts.size(); pos++){
            req1_body += rcpts[pos];
            if (pos != rcpts.size() - 1) {
                req1_body += " ";
            }
        }
        
        //Headers
        string request = "";
        request += "POST /SENDMSG_ACK HTTP/1.0 \r\n";
        request += "Host: www.finalproject.com \r\n";
        request += "Content-Length: " + std::to_string(req1_body.size()) + "\r\n";
        request += "\r\n";

        //Send the message
        BIO_write(bio, request.data(), request.size());
        BIO_write(bio, req1_body.data(), req1_body.size());
        BIO_flush(bio);

        //Receive the response from first request
        std::string response1 = my::receive_http_message(bio);
        printf("%s", response1.c_str());

        std::istringstream f(response1);
        std::string line;
        bool ok = false;
        int tempcount = 0;

        //read headers
        while (std::getline(f, line))
        {
            
            if (tempcount == 0){
                if (line.find("200 OK") != std::string::npos) ok = true;
                tempcount++;
            }
            
            if (line == "\r")
            {
                break;
            }
        }
        
        vector<string> encrypted;

        // Second Request
        // Message: contains sender and rcpts
        // sample:
        // From: A
        // To: B, C, D
        // I am Message
        string body = "From: " + body + '\n';
        body += "To: "; 
        for (int pos = 0; pos < rcpts.size(); pos++) {
            body += rcpts[pos];
            if (pos != rcpts.size() - 1){
                body += ", ";
            }
        }

        //read the certs from response to first request
        string current_cert = "";
        while (ok && std::getline(f, line))
        {
            if (line != "\n")
            {
                current_cert += line + "\n";
            }
            else
            {
                //WE HIT THE END OF THE CERT TIME TO ENCRYPT!!
                //THE STUFF BELOW ASSUMES A TMP FOLDER INSIDE STARSHINE!!!!
                //****ENCRYPTION STUFF FROM DEMOS BEGINNING*******

                BIO *r_in = NULL, *r_out = NULL, *r_tbio = NULL;
                X509 *rcert = NULL;
                STACK_OF(X509) *recips = NULL;
                CMS_ContentInfo *r_cms = NULL;
                int r_ret = 1;

                int r_flags = CMS_STREAM;

                OpenSSL_add_all_algorithms();
                ERR_load_crypto_strings();

                //I ADDED THE STUFF BELOW TO THE DEMO CODE
                //temp cert file for the current recipient & message file
                ofstream tempcert("tmp/mytemp.pem");
                ofstream tempmsg("tmp/message");

                if (!tempcert.is_open())
                {
                    goto r_err;
                }

                if (!tempmsg.is_open())
                {
                    goto r_err;
                }

                tempcert << current_cert << endl;
                tempmsg << body << endl;
                tempcert.close();
                tempmsg.close();
                //current_cert & message wirtten to tmp files


                /* Read in recipient certificate */
                r_tbio = BIO_new_file("tmp/mytemp.pem", "r");

                if (!r_tbio)
                    goto r_err;

                rcert = PEM_read_bio_X509(r_tbio, NULL, 0, NULL);

                if (!rcert)
                    goto r_err;

                /* Create recipient STACK and add recipient cert to it */
                recips = sk_X509_new_null();

                if (!recips || !sk_X509_push(recips, rcert))
                    goto r_err;

                /*
                * sk_X509_pop_free will free up recipient STACK and its contents so set
                * rcert to NULL so it isn't freed up twice.
                */
                rcert = NULL;

                /* Open content being encrypted */

                r_in = BIO_new_file("tmp/message", "r");

                if (!r_in)
                    goto r_err;

                /* encrypt content */
                r_cms = CMS_encrypt(recips, r_in, EVP_des_ede3_cbc(), r_flags);

                if (!r_cms)
                    goto r_err;

                r_out = BIO_new_file("tmp/enc_message", "w");
                if (!r_out)
                    goto r_err;

                /* Write out S/MIME message */
                if (!SMIME_write_CMS(r_out, r_cms, r_in, r_flags))
                    goto r_err;

                r_ret = 0;

            r_err:

                if (r_ret) {
                    fprintf(stderr, "Error Encrypting Data\n"); //do I need to change this?????????
                    ERR_print_errors_fp(stderr);
                    return r_ret;
                }

                CMS_ContentInfo_free(r_cms);
                X509_free(rcert);
                sk_X509_pop_free(recips, X509_free);
                BIO_free(r_in);
                BIO_free(r_out);
                BIO_free(r_tbio);
                
            
            //At this point, we have the encrypted message in tmp/enc_message, time to sign it

                BIO *s_in = NULL, *s_out = NULL, *s_tbio = NULL;
                X509 *scert = NULL;
                EVP_PKEY *skey = NULL;
                CMS_ContentInfo *s_cms = NULL;
                int s_ret = 1;

                int s_flags = CMS_DETACHED | CMS_STREAM;

                OpenSSL_add_all_algorithms();
                ERR_load_crypto_strings();

                /* Read in signer certificate and private key */
                s_tbio = BIO_new_file("keys/mykey.key.pem", "r");

                if (!s_tbio)
                    goto s_err;

                scert = PEM_read_bio_X509(s_tbio, NULL, 0, NULL);

                BIO_reset(s_tbio);

                skey = PEM_read_bio_PrivateKey(s_tbio, NULL, 0, NULL);

                if (!scert || !skey)
                    goto s_err;

                /* Open content being signed */

                s_in = BIO_new_file("tmp/enc_message", "r");

                if (!s_in)
                    goto s_err;

                /* Sign content */
                s_cms = CMS_sign(scert, skey, NULL, s_in, s_flags);

                if (!s_cms)
                goto s_err;

                s_out = BIO_new_file("tmp/signed_message", "w");
                if (!s_out)
                    goto s_err;

                if (!(s_flags & CMS_STREAM))
                    BIO_reset(s_in);

                /* Write out S/MIME message */
                if (!SMIME_write_CMS(s_out, s_cms, s_in, s_flags))
                    goto s_err;

                s_ret = 0;

            s_err:

                if (s_ret) {
                    fprintf(stderr, "Error Signing Data\n");
                    ERR_print_errors_fp(stderr);
                    return s_ret;
                }

                CMS_ContentInfo_free(s_cms);
                X509_free(scert);
                EVP_PKEY_free(skey);
                BIO_free(s_in);
                BIO_free(s_out);
                BIO_free(s_tbio);
                    

                //****ENCRYPTION STUFF FROM DEMOS END*********

                //signed message in tmp/signed_message

                ifstream message_final("tmp/signed_message");

                std::string msgline;
                string mymessage = "";
                while (std::getline(message_final, msgline))
                {
                    mymessage += msgline + "\n";
                }

                encrypted.push_back(mymessage);

                remove("tmp/signed_message");
                remove("tmp/enc_message");
                remove("tmp/mytemp.pem");
                remove("tmp/mymessage");

                //cout << mymessage << endl;

                return s_ret;
            }

        } //end of while

        //Second request continued

        for (int i = 0; i < encrypted.size(); i++)
        {
            //Headers
            string request_2 = "";
            request_2 += "POST /SENDMSG HTTP/1.0 \r\n";
            request_2 += "Host: www.finalproject.com \r\n";
            request_2 += "Content-Length: " + std::to_string(encrypted[i].size()) + "\r\n";
            request_2 += "\r\n";

            //Send the message
            BIO_write(bio, request_2.data(), request_2.size());
            BIO_write(bio, encrypted[i].data(), encrypted[i].size());
            BIO_flush(bio);

            //Receive response (confirmation)
            std::string response2 = my::receive_http_message(bio);
            printf("%s", response2.c_str());
        }
    }

    int recv_msg(BIO *bio, string username)
    {
    
        //Headers
        std::string request = "";
        request += "POST /RECV_MSG HTTP/1.0 \r\n";
        request += "Host: www.finalproject.com \r\n";
        request += "Content-Length: " + std::to_string(username.size()) + "\r\n";
        request += "\r\n";

        //Send the message
        BIO_write(bio, request.data(), request.size());
        BIO_write(bio, username.data(), username.size());
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
        string msg = "";
        bool cert = true;
        while (std::getline(f, line))
        {
            if (cert) {
                if (line == "\n") {
                    cert = false;
                    continue;
                }
                mycert += line + "\n";
            } else {
                msg += line + "\n";
            }
        }

        //write the cert to file
        string cert_path = "tmp/sender.cert.pem";
        std::ofstream out2(cert_path);
        out2 << mycert;
        out2.close();
        
        //write the encrypted message to file
        string msg_path = "tmp/msg_to_verify";
        std::ofstream out1(msg_path);
        out1 << msg;
        out1.close();

        //verify signature

        BIO *v_in = NULL, *v_out = NULL, *v_tbio = NULL, *v_cont = NULL;
        X509_STORE *v_st = NULL;
        X509 *cacert = NULL;
        CMS_ContentInfo *v_cms = NULL;

        int v_ret = 1;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Set up trusted CA certificate store */

        v_st = X509_STORE_new();

        /* Read in CA certificate */
        v_tbio = BIO_new_file("tmp/sender.cert.pem", "r");

        if (!v_tbio)
            goto v_err;

        cacert = PEM_read_bio_X509(v_tbio, NULL, 0, NULL);

        if (!cacert)
            goto v_err;

        if (!X509_STORE_add_cert(v_st, cacert))
            goto v_err;

        /* Open message being verified */

        v_in = BIO_new_file("tmp/msg_to_verify", "r");

        if (!v_in)
            goto v_err;

        /* parse message */
        v_cms = SMIME_read_CMS(v_in, &v_cont);

        if (!v_cms)
            goto v_err;

        /* File to output verified content to */
        v_out = BIO_new_file("tmp/verified_msg", "w");
        if (!v_out)
            goto v_err;

        if (!CMS_verify(v_cms, NULL, v_st, v_cont, v_out, 0)) {
            fprintf(stderr, "Verification Failure\n");
            goto v_err;
        }

        fprintf(stderr, "Verification Successful\n");

        v_ret = 0;

    v_err:

        if (v_ret) {
            fprintf(stderr, "Error Verifying Data\n");
            ERR_print_errors_fp(stderr);
            return v_ret;
        }

        CMS_ContentInfo_free(v_cms);
        X509_free(cacert);
        BIO_free(v_in);
        BIO_free(v_out);
        BIO_free(v_tbio);

        //signature verified, time to decrypt!

        BIO *in = NULL, *out = NULL, *tbio = NULL;
        X509 *rcert = NULL;
        EVP_PKEY *rkey = NULL;
        CMS_ContentInfo *cms = NULL;
        int ret = 1;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Read in recipient certificate and private key */
        tbio = BIO_new_file("keys/mykey.key.pem", "r");

        if (!tbio)
            goto err;

        rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

        BIO_reset(tbio);

        rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

        if (!rcert || !rkey)
            goto err;

        /* Open S/MIME message to decrypt */

        in = BIO_new_file("tmp/verified_msg", "r");

        if (!in)
            goto err;

        /* Parse message */
        cms = SMIME_read_CMS(in, NULL);

        if (!cms)
            goto err;

        out = BIO_new_file("tmp/decout", "w");
        if (!out)
            goto err;

        /* Decrypt S/MIME message */
        if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
            goto err;

        ret = 0;

    err:

        if (ret) {
            fprintf(stderr, "Error Decrypting Data\n");
            ERR_print_errors_fp(stderr);
            return ret;
        }

        CMS_ContentInfo_free(cms);
        X509_free(rcert);
        EVP_PKEY_free(rkey);
        BIO_free(in);
        BIO_free(out);
        BIO_free(tbio);

        string line1;
        ifstream myfile ("temp/decout");
        if (myfile.is_open())
        {
            while ( getline (myfile,line1) )
            {
                cout << line1 << '\n';
            }
            myfile.close();
        }
        else cout << "Unable to open file"; 
    
        remove("tmp/sender.cert.pem");
        remove("tmp/verified_msg");
        remove("tmp/msg_to_verify");
        remove("tmp/decout");

        return ret;
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
        my::recv_msg(ssl_bio.get(), all_args[1]);
    }
    else if (programName == "SENDMSG")
    {
        string temp = "";
        string message = "";
        while(getline(cin, temp)) {
            message += temp;
            message += '\n';
        }
        std::vector<string> rcpts;
        for (int rec = 4; rec < argc; rec++) {
            rcpts.push_back(argv[rec]);
        }

        if (!rcpts.empty()) my::send_msg(ssl_bio.get(), all_args[1], message, rcpts);
        else cerr << "Error: No recipient specified." << endl;
    }
    return 0;
}
