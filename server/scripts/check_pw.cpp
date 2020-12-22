#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <crypt.h>
using namespace std;

//Assume that this is being run from the server/ directory.
//Given a username and password, will go grab the hashed password and check that the supplied password hashes correctly.
int main(int argc, char *argv[])
{
    bool password_ok = true;
    char *c;

    if (argc != 3)
    {
        fprintf(stderr, "arg count\n");
        return 1;
    }
    char *username = argv[1];
    char *password = argv[2];

    streampos size;
    char *hashed_pw;

    ifstream file("filesystem/" + string(username) + "/hashed_password", ios::in | ios::binary | ios::ate);
    if (file.is_open())
    {
        size = file.tellg();
        hashed_pw = new char[size];
        file.seekg(0, ios::beg);
        file.read(hashed_pw, size);
        file.close();
        c = crypt(password, hashed_pw);
        if (string(c) != string(hashed_pw))
        {
            password_ok = false;
            cout << "bad" << endl;
        }
        delete[] hashed_pw;
    }
    else
        cout << "Unable to open file";
    if (password_ok == false)
    {
        return 1;
    }
    return 0;
}
