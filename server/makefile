https_server: https_server.o
	g++ https_server.o -o https_server -lssl -lcrypto -lstdc++fs

https_server.o: https_server.cpp
	g++ --std=c++17 -c https_server.cpp

clean:
	rm *.o https_server
