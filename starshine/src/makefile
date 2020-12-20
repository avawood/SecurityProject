https_client: https_client.o
	g++ https_client.o -o https_client -lssl -lcrypto

https_client.o: https_client.cpp
	g++ --std=c++17 -c https_client.cpp

clean:
	rm *.o https_client
