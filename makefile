http_client: http_client.o
	g++ http_client.o -o http_client -lssl -lcrypto

http_client.o: http_client.cpp
	g++ --std=c++17 -c http_client.cpp

http_server: http_server.o
	g++ http_server.o -o http_server -lssl -lcrypto

http_server.o: http_server.cpp
	g++ --std=c++17 -c http_server.cpp

clean:
	rm *.o http_server http_client
