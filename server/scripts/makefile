all: check_pw

check_pw: check_pw.o
	g++ check_pw.o -o check_pw -lssl -lcrypto -lcrypt

check_pw.o: check_pw.cpp
	g++ --std=c++17 -c check_pw.cpp -lcrypt

clean:
	rm *.o check_pw