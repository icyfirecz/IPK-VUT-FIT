CC=g++
FLAGS=-g -Wall -Werror -pedantic -std=c++11
FILE=ipk-scan

all:
	$(CC) $(FLAGS) $(FILE).cpp udp.cpp tcp.cpp -o $(FILE) -lpcap -pthread
