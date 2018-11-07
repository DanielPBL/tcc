CC=gcc
CFLAGS= -I/usr/include/mysql -I../shared_headers -Wall -Werror -g -ggdb
LDFLAGS=-lpthread -lcoap-2-tinydtls -ltinydtls -lmysqlclient -lcbor -lcrypto -lssl

CXX=g++
CXXFLAGS=-I../shared_headers -Wall -Werror -g -ggdb
LDXXFLAGS=

RM=rm
RMFLAGS=-rf

TARGET=auth_server
OBJS=auth_server.o ../shared/cwt.o ../shared/ssl_utils.o

all: $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(TARGET)

run:	$(TARGET)
	./auth_server

$(TARGET):	$(OBJS)
		$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

../shared/ssl_utils.o: ../shared/ssl_utils.c ../shared_headers/ssl_utils.h
	$(CC) $(CFLAGS) -c -o $@ ../shared/ssl_utils.c

../shared/cwt.o: ../shared/cwt.c ../shared_headers/cwt.h
	$(CC) $(CFLAGS) -c -o $@ ../shared/cwt.c

auth_server.o: auth_server.c ../shared/cwt.o ../shared/ssl_utils.o
	$(CC) $(CFLAGS) -c -o $@ auth_server.c
