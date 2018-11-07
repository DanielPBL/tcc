CC=gcc
CFLAGS=-I/usr/include/mysql -I../shared_headers -Wall -Werror -g -ggdb
LDFLAGS=-lpthread -lcoap-2-tinydtls -ltinydtls -lmysqlclient -lcbor -lcrypto -lssl

RM=rm
RMFLAGS=-rf

TARGET=db_server
OBJS=db_server.o

all: $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(TARGET)

run:	$(TARGET)
	./db_server

$(TARGET):	$(OBJS)
		$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

publisher.o: db_server.c
	$(CC) $(CFLAGS) -c -o $@ db_server.c
