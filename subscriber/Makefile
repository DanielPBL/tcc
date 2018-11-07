CC=gcc
CFLAGS=-I../shared_headers -Wall -Werror -g -ggdb
LDFLAGS=-lpthread -lcoap-2-tinydtls -ltinydtls -lmysqlclient -lcbor -lcrypto -lssl

RM=rm
RMFLAGS=-rf

TARGET=subscriber
OBJS=subscriber.o ../shared/cwt.o ../shared/coap_utils.o

all: $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(TARGET)

run:	$(TARGET)
	./subscriber

$(TARGET):	$(OBJS)
		$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

../shared/coap_utils.o: ../shared/coap_utils.c ../shared_headers/coap_utils.h
	$(CC) $(CFLAGS) -c -o $@ ../shared/coap_utils.c

../shared/cwt.o: ../shared/cwt.c ../shared_headers/cwt.h
	$(CC) $(CFLAGS) -c -o $@ ../shared/cwt.c

subscriber.o: subscriber.c ../shared/cwt.o ../shared/coap_utils.o
	$(CC) $(CFLAGS) -c -o $@ subscriber.c
