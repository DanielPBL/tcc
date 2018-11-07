CC=gcc
CFLAGS=-Iinclude -I../shared_headers -g -ggdb -Wno-discarded-qualifiers
LDFLAGS=-lpthread -lcoap-2-tinydtls -ltinydtls -lmysqlclient -lcbor -lcrypto -lssl

RM=rm
RMFLAGS=-rf


TARGET=build/broker
OBJS=src/coap-broker.o src/CoAPRD.o src/LibcoapMod.o src/LinkedListDB.o src/LinkFormatParser.o ../shared/ssl_utils.o ../shared/cwt.o

all: $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(TARGET)

run:	$(TARGET)
	./build/broker

$(TARGET):	$(OBJS)
		$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

src/CoAPRD.o: include/CoAPRD.h src/CoAPRD.c
	$(CC) $(CFLAGS) -c -o $@ src/CoAPRD.c

src/LibcoapMod.o: include/LibcoapMod.h src/LibcoapMod.c
	$(CC) $(CFLAGS) -c -o $@ src/LibcoapMod.c

src/LinkedListDB.o: include/LinkedListDB.h src/LinkedListDB.c
	$(CC) $(CFLAGS) -c -o $@ src/LinkedListDB.c

src/LinkFormatParser.o: include/LinkFormatParser.h src/LinkFormatParser.c
	$(CC) $(CFLAGS) -c -o $@ src/LinkFormatParser.c

../shared/ssl_utils.o: ../shared_headers/ssl_utils.h ../shared/ssl_utils.c
	$(CC) $(CFLAGS) -c -o $@ ../shared/ssl_utils.c

../shared/cwt.o: ../shared/cwt.c ../shared_headers/cwt.h
	$(CC) $(CFLAGS) -c -o $@ ../shared/cwt.c

src/main/coap-broker.o: include/CoAPRD.h include/LibcoapMod.h include/LinkedListDB.h include/LinkFormatParser.h src/main/coap-broker.c
	$(CC) $(CFLAGS) -c -o $@ src/main/coap-broker.c
