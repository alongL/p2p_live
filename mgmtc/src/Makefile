#WEB_PRO_DIR=webproto

all:mgmtc

OBJS=main.o iotc_log.o listener.o parser.o cJSON.o proto.o socket.o session.o glue.o http.o

# TODO: support full http protocol
#OBJS+=$(WEB_PRO_DIR)/protocol.o $(WEB_PRO_DIR)/wget.o $(WEB_PRO_DIR)/www.o


CFLAGS+=-lubox -lm

mgmtc:$(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lpthread

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf mgmtc

.PHONY: all clean
