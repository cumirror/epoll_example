#
# Makefile created by tongjinam@qq.com 20160620
#

TARGET=client

GCC = gcc
CFLAGS = -O2 -I../include -DPORT=8777
LIBS = -lpthread -lcrypto
CRYPT = ../server/coding.o ../server/buffer.o ../server/log.o
CRYPT_H = ../server/coding.h ../server/buffer.h
OBJS = $(CRYPT)

.PHONY: all clean

all: $(TARGET)

$(TARGET) : $(OBJS) client.o
	$(GCC) $(LIBS) -o $@ $^  

clean:
	rm -rf *.o $(TARGET)

 %.o : %.c
	$(GCC) $(CFLAGS) -c $< -o $@ 

