#
# Makefile created by tongjinam@qq.com 20160620
#

TARGET=server

GCC = gcc
CFLAGS = -g -Wall -W -Winline -Werror -Wno-unused-parameter -Wno-unused-function \
		 -I../include
LIBS = -lpthread -lcrypto

.PHONY: all clean

all: $(TARGET)

$(TARGET) : \
	main.o person_policy.o \
	connection.o epoll_event.o event.o message.o log.o coding.o buffer.o

	$(GCC) $(LDFLAGS) $(LIBS) -o $@ $^  

clean:
	rm -rf *.o $(TARGET)

 %.o : %.c
	$(GCC) $(CFLAGS) -c $< -o $@ 

