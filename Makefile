#
# Makefile created by tongjin@baidu.com 20151113
#

WORKROOT=..

.PHONY: all clean

all:
	make -C server clean
	make -C server
	cp server/server output/
	make -C client clean
	make -C client
	cp client/client output/
	ls output/*

clean:
	make -C server clean
	make -C client clean
	rm -rf output/client output/server

backup: clean
	cd ..; tar jcvf epoll_example.tar.bz2 epoll_example

test: all
	cd output; sh test.sh
