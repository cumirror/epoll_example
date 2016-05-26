#!/bin/bash

#max open files for concurrency sockets
ulimit -n 65536

pid=`ps -ef | grep server | grep -v grep | awk '{print $2}'`

if [ -n "$pid" ];then
    kill -9 $pid
fi

echo "start server..."
./server

echo "start test..."
./client 5 10000
