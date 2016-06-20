# epoll_example
epoll ET 模式的简单示例。
  
## 编译说明：
安装openssl库：  
- centos: yum install -y openssl-devel  
- ubuntu: apt-get install libssl-dev

**client-server间采用短连接方式，一个消息一个应答，双方各自关闭连接。**

## server简要说明：
1. 功能：监听8777端口，进行网络消息处理
2. 内部采用epoll的ET模式，实现网络连接的异步处理
3. 两个线程：  
线程1用于epoll_wait等待连接，并进行IO的读写操作  
网络数据处理完成后，线程2进行消息的处理
4. 消息格式:  
[content-length/4B][content]  
content：message -> AES加密 -> base64 encode
5. 日志采用syslog的方式
6. 消息处理为单线程方式，所以内部主要采用静态buffer
7. 超时处理采用简单的链表管理方式

##client简要说明：  
1. 功能：主要用于server的性能测试

##不足：
1. 不支持长连接
2. 处理的模型简单：一问一答方式
3. 超时处理设计过于简单
4. 没有实现内存池：对于恶意构造的请求（如恶意Length）缺乏防护
