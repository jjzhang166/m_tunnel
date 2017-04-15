
# About

m_tunnel was TCP tunnel VPN with sock5 proxy interface, action like shadowsocks, but it only keeps 1 tcp connection between local and remote. It's lightweight and play well with https://github.com/xtaci/kcptun.

only support IPV4, under MacOSX/Linux/Windows. 

using crypto from cloudwu's mptun https://github.com/cloudwu/mptun/.




# QuickStart

Download precompiled [Release](https://github.com/lalawue/m_tunnel/releases).





# Install & Running

```
# make
# ./tun_remote.out config/remote_conf.txt # in server
# ./tun_local.out config/local_conf.txt   # in local
```





# Configure

Under config dir, using \TAB to seperate key/value.
