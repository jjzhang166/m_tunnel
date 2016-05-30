
# About

m_tunnel was TCP tunnel VPN with sock5 proxy interface, action like shadowsocks, but it only keeps 1 tcp connection between local and remote.

only support IPV4, under MacOSX and Linux.

using crypto from cloudwu's mptun https://github.com/cloudwu/mptun/.





# Install & Running

```
# make
# ./tun_remote.out config/remote_conf.txt # in server
# ./tun_local.out config/local_conf.txt   # in local
```





# Configure

see config dir, using \TAB to seperate key/value.






# Bugs & Question

welcome Issues and PR.
