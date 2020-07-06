# netstatfs
FUSE app to map network statistics to filesystem written in GO.

# Hierarchy
```
  /
  |-- <process_id>_<process_name>
  |   |-- <fd>_<unix|tcp{,6}|udp{,6}>_<local_ip>:<local_port>-><remote_ip>:<remote_port>_<state>
  |   `-- ... 
  |-- <process_id>_<process_name>
  `-- ...
```

# Roadmap  
1. PoC
1. Refactoring and tests
1. /proc/id/fd/ is linux-specific - plan for portability

# What netstat on Linux actually does
1. Opens /proc/ and read all numerical ids there - those are the processes
1. Reads all ids in each /proc/{processId}/fd/
1. Resolve links so socket file ids become of format 'socket:[socketInode]' or '[0000]:socketInode'
1. Stores socketInode -> process in the `pgr_hash` hashmap
1. Reads /proc/net/{tcp,tcp6,udp,udp6,igmp,igmp6,unix} - each of those have inode field to get process from the `prg_hash` hashmap

NB ss on the other hand uses netlink protocol:
https://man7.org/linux/man-pages/man7/sock_diag.7.html

