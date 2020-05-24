# netstatfs
FUSE app to map network statistics to filesystem written in GO.

# Hierarchy
Hierarchy:
  /
  ├ processes
    ├ <process_id>_<process_name>
      ├ unix
      ├ tcp
        ├ <port>_<state>
      ├ udp
      ├ tcp6
      ├ udp6
    ├ <process_id>_<process_name>
    ├ ...
 
# Roadmap  
1. PoC
1. Refactor, go module, tests

# What netstat on Linux actually does
1. Opens /proc/ and read all numerical ids there - those are the processes
1. Reads all ids in each /proc/{processId}/fd/
1. Resolve links so socket file ids become of format 'socket:[socketInode]' or '[0000]:socketInode'
1. Stores in socketInode -> process name hash map
1. Reads /proc/net/{tcp,tcp6,udp,udp6,igmp,igmp6,unix} - each of those have inode field to connect to previous

