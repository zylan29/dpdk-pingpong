# DPDK Ping-Pong

A simple program to evaluate raw DPDK latency.

The client sends a packet to server as a `ping`, then the server returns it back to client as a `pong`. 
The client records such ping-pong round trip time.

`Note` that the following steps have been evaluated on 2 Ubuntu 18.04 virtual machines (KVM) with DPDK 19.05. 

## Prepare

The following operations are tested on Ubuntu 18.04.4 with DPDK 19.11.1.

### Setup DPDK

```shell
sudo apt-get install make gcc libnuma-dev pkgconf python
make config T=x86_64-native-linuxapp-gcc
make

echo "export RTE_SDK=/root/dpdk-18.05" >> ~/.profile
echo "export RTE_TARGET=build" >> ~/.profile
. ~/.profile

```

### Setup huge memory pages

1. Enable huge memory page by default.

``` shell
vim /etc/default/grub

# Append "default_hugepagesz=1GB hugepagesz=1G hugepages=8" to the end of line GRUB_CMDLINE_LINUX_DEFAULT.

update-grub
```

2. Mount huge tlb by default.

```shell
vim /etc/fstab

# Append "nodev /mnt/huge hugetlbfs defaults 0 0" to the end of file.
```

### Install user space NIC driver
```shell
modprobe uio
cd $RTE_SDK/build/kmod
insmod igb_uio.ko
```

### Bind NIC to userspace driver

```shell
cd $RTE_SDK/usertools
./dpdk-devbind.py -s
./dpdk-devbind.py -b igb_uio $YOUR_NIC
```

## Build

1. Modify the MAC and IP addresses

Since the ARP protocol is not implemented, the MAC and IP addresses of the client and server are hardcoded.
Modify the follwing variables.
```c
/* the client side */
static struct ether_addr client_ether_addr =
    {{0x00, 0x0c, 0x29, 0xd5, 0xac, 0xc9}};
static uint32_t client_ip_addr = IPv4(172, 16, 166, 131);

/* the server side */
static struct ether_addr server_ether_addr =
    {{0x00, 0x0c, 0x29, 0xd1, 0xdc, 0x50}};
static uint32_t server_ip_addr = IPv4(172, 16, 166, 132);
```

2. Build

```shell
export RTE_SDK=/path/to/dpdk-19.05/
export RTE_TARGET=build
make
```

The valid parameters are: 
`-p` to specify the id of  which port to use, 0 by default (both sides), 
`-n` to customize how many ping-pong rounds, 100 by default (client side), 
`-s` to enable server mode (server side).

## Run
1. Make sure that NIC is properly binded to the DPDK-compible driver and huge memory page is configured on both client and server.

2. On the server side
```shell
sudo ./build/pingpong -l 1,2 -- -p 0 -s
```

3. On the client side
```shell
sudo ./build/pingpong -l 1,2 -- -p 0 -n 200
```

`Note` that >= 2 lcores are needed.

The output shoud be like this
```
====== ping-pong statistics =====
tx 200 ping packets
rx 200 pong packets
dopped 0 packets
min rtt: 50 us
max rtt: 15808 us
average rtt: 427 us
=================================
```
Note that this test is run on virtual machines, ignore the numbers.

## Issues

1. The 1st ping-pong round is very slow.
2. Only support directly connectted client and server NICs.
