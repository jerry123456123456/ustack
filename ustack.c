#include <stdio.h>
#include <unistd.h>
#include <rte_eal.h>  //包含DPDK（Data Plane Development Kit）的环境抽象层（EAL）相关的头文件。
#include <rte_ethdev.h>  //包含DPDK中以太网设备相关的头文件。
#include <rte_mbuf.h>   //包含DPDK中数据包缓冲区（mbuf）相关的头文件。
#include <arpa/inet.h>  //包含Internet地址转换函数的头文件。

#define NUM_MBUFS 2048
#define BURST_SIZE 128

#define ENABLE_SEND 1

int gDpdkPortId = 0;

#if ENABLE_SEND
//8*6=48,MAC地址48位
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];   //源MAC地址    
uint8_t gDstMac[RTE_ETHER_ADDR_LEN];   //目的MAC地址
//ip地址32位
uint32_t gSrcIp;   //源ip
uint32_t gDstIp;   //目的ip
//端口最大65535,16位
uint16_t gSrcPort;  //源端口
uint16_t gDstPort;  //目的端口
#endif

/*网络字节序是大端，主机字节序是小端
htonl(Host to Network Long):将32位无符号整数从主机字节序转换为网络字节序。

htons:将16位无符号短整数从主机字节序转换为网络字节序。

ntohs:将16位的无符号短整数从网络字节序转换为主机字节序。

ntohl:将32位的无符号整数从网络字节序转换为主机字节序。
*/

static int ustack_encode_udp_pkt(uint8_t *msg,char *data,uint16_t total_length){
    //逐层解析
    //以太网
    struct rte_ether_hdr *eth=(struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes,gSrcMac,RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes,gDstMac,RTE_ETHER_ADDR_LEN);
    //协议类型
    eth->ether_type=htons(RTE_ETHER_TYPE_IPV4);

    //ip头
    struct rte_ipv4_hdr *iphdr=(struct rte_ipv4_hdr*)(eth+1);
    //这行代码设置IP版本号和首部长度字段。version_ihl是一个8位字段，其中高4位表示IP协议版本号（一般为IPv4或IPv6），低4位表示IP首部长度（以32位字长为单位）。0x45在二进制中是01010100，它对应的IP版本号为IPv4（0100），首部长度为20字节（0101乘以32位=20字节）。
    iphdr->version_ihl=0x45;
    //这行代码设置服务类型字段，用于指定数据包的优先级、拥塞控制等信息。type_of_service是一个8位字段，在此处被设置为0x0，表示未指定特殊服务类型。
    iphdr->type_of_service=0x0;
    iphdr->total_length=htons(total_length-sizeof(struct rte_ether_hdr));
    iphdr->packet_id=0;  //这个值可以随便写
    iphdr->fragment_offset=0;  //如果只发一个包，偏移地址就是0
    iphdr->time_to_live = 64;  //这个64就是有recv数据的关键，不能是0，因为这个代表ttl，每经过一个跳数-1,为0就丢弃
    iphdr->next_proto_id=IPPROTO_UDP;  //指出下一层协议的类型，TCP为6，UDP为17，ICMP为1
    iphdr->src_addr=gSrcIp;
    iphdr->dst_addr=gDstIp;
    iphdr->hdr_checksum=0;  //必须先置0，在计算
    iphdr->hdr_checksum=rte_ipv4_cksum(iphdr);

    //udp头
    struct rte_udp_hdr *udphdr =  (struct rte_udp_hdr *)(iphdr+1);
	udphdr->src_port = gSrcPort;
	udphdr->dst_port = gDstPort;
	
	uint16_t udplen = total_length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udphdr->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udphdr+1), data, udplen-sizeof(struct rte_udp_hdr));  //拷贝数据到udp头之后

	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

	return total_length;
}

//重新在内存池中分配
static struct rte_mbuf *ustack_send(struct rte_mempool *mbuf_pool,char *data,uint16_t length){
    const unsigned total_length = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
    struct rte_mbuf *mbuf=rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"Error with EAL init\n");
    }   
    mbuf->pkt_len=total_length;
    mbuf->data_len=total_length;

    uint8_t *pktdata=rte_pktmbuf_mtod(mbuf,uint8_t*);   //获得指向缓冲区起始位置的指针，便于后续使用
    ustack_encode_udp_pkt(pktdata,data,total_length);
    return mbuf;
}

static const struct rte_eth_conf port_conf_default = {  //定义了名为 `port_conf_default` 的结构体变量，其中包含了端口配置的默认值，主要设置了接收模式的最大数据包长度。
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

int main(int argc, char *argv[]) {
    if (rte_eal_init(argc, argv) < 0) {     //环境初始化
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    // 返回检测的网卡数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Support eth found\n");
    }
    printf("nb_sys_ports: %d\n", nb_sys_ports);

	//创建名为 `mbuf_pool` 的数据包缓冲池，用于存储数据包的缓冲区
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    // 设置每一个网口的读和写
    struct rte_eth_dev_info dev_info;    //存储以太网设备
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);    //获取设备信息，存在dev_onfo中

    const int num_rx_queues = 1;   //定义了一个常量 `num_rx_queues`，表示接收队列的数量为1
    const int num_tx_queues = 1;   //定义了一个常量 `num_tx_queues`，表示发送队列的数量为1
    struct rte_eth_conf port_conf = port_conf_default;
    //创建一个名为 `port_conf` 的结构体变量，并将其初始化为 `port_conf_default` 结构体的值。这里用于配置端口的默认值。
    
    //调用 `rte_eth_dev_configure()` 函数配置指定的DPDK端口。该函数接受端口ID、接收队列数量、发送队列数量和端口配置信息作为参数。如果配置失败（返回值小于0），则输出错误信息并退出程序。
    if (rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Could not configure\n");
    }

    //调用 `rte_eth_rx_queue_setup()` 函数设置指定端口的接收队列参数。该函数接受端口ID、队列索引、队列大小、队列绑定的NUMA节点、用户定义的配置和数据包缓冲池作为参数。如果设置接收队列失败（返回值小于0），则输出错误信息并退出程序。
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }
#if ENABLE_SEND
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;

	if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 512, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

#endif
    // 调用 `rte_eth_dev_start()` 函数启动指定的DPDK端口。如果启动失败（返回值小于0），则输出错误信息并退出程序
    if (rte_eth_dev_start(gDpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }

    printf("success\n");

    // 接收数据和处理数据
    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE]; //定义一个名为 `mbufs` 的指针数组，用于存储接收到的数据包。
        //调用 `rte_eth_rx_burst()` 函数从指定的DPDK端口接收数据包，并将其存储在 `mbufs` 数组中。`BURST_SIZE` 表示最大接收数据包数量。
        unsigned nb_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE); 
        if (nb_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error recv\n");
        }
        unsigned i = 0;
        for (i = 0; i < nb_recvd; i++) {
            // 先取出以太网头
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);    //用于将数据包缓冲区（`rte_mbuf` 结构体）转换为指定类型的数据结构指针。
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {   //用于将主机字节序（CPU字节序）的16位整数转换为大端字节序（网络字节序）的16位整数。在网络编程中，大多数网络协议使用的是大端字节序（网络字节序），因此在处理网络数据时需要进行字节序的转换。
                continue;  //检查是否为ipv4
            }
            //用于从数据包缓冲区中偏移指定字节数后，将数据包缓冲区转换为指定类型的数据结构指针。这个函数的作用类似于 `rte_pktmbuf_mtod()`，但是在转换时会进行偏移操作
            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            // 判断是不是UDP
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

#if ENABLE_SEND
                //寄收调换
                rte_memcpy(gSrcMac,ehdr->d_addr.addr_bytes,RTE_ETHER_ADDR_LEN);  //源MAC地址拿过来
                rte_memcpy(gDstMac,ehdr->s_addr.addr_bytes,RTE_ETHER_ADDR_LEN);  //目的MAC地址拿过来

                rte_memcpy(&gSrcIp,&iphdr->dst_addr,sizeof(uint32_t));   //ip
                rte_memcpy(&gDstIp,&iphdr->src_addr,sizeof(uint32_t));

                rte_memcpy(&gSrcPort,&udphdr->dst_port,sizeof(u_int16_t));  //端口
                rte_memcpy(&gDstPort,&udphdr->src_port,sizeof(u_int16_t));
#endif
                uint16_t length = ntohs(udphdr->dgram_len)-sizeof(struct rte_udp_hdr);  //这里有大小端的问题
                printf("length: %d, content: %s\n", length, (char *)(udphdr + 1));

#if ENABLE_SEND
                //发送
                struct rte_mbuf *txbuf = ustack_send(mbuf_pool, (char *)(udphdr+1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
				//printf("ustack_send\n");
				rte_pktmbuf_free(txbuf);
#endif
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }

    return 0;
}