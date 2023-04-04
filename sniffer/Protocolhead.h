
#ifndef PROTOCOLHEAD_H
#define PROTOCOLHEAD_H

#include <vector>
#include<iostream>

//逐层分解数据包
// u_char:	1字节，8位
// u_short:	2字节，16位
// u_int:	4字节，32位

//数据链路层MAC帧-固定14字节
typedef struct _ethheader
{
    u_char dst[6]; // 目的MAC6字节
    u_char src[6]; // 源MAC6字节
    u_short type; // 类型2字节
}ethheader;

//链路层下层协议类型
#define PROTO_IP 0x0800
#define PROTO_IP6 0x86dd
#define PROTO_ARP 0X0806

//ARP协议
typedef struct _arpheader
{
    u_short htype; // 硬件类型2字节
    u_short ptype; // 协议类型2字节
    u_char hsize; // 硬件地址长度1字节
    u_char psize; // 协议地址长度1字节
    u_short op; // op字段（1：请求；2：应答）
    u_char srcmac[6]; // 发送方MAC地址6字节
    u_char srcip[4]; // 发送方IP地址4字节
    u_char dstmac[6]; // 接收方MAC地址6字节
    u_char dstip[4]; // 接收方IP地址4字节
}arpheader;

//网络层IP数据报
//IPv4数据报-首部固定20字节
typedef struct _ipheader
{
    u_char ver:4,ihl:4; // 版本（4 bits）+首部长度（4 bits）
    u_char tos; // 区分服务（Type of Service, 8 bits）
    u_short tlen; // 总长（Total Length, 16 bits）=首部长度+数据长度，最大为65535字节（2^16-1）
    u_short identify; // 标识（Identify, 16 bits）
    u_short flags_fo; // 标志位（Flags 3 bits）+段偏移量（Fragment offset 13 bits）
    #define IP_RF 0x8000        //reservedfragment flag
    #define IP_DF 0x4000        //don't fragment flag
    #define IP_MF 0x2000        //more fragment flag
    #define IP_OFFMASK 0x1fff   //mask for fragment offset bits
    u_char ttl; // 存活时间（Time to Live, 8 bits）
    u_char proto; // 协议（Protocol, 8 bits）
    u_short crc; // 首部校验和（Header checkSum, 16 bits）
    u_char src_addr[4]; // 源地址（Source Address, 32 bits）
    u_char des_addr[4]; // 目的地址（Destination Address, 32 bits）
    u_int op_pad; // 可选字段与填充（Option * Padding, 32 bits）
}ipheader;


//IPv6数据报-首部固定40字节
typedef struct _ipheader6
{
    u_int ver:4,flowtype:8,flowid:20; // 版本（4 bits）+流分类（8 bits）+流标签（20 bits）
    u_short tlen; // 有效载荷长度（Payload Length, 16 bits）
    u_char nh; // 下一跳头部（Next Header, 8 bits）
    u_char hlimit; // 跳数限制（Hop Limit, 8 bits）
    u_short src[8]; // 源地址16字节
    u_short dst[8]; // 目的地址16字节
}ipheader6;

//IPv4下层协议类型
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

//ICMP协议
typedef struct _icmpheader
{
    u_char type; // 类型（8 bits）
    u_char code; // 代码（8 bits）
    u_short chksum; // 校验和 （16 bits）
    u_short identify; // 标识符（16 bits）
    u_short seq; // 序列号（16 bits）
}icmpheader;


//传输层UDP/TCP协议数据
//UDP数据包-首部固定8字节
typedef struct _udpheader
{
    u_short	src_port; // 源端口（Source Port, 16 bits）
    u_short	des_port; // 目的端口（Destination Port, 16 bits）
    u_short	len; // UDP数据包长度（Datagram Length, 2 bytes）
    u_short	crc; // 校验和（CheckSum, 16 bits）
}udpheader;
//TCP数据包-首部固定20字节
typedef struct _tcpheader
{
    u_short	src_port;// 源端口（2 bytes = 16 bits）
    u_short	des_port;// 目的端口(2 bytes = 16 bits)
    u_int	seq_num;// 序号（4 bytes = 32 bits）
    u_int	ack_num;// 确认号（4 bytes = 32 bits）
    u_char th_offx2;// 首部长度（4 bits）+保留（4 bits）+ CWR +ECE + URG + ACK + PSH + RST + SYN + FIN(各 1 bit)
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) // 前4位->首部长度
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) //按位或
    u_short	wind;// 窗口（2 bytes = 16 bits）
    u_short	check_sum;// 校验和（2 bytes = 16 bits）
    u_short ur_point;// 紧急指针（2 bytes = 16 bits）
    u_int	op_pad;	// 选项与填充（Option * Padding, 32 bits）
}tcpheader;


//应用层协议
//HTTP协议



//所保存的数据结构
typedef struct _pktdata
{
    char pkttype[8]; // 包类型
    int time[6]; // 时间戳
    int len; // 长度
    u_char* apph; //应用层包头
    bool isHttp = false; // HTTP数据包（端口号80）
    int httpsize;
    struct _ethheader *ethh; // 链路层包头
    struct _arpheader *arph; // ARP包头
    struct _ipheader *iph; // IPv4包头
    struct _ipheader6 *iph6; // IPv6包头
    struct _icmpheader *icmph; // ICMP包头
    struct _udpheader *udph; // UDP包头
    struct _tcpheader *tcph; // TCP包头
}pktdata;

//存储数据包分析得到的数据结构
typedef std::vector<pktdata *> pktdataVec;
//以字符串形式存储捕获的单个数据包所有内容
typedef std::vector<u_char *> dataVec;
#endif // PROTOCOLHEAD_H
