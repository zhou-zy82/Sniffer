
#ifndef ANALYSE_H
#define ANALYSE_H

#include <pcap.h>
#include <Protocolhead.h>
#define HAVE_REMOTE
#include <remote-ext.h>
#include <winsock.h>
#include <QDebug>



class analyse
{
public:
    int analyse_frame(const u_char *pkt, pktdata *data);
    int analyse_arp(const u_char *pkt, pktdata *data);
    int analyse_ip(const u_char *pkt, pktdata *data);
    int analyse_ip6(const u_char *pkt, pktdata *data);
    int analyse_icmp(const u_char *pkt, pktdata *data);
    int analyse_tcp(const u_char *pkt, pktdata *data);
    int analyse_udp(const u_char *pkt, pktdata *data);
private:
    const u_char *pktInitialAddress;  //数据包的起始地址
};

#endif // ANALYSE_H
