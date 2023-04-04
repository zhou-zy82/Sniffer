
#include "analyse.h"


// 链路层
int analyse::analyse_frame(const u_char *pkt, pktdata *data){
    pktInitialAddress = pkt;
    struct _ethheader *ethh = (struct _ethheader*)pkt;
    data->ethh = (struct _ethheader *)malloc(sizeof(struct _ethheader)); // 预先分配空间
    for(int i=0; i<6; i++){
        data->ethh->src[i] = ethh->src[i];
        data->ethh->dst[i] = ethh->dst[i];
    } // 获取源MAC、目的MAC
    data->ethh->type = ntohs(ethh->type); // 将数据包的网络字节序转换为主机字节序

    // 判断ARP or IP
    switch (data->ethh->type) {
    case PROTO_ARP:
        return analyse_arp((u_char *)pkt + 14, data);
        break;
    case PROTO_IP:
        return analyse_ip((u_char*)pkt+14,data);
        break;
    case PROTO_IP6:
        return analyse_ip6((u_char*)pkt+14,data);
        break;
    default:
        return -1;
        break;
    }
    return 0;
}

int analyse::analyse_arp(const u_char *pkt, pktdata *data){
    struct _arpheader *arph = (struct _arpheader *)pkt;
    data->arph = (struct _arpheader *)malloc(sizeof(struct _arpheader));
    for(int i=0; i<6; i++){
        if (i<4){
            data->arph->srcip[i] = arph->srcip[i];
            data->arph->dstip[i] = arph->dstip[i];
        }
        data->arph->srcmac[i] = arph->srcmac[i];
        data->arph->dstmac[i] = arph->dstmac[i];
    } // 获取源MAC、目的MAC、源IP、目的IP
    data->arph->htype = ntohs(arph->htype);
    data->arph->ptype = ntohs(arph->ptype);
    data->arph->hsize = arph->hsize;
    data->arph->psize = arph->psize;
    data->arph->op = ntohs(arph->op);

    strcpy(data->pkttype,"ARP");
    return 1;
}

int analyse::analyse_ip(const u_char *pkt, pktdata *data){
    struct _ipheader *iph = (struct _ipheader *)pkt;
    data->iph = (struct _ipheader *)malloc(sizeof(struct _ipheader));
    data->iph->ver = iph->ver;
    data->iph->ihl = iph->ihl;
    int iplen = iph->ihl * 4; //ip头长度（字节长度）
    data->iph->tlen = ntohs(iph->tlen);
    data->iph->identify = ntohs(iph->identify);
    data->iph->flags_fo = ntohs(iph->flags_fo);
    data->iph->ttl = iph->ttl;
    data->iph->proto = iph->proto;
    data->iph->crc = ntohs(iph->crc);
    for (int i=0; i<4; i++){
        data->iph->src_addr[i] = iph->src_addr[i];
        data->iph->des_addr[i] = iph->des_addr[i];
    }
    data->iph->op_pad = ntohl(iph->op_pad);
    switch (iph->proto) {
    case PROTO_ICMP:
        return(analyse_icmp((u_char *)iph+iplen,data));
        break;
    case PROTO_UDP:
        return(analyse_udp((u_char *)iph+iplen,data));
        break;
    case PROTO_TCP:
        return(analyse_tcp((u_char *)iph+iplen,data));
        break;
    default :
        return -1;
        break;
    }
    return 0;
}

int analyse::analyse_ip6(const u_char *pkt, pktdata *data){
    struct _ipheader6 *iph6 = (struct _ipheader6*)pkt;
    data->iph6 = (struct _ipheader6*)malloc(sizeof(struct _ipheader6));
//    data->iph6->ver = iph6->ver;
//    data->iph6->flowtype = iph6->flowtype;
//    data->iph6->flowid = iph6->flowid;
    data->iph6->tlen = ntohs(iph6->tlen);
    data->iph6->nh = iph6->nh;
    data->iph6->hlimit = iph6->hlimit;
    for (int i=0; i<8; i++){
        data->iph6->src[i] = ntohs(iph6->src[i]);
        data->iph6->dst[i] = ntohs(iph6->dst[i]);
    }
    strcpy(data->pkttype,"IPv6");
    switch (iph6->nh) {
    case PROTO_UDP:
        qDebug() << "ipv6 UDP";
        return(analyse_udp((u_char *)iph6+40,data));
        break;
    case PROTO_TCP:
        qDebug() << "ipv6 TCP";
        return(analyse_tcp((u_char *)iph6+40,data));
        break;
    default :
        return -1;
        break;
    }
    return 0;
}

int analyse::analyse_icmp(const u_char *pkt, pktdata *data){
    struct _icmpheader *icmph = (struct _icmpheader*)pkt;
    data->icmph = (struct _icmpheader*)malloc(sizeof(struct _icmpheader));
    data->icmph->type = icmph->type;
    data->icmph->code = icmph->code;
    data->icmph->seq = ntohs(icmph->seq);
    data->icmph->chksum = ntohs(icmph->chksum);
    data->icmph->identify = ntohs(icmph->identify);
    strcpy(data->pkttype,"ICMP");
    return 1;
}

int analyse::analyse_udp(const u_char *pkt, pktdata *data){
    struct _udpheader *udph = (struct _udpheader*)pkt;
    data->udph = (struct _udpheader*)malloc(sizeof(struct _udpheader));
    data->udph->src_port = ntohs(udph->src_port);
    data->udph->des_port = ntohs(udph->des_port);
    data->udph->len = ntohs(udph->len);
    data->udph->crc = ntohs(udph->crc);
    strcpy(data->pkttype,"UDP");
    return 1;
}

int analyse::analyse_tcp(const u_char *pkt, pktdata *data){
    struct _tcpheader *tcph = (struct _tcpheader*)pkt;
    data->tcph = (struct _tcpheader*)malloc(sizeof(struct _tcpheader));
    data->tcph->src_port = ntohs(tcph->src_port);
    data->tcph->des_port = ntohs(tcph->des_port);
    data->tcph->seq_num = ntohl(tcph->seq_num);
    data->tcph->ack_num = ntohl(tcph->ack_num);
    data->tcph->th_offx2 = tcph->th_offx2;
    data->tcph->th_flags = tcph->th_flags;
    data->tcph->wind = ntohs(tcph->wind);
    data->tcph->check_sum = ntohs(tcph->check_sum);
    data->tcph->ur_point = ntohs(tcph->ur_point);
    data->tcph->op_pad = ntohl(tcph->op_pad);
    //HTTP筛选
    if(data->tcph->src_port == 80 || data->tcph->des_port == 80)
    {

        u_char *httpdata = (u_char *)tcph + TH_OFF(tcph) * 4;
        const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
        u_char *httph;

        for(int i = 0 ; i < 4 ; i ++){
            httph = (u_char *)strstr((char *)httpdata,token[i]);
            if(httph){
                strcpy(data->pkttype, "HTTP");
                data->isHttp = true;
                int size = data->len - ((u_char *)httpdata - pktInitialAddress);
                data->httpsize = size;
                data->apph = (u_char *)malloc(size * sizeof(u_char));
                for(int j = 0; j < size; j++){
                    data->apph[j] = httpdata[j];
                }

                return 1;
            }
        }

        strcpy(data->pkttype,"TCP");
    }
    else
        strcpy(data->pkttype,"TCP");
    return 1;
}
