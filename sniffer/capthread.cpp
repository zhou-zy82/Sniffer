
#include "capthread.h"
#include <analyse.h>
#include <QTextStream>
#include <QDebug>

capthread::capthread(pcap_t *pkthandle, pktdataVec &datapktlink, dataVec &datacharlink, pcap_dumper_t *dumpfile):
    datapktlink(datapktlink),datacharlink(datacharlink)
{
    stopped = false;
    this->pkthandle = pkthandle;
    this->dumpfile = dumpfile;
}

void capthread::run()
{
    int res;
    struct tm *ltime; // 获取当前日期和时间
    time_t local_utc; // 获取utc时间
    struct pcap_pkthdr *header; // 数据包头
    const u_char *pkt_data = NULL; // 网络中收到的字节流数据
    u_char *pkt_data0;

    while(stopped == false && (res = pcap_next_ex(pkthandle, &header, &pkt_data)) >= 0){

        if (res == 0) // 读取超时
            continue;

        struct _pktdata *data = (struct _pktdata*)malloc(sizeof(struct _pktdata));
        data->isHttp = false;
        memset(data,0,sizeof(struct _pktdata)); // data初始化为全0
        data->len = header->len;

        // analyse_frame返回值为-1，即出错或不被处理的其他类型数据包
        analyse* fc = new analyse;
        if(fc->analyse_frame(pkt_data, data) < 0)
            continue;

        // 数据包临时保存
        if (dumpfile != NULL){

            pcap_dump((u_char *)dumpfile, header, pkt_data);
        }

        // 将本地化后的数据放入一个链表
        pkt_data0 = (u_char *)malloc(header->len * sizeof(u_char));
        memcpy(pkt_data0, pkt_data, header->len);
        datapktlink.push_back(data);
        datacharlink.push_back(pkt_data0);

        // 获得时间(UTC时间转换)
        local_utc = header->ts.tv_sec;
        ltime = localtime(&local_utc);
        data->time[0] = ltime->tm_year + 1900;
        data->time[1] = ltime->tm_mon + 1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;
        // 获取时间戳
        QString timestr;
        QTextStream(&timestr) << data->time[0] << "/" << data->time[1] << "/" << data->time[2]
                              << " " << data->time[3] << ":" << data->time[4]
                              << ":" << data->time[5];

        // 获取源MAC
        QString srcmac;
        char *buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", data->ethh->src[0], data->ethh->src[1],
                data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
        srcmac = QString(QLatin1String(buf));

        // 获取目的MAC
        QString dstmac;
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", data->ethh->dst[0], data->ethh->dst[1],
                data->ethh->dst[2], data->ethh->dst[3], data->ethh->dst[4], data->ethh->dst[5]);
        dstmac = QString(QLatin1String(buf));

        // 获取协议类型
        QString ptype = QString(data->pkttype);

        // 获取源IP
        QString srcip;
        if(data->ethh->type == PROTO_ARP){
            sprintf(buf, "%d.%d.%d.%d", data->arph->srcip[0], data->arph->srcip[1], data->arph->srcip[2], data->arph->srcip[3]);
           srcip = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == PROTO_IP){
           sprintf(buf, "%d.%d.%d.%d", data->iph->src_addr[0], data->iph->src_addr[1], data->iph->src_addr[2], data->iph->src_addr[3]);
           srcip = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == PROTO_IP6){
           sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", data->iph6->src[0], data->iph6->src[1], data->iph6->src[2], data->iph6->src[3],
                   data->iph6->src[4], data->iph6->src[5], data->iph6->src[6], data->iph6->src[7]);
           srcip = QString(QLatin1String(buf));
        }

        // 获取目的IP
        QString dstip;
        if(data->ethh->type == PROTO_ARP){
           sprintf(buf, "%d.%d.%d.%d", data->arph->dstip[0], data->arph->dstip[1], data->arph->dstip[2], data->arph->dstip[3]);
           dstip = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == PROTO_IP){
           sprintf(buf, "%d.%d.%d.%d", data->iph->des_addr[0], data->iph->des_addr[1], data->iph->des_addr[2], data->iph->des_addr[3]);
           dstip = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == PROTO_IP6){
           sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", data->iph6->dst[0], data->iph6->dst[1], data->iph6->dst[2], data->iph6->dst[3],
                   data->iph6->dst[4], data->iph6->dst[5], data->iph6->dst[6], data->iph6->dst[7]);
           dstip = QString(QLatin1String(buf));
        }
        // 获取数据包长度
        QString pktlen = QString::number(data->len);


        emit addOneCaptureLine(timestr, srcmac, dstmac, pktlen, ptype, srcip, dstip);
        free(buf);
    }
}


void capthread::stop()
{
    QMutexLocker locker(&lock);
    stopped = true;
}
