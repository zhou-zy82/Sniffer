
#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QThread>
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <Protocolhead.h>
#include <QMutex>



class capthread : public QThread
{
    Q_OBJECT
public:
    capthread(pcap_t *pkthandle, pktdataVec &datapktlink, dataVec &datacharlink, pcap_dumper_t *dumpfile);
    void stop();
protected:
    void run();
private:
    QMutex lock;
    volatile bool stopped;
    pcap_t *pkthandle;
    pktdataVec &datapktlink;
    dataVec &datacharlink;
    pcap_dumper_t *dumpfile;
signals:
    void addOneCaptureLine(QString timestr, QString srcmac, QString dstmac, QString pktlen, QString ptype, QString srcip, QString dstip);
};

#endif // CAPTHREAD_H
