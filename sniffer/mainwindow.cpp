
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QDir>
#include <QDebug>
#include <vector>
#include <iostream>
#include <QColor>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("MySniffer");
    createActions();
    createMenus();
    isFileSaved = false;
    RowCount =0;
    // 参数初始化

    ui->packetlist->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                                            << tr("源MAC地址") << tr("目的MAC地址")
                                                            << tr("源IP地址") << tr("目的IP地址")
                                                             << tr("协议类型")<< tr("长度"));
    ui->packetlist->setColumnWidth(0, 60);
    ui->packetlist->setColumnWidth(1, 120);
    ui->packetlist->setColumnWidth(2, 180);
    ui->packetlist->setColumnWidth(3, 180);
    ui->packetlist->setColumnWidth(4, 180);
    ui->packetlist->setColumnWidth(5, 180);
    ui->packetlist->setColumnWidth(6, 120);
    ui->packetlist->setColumnWidth(7, 120);

    connect(ui->packetlist, SIGNAL(cellClicked(int,int)), this, SLOT(showpktanalyse(int)));
    ui->packetlist->verticalHeader()->setVisible(false);    // 隐藏列表头
    ui->packetanalysis->setColumnCount(1);

    // 设置协议解析窗口表头
    ui->packetanalysis->setHeaderLabel(QString("协议分析"));
    ui->packetanalysis->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->packetanalysis->header()->setStretchLastSection(false);

    ui->end->setEnabled(false);

    //网卡列表加载
    if(devs_get() != 0){
        QMessageBox::warning(this, "WARNING", "无网卡接口！", QMessageBox::Ok);
    }
    for(dev=alldevs; dev; dev=dev->next){
        if(dev->description)
            ui->devs_choose->addItem(QString("%1\n(%2)").arg(dev->description,dev->name));
    }

    capth = NULL;

}

MainWindow::~MainWindow()
{
    delete ui;
}

int MainWindow::devs_get()
{
    devcount = 0;
    if(pcap_findalldevs(&alldevs, errbuf) ==-1)
        return -1;
    for(dev=alldevs;dev;dev=dev->next)
        devcount++;
    return 0;

}

// 捕获数据包
int MainWindow::startcap()
{
    int dev_index = -1;
    u_int netmask; // 子网掩码
    struct bpf_program fcode;   //bpf_program结构体在编译BPF过滤规则函数执行成功后将会被填充


    dev_index = ui->devs_choose->currentIndex();  //获取选中的网卡序号
    qDebug() << dev_index;

    if(dev_index == -1){
        QMessageBox::warning(this, "WARNING", "请选择一个网卡接口！", QMessageBox::Ok);
        return -1;
    } //未选中网卡警告
    dev = alldevs;
    for(int i = 0; i < dev_index - 1; i++)
        dev = dev->next; //选中网卡
    pkthandle = pcap_open_live(dev->name,65536,1,1000,errbuf); //设备名，数据包长度，混杂模式，超时时间，错误信息

    if(pkthandle == NULL){
        QMessageBox::warning(this,"WARNING","网卡接口打开失败！",QMessageBox::Ok);
        pcap_freealldevs(alldevs); //释放接口列表
        alldevs = NULL;
        return -1;
    } //网卡打开失败警告

    if(pcap_datalink(pkthandle) != DLT_EN10MB){
        QMessageBox::warning(this,"WARNING","非以太网流量！",QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    } //非以太网流量警告

    // 获取接口第一个地址的子网掩码，如果接口没有地址，假设这个接口在C类网络中
    if(dev->addresses != NULL){
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
        netmask = 0xffffff;

    // 编译过滤器
    QString filterContent = ui->filterline->text(); // 获取输入的规则
    if(filterContent.isEmpty()){
        char filter[] = "";
        if(pcap_compile(pkthandle, &fcode, filter, 1, netmask) < 0){
            QMessageBox::warning(this, "WARNING", tr("无效规则，请检查语法！"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }
    } // 提示规则错误
    else{
        QByteArray ba = filterContent.toLatin1();
        char *filter = NULL;
        filter = ba.data();
        if(pcap_compile(pkthandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "WARNING", tr("无效规则，请检查语法！"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }

    }
    // 设置过滤器
    if(pcap_setfilter(pkthandle, &fcode) < 0){
        QMessageBox::warning(this, "WARNING", tr("过滤器设置错误！"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    // 储存文件
    QString path = QDir::currentPath();
    // qDebug() << path;
    QString direcPath = path + "/data";
    QDir dir(direcPath);
    if(!dir.exists() ){
        if(!dir.mkdir(direcPath)){
            QMessageBox::warning(this, "WARNING", tr("保存路径创建失败!"), QMessageBox::Ok);
            return -1;
        }
    }
    char starttime[30];
    struct tm *ltime;
    time_t time_utc;
    time (&time_utc);
    ltime = localtime(&time_utc);
    strftime(starttime,sizeof(starttime),"%Y%m%d %H%M%S",ltime);
    std::string str = direcPath.toStdString();
    strcpy(filepath, str.c_str());
    strcat(filepath, "/");
    strcat(filepath, starttime);
    strcat(filepath, ".pcap"); // 以开始时间命名文件（.pcap文件）
    qDebug() << "data saved path is:" << QString(filepath) << "\n";
    dumpfile =  pcap_dump_open(pkthandle, filepath);
    if(dumpfile == NULL){
        QMessageBox::warning(this, "WARNING", tr("捕获数据文件打开错误"), QMessageBox::Ok);
        return -1;
    }

    pcap_freealldevs(alldevs);
    alldevs = NULL;

    capth = new capthread(pkthandle, datapktLink, dataCharLink, dumpfile);
    connect(capth, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(updatePktList(QString, QString, QString, QString, QString, QString, QString)));
    capth->start();
    return 1;
}

// 点击开始按钮
void MainWindow::on_start_clicked()
{
    //如果已有数据，则提示先保存数据
    if(isFileSaved == false && RowCount != 0){
        int ans;
        ans = QMessageBox::information(this, "MySniffer", "当前数据尚未保存，是否进行保存？", QMessageBox::Save, QMessageBox::Cancel);
        if(ans == QMessageBox::Save){
            QString filename = QFileDialog::getSaveFileName(this,"另存为", ".", "Sniffer 捕获数据文件(*.pcap)");
            if(!filename.isEmpty())
                saveFile(filename);
        }
    }
    // 释放内存
    std::vector<pktdata *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++){
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free((*it)->iph6);
        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
        free(*kt);
    }
    pktdataVec().swap(datapktLink);
    dataVec().swap(dataCharLink);
    pcap_freealldevs(alldevs);
    alldevs = NULL;

    ui->packetanalysis->clear();
    ui->packethex->clear();
    saveAction->setEnabled(false);


    // 重新获取网络接口信息
    if(alldevs == NULL){
        if(devs_get() < 0){
            QMessageBox::warning(this,"WARNING","网卡接口获取失败！",QMessageBox::Ok);
            return;
        }
    }
    if(capth != NULL){
        delete capth;
        capth = NULL;
    }
    if(startcap() < 0)
        return;

    // 清空显示内容
    ui->packetlist->clearContents();
    ui->packetlist->setRowCount(0);
    ui->end->setEnabled(true);
    ui->start->setEnabled(false);
    // 设置文件保存标志为false
    isFileSaved = false;
}

// 更新pktlist
void MainWindow::updatePktList(QString timestr, QString srcmac, QString dstmac, QString len, QString ptype, QString srcip, QString dstip)
{
    RowCount = ui->packetlist->rowCount();
    ui->packetlist->insertRow(RowCount);
    QString orderNumber = QString::number(RowCount, 10);
    ui->packetlist->setItem(RowCount, 0, new QTableWidgetItem(orderNumber));
    ui->packetlist->setItem(RowCount, 1, new QTableWidgetItem(timestr));
    ui->packetlist->setItem(RowCount, 2, new QTableWidgetItem(srcmac));
    ui->packetlist->setItem(RowCount, 3, new QTableWidgetItem(dstmac));
    ui->packetlist->setItem(RowCount, 4, new QTableWidgetItem(srcip));
    ui->packetlist->setItem(RowCount, 5, new QTableWidgetItem(dstip));
    ui->packetlist->setItem(RowCount, 6, new QTableWidgetItem(ptype));
    ui->packetlist->setItem(RowCount, 7, new QTableWidgetItem(len));

    if(RowCount > 1)
    {
        ui->packetlist->scrollToItem(ui->packetlist->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
    }

    QColor color;
    if(ptype == "TCP"){
        color = QColor(199,237,204);
    }
    else if(ptype == "UDP"){
        color = QColor(250,249,222);
    }
    else if(ptype == "HTTP"){
        color = QColor(253,230,224);
    }
    else if(ptype == "ARP"){
        color = QColor(220,226,241);
    }
    else if(ptype == "ICMP"){
        color = QColor(234,234,239);
    }
    for(int i = 0; i < 8 ; i ++){
        ui->packetlist->item(RowCount,i)->setBackground(color);
    }
}

// 点击结束按钮
void MainWindow::on_end_clicked()
{
    // 设置按钮状态
    ui->start->setEnabled(true);
    ui->end->setEnabled(false);
    saveAction->setEnabled(true);
    // 停止抓包线程
    capth->stop();
    //关闭winpcap会话句柄，并释放其资源
    pcap_close(pkthandle);
}

// 文件保存
bool MainWindow::saveFile(const QString &filename)
{
    QString curFile = QString(filepath);
    if(curFile.isEmpty()){
        return false;
    }
    if(!QFile::copy(curFile, filename)){
        QMessageBox::warning(this, "WARNING", tr("文件保存失败!"), QMessageBox::Ok);
        return false;
    }
    QMessageBox::information(this, "File Save", tr("文件保存成功!"), QMessageBox::Ok);
    isFileSaved = true;
    return true;
}

// 十六进制内容显示
void MainWindow::showHexData(u_char *print_data, int print_len)
{
    QString tempnum,tempchar;
    QString oneline;
    tempchar = "  ";
    oneline = "";
    int i=0;
    for(; i < print_len ; i ++){
        if(i % 16 == 0)
            oneline += tempnum.asprintf("%04x  ",i); // 行号
        oneline += tempnum.asprintf("%02x ",print_data[i]);
        if(isprint(print_data[i]))
            tempchar += (QChar)print_data[i];
        else
            tempchar += "."; // 判断是否可打印，不可打印显示为"."
        if((i+1)%16 == 0){
            ui->packethex->append(oneline + tempchar);
            tempchar = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    ui->packethex->append(oneline + tempchar);
}

// 数据包分析模块显示
void MainWindow::showpktanalyse(int row){
    // 清空控件内容
    ui->packetanalysis->clear();
    ui->packethex->clear();

    struct _pktdata *mem_data = (struct _pktdata *)datapktLink[row];
    // 在编辑栏中要显示的数据包内容
    u_char *print_data = (u_char *)dataCharLink[row];
    int print_len = mem_data->len;
    showHexData(print_data, print_len);

    QString showStr;
    char buf[100];
    sprintf(buf, "接收到的第%d个数据包", row + 1);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->packetanalysis);
    root->setText(0, showStr);

    // MAC帧
    showStr = QString("链路层数据");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->src[0], mem_data->ethh->src[1],
            mem_data->ethh->src[2], mem_data->ethh->src[3], mem_data->ethh->src[4], mem_data->ethh->src[5]);
    showStr = "源MAC: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->dst[0], mem_data->ethh->dst[1],
            mem_data->ethh->dst[2], mem_data->ethh->dst[3], mem_data->ethh->dst[4], mem_data->ethh->dst[5]);
    showStr = "目的MAC: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", mem_data->ethh->type);
    showStr = "类型:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    // ARP/IPv4/IPv6
    if(mem_data->ethh->type == PROTO_ARP)
    {

        showStr = QString("ARP协议头");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, showStr);

        sprintf(buf, "硬件类型: 0x%04x", mem_data->arph->htype);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "协议类型: 0x%04x", mem_data->arph->ptype);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "硬件地址长度: %d", mem_data->arph->hsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "协议地址长度: %d", mem_data->arph->psize);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "操作码: %d", mem_data->arph->op);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mem_data->arph->srcmac[0], mem_data->arph->srcmac[1],
                mem_data->arph->srcmac[2], mem_data->arph->srcmac[3], mem_data->arph->srcmac[4], mem_data->arph->srcmac[5]);
        showStr = "发送方MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->srcip[0], mem_data->arph->srcip[1], mem_data->arph->srcip[2]
                ,mem_data->arph->srcip[3]);
        showStr = "发送方IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mem_data->arph->dstmac[0], mem_data->arph->dstmac[1],
                mem_data->arph->dstmac[2], mem_data->arph->dstmac[3], mem_data->arph->dstmac[4], mem_data->arph->dstmac[5]);
        showStr = "接收方MAC: " + QString(buf);
        QTreeWidgetItem *dstArpMac = new QTreeWidgetItem(level2);
        dstArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->dstip[0], mem_data->arph->dstip[1], mem_data->arph->dstip[2]
                ,mem_data->arph->dstip[3]);
        showStr = "接收方IP: " + QString(buf);
        QTreeWidgetItem *dstArpIp = new QTreeWidgetItem(level2);
        dstArpIp->setText(0, showStr);
    }
    else if(mem_data->ethh->type == PROTO_IP) // IPv4
    {
        showStr = QString("IP协议头");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "版本: 4");
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "IP首部长度: %d", mem_data->iph->ihl);
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "服务类型: %d", mem_data->iph->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "总长度: %d", mem_data->iph->tlen);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "标识: 0x%04x", mem_data->iph->identify);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        sprintf(buf, "标志(Reserved Fragment Flag): %d", (mem_data->iph->flags_fo & IP_RF) >> 15);
        showStr = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, showStr);

        sprintf(buf, "标志(Don't fragment Flag): %d", (mem_data->iph->flags_fo & IP_DF) >> 14);
        showStr = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, showStr);

        sprintf(buf, "标志(More Fragment Flag): %d", (mem_data->iph->flags_fo & IP_MF) >> 13);
        showStr = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, showStr);

        sprintf(buf, "段偏移: %d", mem_data->iph->flags_fo & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "生存期: %d", mem_data->iph->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "协议: %d", mem_data->iph->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "首部校验和: 0x%04x", mem_data->iph->crc);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->src_addr[0], mem_data->iph->src_addr[1], mem_data->iph->src_addr[2]
                ,mem_data->iph->src_addr[3]);
        showStr = "源IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->des_addr[0], mem_data->iph->des_addr[1], mem_data->iph->des_addr[2]
                ,mem_data->iph->des_addr[3]);
        showStr = "目的IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        // IPv4->ICMP/UDP/TCP
        if(mem_data->iph->proto == PROTO_ICMP)  //ICMP协议
        {
            //添加ICMP协议头
            showStr = QString("ICMP协议头");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, showStr);

            sprintf(buf, "类型: %d", mem_data->icmph->type);
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "代码: %d", mem_data->icmph->code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->icmph->chksum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "标识: 0x%04x", mem_data->icmph->identify);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "序列号: 0x%04x", mem_data->icmph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(mem_data->iph->proto == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->tcph->src_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->tcph->des_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", mem_data->tcph->seq_num);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", mem_data->tcph->ack_num);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", TH_OFF(mem_data->tcph) * 4, TH_OFF(mem_data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (mem_data->tcph->th_flags & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (mem_data->tcph->th_flags & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (mem_data->tcph->th_flags & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (mem_data->tcph->th_flags & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (mem_data->tcph->th_flags & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (mem_data->tcph->th_flags & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (mem_data->tcph->th_flags & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (mem_data->tcph->th_flags & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", mem_data->tcph->wind);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->tcph->check_sum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", mem_data->tcph->ur_point);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            sprintf(buf, "选项与填充: %x", mem_data->tcph->op_pad);
            showStr = QString(buf);
            QTreeWidgetItem *tcpOp = new QTreeWidgetItem(level5);
            tcpOp->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                level8->setText(0, showStr);

                QString content = "";
                u_char *httpps = mem_data->apph;
                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += (QChar)httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->iph->proto == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->udph->src_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->udph->des_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", mem_data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }
    else if(mem_data->ethh->type == PROTO_IP6) // IPv6
    {
        showStr = QString("IP协议头");
        QTreeWidgetItem *level7 = new QTreeWidgetItem(root);
        level7->setText(0, showStr);

        sprintf(buf, "版本: 6");
        showStr = QString(buf);
        QTreeWidgetItem *ip6Version = new QTreeWidgetItem(level7);
        ip6Version->setText(0, showStr);

//        sprintf(buf, "流类型: %d",mem_data->iph6->flowtype);
//        showStr = QString(buf);
//        QTreeWidgetItem *ip6FlowType = new QTreeWidgetItem(level7);
//        ip6FlowType->setText(0, showStr);

//        sprintf(buf, "流标签: %d",mem_data->iph6->flowid);
//        showStr = QString(buf);
//        QTreeWidgetItem *ip6FlowId = new QTreeWidgetItem(level7);
//        ip6FlowId->setText(0, showStr);

        sprintf(buf, "有效载荷长度: %d",mem_data->iph6->tlen);
        showStr = QString(buf);
        QTreeWidgetItem *ip6PayloadLength = new QTreeWidgetItem(level7);
        ip6PayloadLength->setText(0, showStr);

        sprintf(buf, "下一首部: 0x%02x",mem_data->iph6->nh);
        showStr = QString(buf);
        QTreeWidgetItem *ip6NextHeader = new QTreeWidgetItem(level7);
        ip6NextHeader->setText(0, showStr);

        sprintf(buf, "跳限制: %d",mem_data->iph6->hlimit);
        showStr = QString(buf);
        QTreeWidgetItem *ip6HopLimit = new QTreeWidgetItem(level7);
        ip6HopLimit->setText(0, showStr);

        sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", mem_data->iph6->src[0], mem_data->iph6->src[1],mem_data->iph6->src[2],mem_data->iph6->src[3],
                mem_data->iph6->src[4], mem_data->iph6->src[5], mem_data->iph6->src[6],mem_data->iph6->src[7]);
        showStr = "源地址: " + QString(buf);
        QTreeWidgetItem *ip6Src = new QTreeWidgetItem(level7);
        ip6Src->setText(0, showStr);

        sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", mem_data->iph6->dst[0], mem_data->iph6->dst[1],mem_data->iph6->dst[2],mem_data->iph6->dst[3],
                mem_data->iph6->dst[4], mem_data->iph6->dst[5], mem_data->iph6->dst[6],mem_data->iph6->dst[7]);
        showStr = "目的地址: " + QString(buf);
        QTreeWidgetItem *ip6Dest = new QTreeWidgetItem(level7);
        ip6Dest->setText(0, showStr);

        // IPv6->UDP/TCP
        if(mem_data->iph6->nh == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level9 = new QTreeWidgetItem(root);
            level9->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->tcph->src_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level9);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->tcph->des_port);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level9);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", mem_data->tcph->seq_num);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level9);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", mem_data->tcph->ack_num);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level9);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", TH_OFF(mem_data->tcph) * 4, TH_OFF(mem_data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level9);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level9);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (mem_data->tcph->th_flags & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (mem_data->tcph->th_flags & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (mem_data->tcph->th_flags & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (mem_data->tcph->th_flags & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (mem_data->tcph->th_flags & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (mem_data->tcph->th_flags & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (mem_data->tcph->th_flags & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (mem_data->tcph->th_flags & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", mem_data->tcph->wind);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level9);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->tcph->check_sum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level9);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", mem_data->tcph->ur_point);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level9);
            tcpUrgPtr->setText(0, showStr);

            sprintf(buf, "选项与填充: %x", mem_data->tcph->op_pad);
            showStr = QString(buf);
            QTreeWidgetItem *tcpOp = new QTreeWidgetItem(level9);
            tcpOp->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level11 = new QTreeWidgetItem(root);
                level11->setText(0, showStr);

                QString content = "";
                u_char *httpps = mem_data->apph;
                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level11->addChild(new QTreeWidgetItem(level11,QStringList(content)));
                            level11->addChild(new QTreeWidgetItem(level11,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            level11->addChild(new QTreeWidgetItem(level11,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += (QChar)httpps2[i];
                }
                level11->addChild(new QTreeWidgetItem(level11,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->iph6->nh == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level10 = new QTreeWidgetItem(root);
            level10->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->udph->src_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level10);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->udph->des_port);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level10);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", mem_data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level10);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level10);
            udpCrc->setText(0, showStr);
        }
    }
}

void MainWindow::createActions()
{
    openAction = new QAction(tr("打开"), this);
    openAction->setShortcut(QKeySequence::Open);
    openAction->setStatusTip(tr("打开历史捕获记录"));
    connect(openAction, SIGNAL(triggered()), this, SLOT(slotopen()));

    saveAction = new QAction(tr("保存"), this);
    saveAction->setShortcut(QKeySequence::Save);
    saveAction->setStatusTip(tr("保存本次捕获信息到文件"));
    saveAction->setEnabled(false);
    connect(saveAction, SIGNAL(triggered()), this, SLOT(slotsave()));

    exitAction = new QAction(tr("退出"), this);
    exitAction->setShortcut(tr("Ctrl+Q"));
    exitAction->setStatusTip(tr("退出程序"));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    int ret = QMessageBox::information(this, "MySniffer", tr("是否退出?"), QMessageBox::Ok, QMessageBox::No);
    if(ret == QMessageBox::Ok){
        if(isFileSaved == false && RowCount != 0){
            int ans;
            ans = QMessageBox::information(this, "MySniffer", tr("当前捕获数据尚未保存，是否保存？"), QMessageBox::Save, QMessageBox::Cancel);
            if(ans == QMessageBox::Save){
                QString filename = QFileDialog::getSaveFileName(this,tr("另存为"),".", tr("Sniffer 捕获数据文件(*.pcap)"));
                if(!filename.isEmpty())
                    saveFile(filename);
            }
        }
        //释放内存，避免内存泄漏
        std::vector<pktdata *>::iterator it;
        for(it = datapktLink.begin(); it != datapktLink.end(); it++){
            free((*it)->ethh);
            free((*it)->arph);
            free((*it)->iph);
            free((*it)->icmph);
            free((*it)->udph);
            free((*it)->tcph);
            free((*it)->apph);
            free((*it)->iph6);
            free(*it);
        }
        std::vector<u_char *>::iterator kt;
        for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
            free(*kt);
        }
        pktdataVec().swap(datapktLink);
        dataVec().swap(dataCharLink);
        event->accept();
    }
    else
        event->ignore();
}

void MainWindow::createMenus()
{
    fileMenu = this->menuBar()->addMenu(tr("文件"));
    fileMenu->addAction(openAction);
    fileMenu->addAction(saveAction);
    fileMenu->addAction(exitAction);
}

// 保存文件
void MainWindow::slotsave()
{
    QString filename = QFileDialog::getSaveFileName(this,tr("另存为"),".", tr("Sniffer 捕获数据文件(*.pcap)"));
    if(!filename.isEmpty())
        saveFile(filename);
}

// 从本地打开文件
void MainWindow::slotopen()
{
    //首先判断当前捕获到的数据包是否保存
    if(isFileSaved == false && RowCount != 0){
        int ans;
        ans = QMessageBox::information(this, "Sniffer", tr("当前数据尚未保存，是否保存?"), QMessageBox::Save, QMessageBox::Cancel);
        if(ans == QMessageBox::Save){
            QString filename = QFileDialog::getSaveFileName(this,tr("另存为"),".", tr("Sniffer 捕获数据文件(*.pcap)"));
            if(!filename.isEmpty())
                saveFile(filename);
        }
    }
    isFileSaved = true;//由于是打开已经保存的文件，因此置isFileSaved标志为true
    //清空容器中的数据包信息
    std::vector<pktdata *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++){
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
        free(*kt);
    }
    pktdataVec().swap(datapktLink);
    dataVec().swap(dataCharLink);

    ui->packetlist->clearContents();
    ui->packetlist->setRowCount(0);
    ui->packetanalysis->clear();
    ui->packethex->clear();
    ui->start->setEnabled(true);
    ui->end->setEnabled(false);
    saveAction->setEnabled(false);

    pcap_t *fp;
    char source[PCAP_BUF_SIZE];
    //获取要打开文件的文件名
    QString openfilename = QFileDialog::getOpenFileName(this, tr("打开文件"), ".", "Sniffer pkt(*.pcap)");
    std::string filestr = openfilename.toStdString();
    const char *openstr = filestr.c_str();
    if(pcap_createsrcstr(source,    //源字符串
                         PCAP_SRC_FILE,     //要打开的文件
                         NULL,      //远程主机
                         NULL,      //远程主机端口
                         openstr,   //我们要打开的文件名
                         errbuf
                         ) != 0)
    {
        QMessageBox::warning(this, "warning", tr("创建源字符串失败！"), QMessageBox::Ok);
        return;
    }
    /* 打开捕获文件 */
    if ( (fp= pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf) ) == NULL){
         QMessageBox::warning(this, "WARNING", tr("无法打开本地捕获文件！"), QMessageBox::Ok);
         return;
    }
    capth = new capthread(fp, datapktLink, dataCharLink, NULL);
    connect(capth, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(updatePktList(QString, QString, QString, QString, QString, QString, QString)));
    capth->start();
}
