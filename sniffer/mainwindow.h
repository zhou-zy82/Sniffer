
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QApplication>
#include <pcap.h>
#include <capthread.h>
#include <QAction>
#include <QMenu>
#include <QIcon>
#include <QFileDialog>
#include <QFile>
#include <QCloseEvent>




QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow

{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

// function
    int devs_get(); //网卡捕获
    int startcap(); //数据包捕获
    void showHexData(u_char*, int len); // 显示十六进制内容
    void createActions();
    void createMenus();
    bool saveFile(const QString &filename); //将临时数据文件保存到指定文件中
    void closeEvent(QCloseEvent *event);


//data
    int devcount;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filepath[512]; // 储存文件路径
    pcap_dumper_t *dumpfile;
    pcap_t *pkthandle;
    capthread *capth;

    pktdataVec datapktLink;
    dataVec dataCharLink;
    int RowCount;
    bool isFileSaved;



private slots:
    void on_start_clicked();
    void on_end_clicked();
    void showpktanalyse(int row);
    void slotsave();
    void slotopen();
    void updatePktList(QString timestr, QString srcmac, QString dstmac, QString len, QString ptype, QString srcip, QString dstip);


private:
    Ui::MainWindow *ui;
    QAction *openAction;
    QAction *saveAction;
    QAction *exitAction;
    QAction *bootCheatAction;
    QMenu *fileMenu;
    QMenu *cheatMenu;
};

#endif // MAINWINDOW_H
