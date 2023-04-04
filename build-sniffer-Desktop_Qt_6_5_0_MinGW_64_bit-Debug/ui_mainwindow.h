/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.5.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QWidget *formLayoutWidget;
    QFormLayout *formLayout;
    QLabel *dev;
    QLabel *rule;
    QComboBox *devs_choose;
    QLineEdit *filterline;
    QWidget *horizontalLayoutWidget;
    QHBoxLayout *horizontalLayout;
    QPushButton *start;
    QPushButton *end;
    QTreeWidget *packetanalysis;
    QTextEdit *packethex;
    QTableWidget *packetlist;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(1056, 692);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        formLayoutWidget = new QWidget(centralwidget);
        formLayoutWidget->setObjectName("formLayoutWidget");
        formLayoutWidget->setGeometry(QRect(0, 0, 391, 61));
        formLayout = new QFormLayout(formLayoutWidget);
        formLayout->setObjectName("formLayout");
        formLayout->setContentsMargins(0, 0, 0, 0);
        dev = new QLabel(formLayoutWidget);
        dev->setObjectName("dev");

        formLayout->setWidget(0, QFormLayout::LabelRole, dev);

        rule = new QLabel(formLayoutWidget);
        rule->setObjectName("rule");

        formLayout->setWidget(1, QFormLayout::LabelRole, rule);

        devs_choose = new QComboBox(formLayoutWidget);
        devs_choose->setObjectName("devs_choose");
        devs_choose->setMinimumContentsLength(1);

        formLayout->setWidget(0, QFormLayout::FieldRole, devs_choose);

        filterline = new QLineEdit(formLayoutWidget);
        filterline->setObjectName("filterline");

        formLayout->setWidget(1, QFormLayout::FieldRole, filterline);

        horizontalLayoutWidget = new QWidget(centralwidget);
        horizontalLayoutWidget->setObjectName("horizontalLayoutWidget");
        horizontalLayoutWidget->setGeometry(QRect(440, 0, 195, 51));
        horizontalLayout = new QHBoxLayout(horizontalLayoutWidget);
        horizontalLayout->setObjectName("horizontalLayout");
        horizontalLayout->setContentsMargins(0, 0, 0, 0);
        start = new QPushButton(horizontalLayoutWidget);
        start->setObjectName("start");

        horizontalLayout->addWidget(start);

        end = new QPushButton(horizontalLayoutWidget);
        end->setObjectName("end");

        horizontalLayout->addWidget(end);

        packetanalysis = new QTreeWidget(centralwidget);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        packetanalysis->setHeaderItem(__qtreewidgetitem);
        packetanalysis->setObjectName("packetanalysis");
        packetanalysis->setGeometry(QRect(10, 359, 271, 281));
        packethex = new QTextEdit(centralwidget);
        packethex->setObjectName("packethex");
        packethex->setGeometry(QRect(300, 359, 741, 281));
        packetlist = new QTableWidget(centralwidget);
        if (packetlist->columnCount() < 8)
            packetlist->setColumnCount(8);
        packetlist->setObjectName("packetlist");
        packetlist->setEnabled(true);
        packetlist->setGeometry(QRect(10, 80, 1031, 271));
        packetlist->setEditTriggers(QAbstractItemView::NoEditTriggers);
        packetlist->setSelectionMode(QAbstractItemView::SingleSelection);
        packetlist->setSelectionBehavior(QAbstractItemView::SelectRows);
        packetlist->setColumnCount(8);
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 1056, 26));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        dev->setText(QCoreApplication::translate("MainWindow", "\347\275\221\345\215\241", nullptr));
        rule->setText(QCoreApplication::translate("MainWindow", "\350\247\204\345\210\231", nullptr));
        devs_choose->setCurrentText(QString());
        devs_choose->setPlaceholderText(QCoreApplication::translate("MainWindow", "\350\257\267\351\200\211\346\213\251\344\270\200\344\270\252\347\275\221\345\215\241", nullptr));
        filterline->setPlaceholderText(QCoreApplication::translate("MainWindow", "\350\257\267\350\276\223\345\205\245\350\247\204\345\210\231", nullptr));
        start->setText(QCoreApplication::translate("MainWindow", "\345\274\200\345\247\213", nullptr));
        end->setText(QCoreApplication::translate("MainWindow", "\347\273\223\346\235\237", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
