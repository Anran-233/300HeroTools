QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
	patch2.cpp

HEADERS += \
    mainwindow.h \
	patch2.h

FORMS += \
    mainwindow.ui

TRANSLATIONS += \
    PigFriend_zh_CN.ts

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resource.qrc

# 版本信息
VERSION = 1.0.0.0
# 文件图标
RC_ICONS += icon_exe.ico
# 公司名称
QMAKE_TARGET_COMPANY = "Anran233���޿ɰ���˾"
# 产品名称
QMAKE_TARGET_PRODUCT = "���Ⱥ�ѹ۲�վ����������"
# 文件说明
QMAKE_TARGET_DESCRIPTION = "�����Զ����������Ⱥ�ѹ۲�վ��300Ӣ�۲���"
# 版权信息
QMAKE_TARGET_COPYRIGHT = "Copyright (C) 2023 Anran233."
# 中文（简体）
RC_LANG = 0x0004
