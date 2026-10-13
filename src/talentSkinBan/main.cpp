#include <QVector>
#include <QString>
#include <QMap>
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QDataStream>
#include <QDateTime>
#include <QtZlib/zlib.h>

// DAT数据
struct SDatData {
    int         type    { 0 };      // 类型: 0.为空值; 1.整数型; 2.浮点型; 3.字符型;
    long long   Int     { 0 };      // 整数型
    float       Float   { 0.0f };   // 浮点型
    QString     Str     { "" };     // 字符型
};
typedef QVector<QVector<SDatData> > DATLIST;    // DAT数据表

// DPK数据
struct SDpkData {
    int     column  { 0 };  // 所在列号
    int     index1  { 0 };  // 整数索引值1
    int     index2  { 0 };  // 整数索引值2
    QString indexS  { "" }; // 字符索引值
    int     type    { 0 };  // 类型: 0.缺省值; 1.整数型; 2.浮点型; 3.字符型;
    QString data    { "" }; // 储存数据(默认均转换为字符串保存)
};
struct DPKLIST{
    int mode{ 0 };          // 索引模式: 0.首列索引; 1.一二索引; 2.一三索引; 3.字符索引;
    QVector<SDpkData> list; // DPK数据列表
};  // DPK数据表

//
struct STalentInfo {
    long long id = 0;
    long long level = 0;
    QString name;
};

struct STalentSkin {
    long long id;
    long long level;
    long long no;
    QString name;
    DPKLIST dpk;
};

int ReadDatData(const char *datData, const int &datDataLen, DATLIST &datList)
{
    const int&& int_max{ 0x3fffffff };
    int&& index{ 0 };
    datList.clear();

    /* 是否读取到结尾 */ auto lam_isend = [&](const int& i) -> bool {
        if (i < datDataLen) return false;
        if (i != datDataLen) index = int_max;
        return true;
    };

    /* 获取数据类型 */ auto lam_rtype = [](const char& data_c) -> int {
        char&& type_c = data_c & 0x07;
        if (type_c == 0x00) return 1;
        if (type_c == 0x05) return 2;
        if (type_c == 0x02) return 3;
        return 0;
    };

    /* 读取列号 */ auto lam_rcolumn = [&]() -> long long {
        int&& n{ 0 };
        long long&& nColumn{ 0 };
        do {
            if (lam_isend(index + n)) return 0;
            if (n == 0) nColumn |= (long long)(datData[index] & 0x78) >> 3;
            else        nColumn |= (long long)(datData[index + n] & 0x7f) << (7 * n - 3);
            n += 1;
        } while ((datData[index + n - 1] & 0x80) != 0);
        index += n;
        return nColumn;
    };

    /* 读取vint数据 */ auto lam_rvint = [&]() -> long long {
        int&& n{ 0 };
        long long&& nValue{ 0 };
        do {
            if (lam_isend(index + n)) return 0;
            nValue |= (long long)(datData[index + n] & 0x7f) << (7 * n);
            n += 1;
        } while ((datData[index + n - 1] & 0x80) != 0);
        index += n;
        return nValue;
    };

    /* 读取float数据 */ auto lam_rfloat = [&]() -> float {
        if (lam_isend(index + 3)) return 0.0f;
        float&& f{ 0.0f };
        for (int&& i = 0; i < 4; i++, index++) *((char*)&f + i) = datData[index];
        return f;
    };

    /* 读取str数据 */ auto lam_rstr = [&]() -> QString {
        int&& nStrLen = (int)lam_rvint();
        const char* data = &datData[index];
        index += nStrLen;
        if (lam_isend(index - 1)) return QString("");
        return QString::fromLocal8Bit(data, nStrLen);
    };

    // 读取行索引表
    QVector<int> lineIndexList;
    while (!lam_isend(index))
    {
        if (datData[index++] != char(0x0a)) return -1;
        int nLineLen = (int)lam_rvint();
        lineIndexList.push_back(index);
        lineIndexList.push_back(index += nLineLen);
    }
    if (index == int_max) return -1;

    // 读取每行数据
    int&& nColumnMax{ 0 };
    datList.resize(lineIndexList.size() / 2);
    for (int&& nRowNum{ 0 }; nRowNum < datList.size(); nRowNum++)
    {
        index = lineIndexList[nRowNum * 2];
        int& indexEnd = lineIndexList[nRowNum * 2 + 1];
        while (index < indexEnd)
        {
            // 读取单个数据
            int&& type = lam_rtype(datData[index]);
            int nColumnNum = (int)lam_rcolumn();
            if (nColumnNum > datList[nRowNum].size())
            {
                datList[nRowNum].resize(nColumnNum);
                datList[nRowNum].back().type = type;
                if (type == 1)      datList[nRowNum].back().Int = lam_rvint();
                else if (type == 2) datList[nRowNum].back().Float = lam_rfloat();
                else if (type == 3) datList[nRowNum].back().Str = lam_rstr();
            }
            else index = int_max;
        }
        if (datList[nRowNum].size() > nColumnMax) nColumnMax = datList[nRowNum].size();
        if (lam_isend(index)) break;
    }
    if (index == int_max) datList.clear();
    else for (auto& datLine : datList) datLine.resize(nColumnMax);
    return index == int_max ? -1 : 0;
}

int WriteDpkData(DPKLIST &dpkList, QByteArray &dpkData)
{
    int nSize;
    dpkData.clear();
    dpkData.append("DPK", 4);
    dpkData.append((char*)&dpkList.mode, 4);
    dpkData.append((char*)&(nSize = dpkList.list.size()), 4);

    /* 写入索引信息 */ auto lam_windex = [&](SDpkData& data) {
        if (dpkList.mode == 0) {
            dpkData.append((char*)&data.column, 4);
            dpkData.append((char*)&data.index1, 4);
        }
        else if (dpkList.mode == 1) {
            dpkData.append((char*)&data.column, 4);
            dpkData.append((char*)&data.index1, 4);
            dpkData.append((char*)&data.index2, 4);
        }
        else if (dpkList.mode == 2) {
            dpkData.append((char*)&data.column, 4);
            dpkData.append((char*)&data.index1, 4);
            dpkData.append((char*)&data.index2, 4);
        }
        else if (dpkList.mode == 3) {
            dpkData.append((char*)&data.column, 4);
            QByteArray&& str = data.indexS.toLocal8Bit();
            dpkData.append((char*)&(nSize = str.size()), 4);
            dpkData.append(str);
        }
    };

    /* 读取储存数据 */ auto lam_wdata = [&](SDpkData& data) {
        dpkData.push_back(char(data.type - 1));
        if (data.type == 1) {
            int&& n = data.data.toInt();
            dpkData.append((char*)&n, 4);
        }
        else if (data.type == 2) {
            float&& f = data.data.toFloat();
            dpkData.append((char*)&f, 4);
        }
        else if (data.type == 3) {
            QByteArray&& str = data.data.toLocal8Bit();
            dpkData.append((char*)&(nSize = str.size()), 4);
            dpkData.append(str);
        }
    };

    for (auto& data : dpkList.list)
    {
        lam_windex(data);
        lam_wdata(data);
    }
    return 0;
}

QByteArray ReadFile(QString path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    auto data = file.readAll();
    file.close();
    return data;
}

void WriteFile(QString path, const QByteArray &data)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return;
    file.write(data);
    file.close();
}

int main(int , char **)
{
    //QDir::setCurrent("D:/JumpGame/300Hero");

    qDebug() << u8"===== 【Anran233】禁用修仙机缘皮肤特效补丁生成器 v2026.10.13 =====";

    qDebug() << u8"读取资源文件：talent_talentinfo_c.dat, talent_skin_c.dat";
    QByteArray talent_talentinfo_c_data, talent_skin_c_data;
    {
        const QString talent_talentinfo_c_patch("..\\excel\\talent_talentinfo_c.dat"), talent_skin_c_data_patch("..\\excel\\talent_skin_c.dat");
        QSet<QString> datSet{talent_talentinfo_c_patch, talent_skin_c_data_patch};
        for (int i = 0; i <= 99; ++i) {
            QString path = i ? QString("Data%1.jmp").arg(i) : QString("Data.jmp");
            QFile file(path);
            if (!file.exists()) break;
            if (!file.open(QIODevice::ReadOnly)) continue;
            if (file.size() >= 10485760) {
                int jmpNum;
                file.seek(50);
                file.read((char*)&jmpNum, 4);
                for (int i = 0; i < jmpNum; ++i) {
                    file.seek(i * 304 + 54);
                    QString strPatchPath = file.read(260).data();
                    if (!datSet.contains(strPatchPath)) continue;
                    int index;      // 索引位置
                    int compLen;    // 压缩数据长度
                    ulong fileLen;  // 文件数据长度
                    file.read((char*)&index, 4);
                    file.read((char*)&compLen, 4);
                    file.read((char*)&fileLen, 4);
                    file.seek(index);
                    auto comp = file.read(compLen);
                    auto &d = strPatchPath == talent_talentinfo_c_patch ? talent_talentinfo_c_data : talent_skin_c_data;
                    d.resize(fileLen);
                    int result = z_uncompress((uchar*)d.data(), &fileLen, (uchar*)comp.data(), compLen);
                    if (result == Z_OK){
                        d.resize(fileLen), datSet.remove(strPatchPath);
                        qDebug().noquote() << path << strPatchPath;
                    }
                    else d.clear();
                }
            }
            file.close();
            if (datSet.isEmpty()) break;
        }
    }
    if (talent_skin_c_data.isEmpty() || talent_skin_c_data.isEmpty()) {
        qDebug() << u8"失败：未找到资源文件，请将程序放在300英雄游戏目录下再启动！";
        system("pause");
        return -1;
    }
    else {
        qDebug() << u8"成功";
    }

    qDebug() << u8"读取机缘列表";
    QMap<QString, STalentSkin> talentskin;
    {
        QMap<long long, STalentInfo> talentinfo;
        const auto getSkinNo = [](const QString &str7, const QString &str10)->QString {
            for (int i = 1; i <= 999; ++i) {
                if (str10.contains(QString("skin%1.").arg(i))) return QString::number(i);
            }
            for (int i = 1; i <= 999; ++i) {
                if (str7.contains(QString("skin%1.").arg(i))) return QString::number(i);
            }
            return "";
        };

        DATLIST talent_talentinfo_c;
        ReadDatData(talent_talentinfo_c_data.data(), talent_talentinfo_c_data.size(), talent_talentinfo_c);
        for (auto &line : talent_talentinfo_c) {
            if(line.size() >= 3) talentinfo.insert(line[0].Int, STalentInfo{line[0].Int, line[1].Int, line[2].Str});
        }

        DATLIST talent_skin_c;
        ReadDatData(talent_skin_c_data.data(), talent_skin_c_data.size(), talent_skin_c);
        for (auto &line : talent_skin_c) {
            if (line.size() < 26) continue;
            if (line[2].Int <= 0) continue;
            QString skinNo = getSkinNo(line[7].Str, line[10].Str);
            QString key = QString("%1_%2_%3").arg(line[0].Int).arg(line[2].Int).arg(skinNo);
            auto &skin = talentskin[key];
            skin.id = line[0].Int;
            skin.level = talentinfo.value(skin.id).level;
            skin.no = line[1].Int;
            if (skin.name.isEmpty()) skin.name = line[3].Str;
            if (skin.name.isEmpty()) skin.name = talentinfo.value(skin.id).name + (skinNo.isEmpty() ? "" : QString(u8"（皮肤%1）").arg(skinNo));
            skin.dpk.mode = 1;
            int index1 = (int)line[0].Int;
            int index2 = (int)line[1].Int;
            skin.dpk.list.append(SDpkData{7, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{8, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{9, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{10, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{11, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{12, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{15, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{16, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{17, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{18, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{19, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{20, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{21, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{22, index1, index2, "", 3, ""});
            skin.dpk.list.append(SDpkData{23, index1, index2, "", 1, "0"});
            skin.dpk.list.append(SDpkData{24, index1, index2, "", 1, "0"});
        }
    }
    if (talentskin.isEmpty()) {
        qDebug() << u8"失败：未读取到任何机缘皮肤！";
        system("pause");
        return -1;
    }
    else {
        qDebug() << u8"成功";
    }

    qDebug() << u8"正在打包动态补丁";
    {
        auto skinList = talentskin.values();
        std::sort(skinList.begin(), skinList.end(), [](const STalentSkin &skin1, const STalentSkin &skin2)->bool{
            if (skin1.level != skin2.level) return skin1.level < skin2.level;
            if (skin1.id != skin2.id) return skin1.id < skin2.id;
            return skin1.no < skin2.no;
        });

        const QByteArray patch = "..\\excel\\talent_skin_c.dpk";
        const auto date = QDateTime::currentDateTime();
        const QMap<int, QString> levelMap {{1,u8"凡品"},{2,u8"玄品"},{3,u8"天品"},{4,u8"仙品"}};
        const auto checkKey = [](QString name)->QString {
            static QSet<QString> keys;
            name.remove(' ').remove(';').remove(':').remove('#');
            name.replace(QChar(u'['), QChar(u'【')).replace(QChar(u']'), QChar(u'】'));
            name.replace(QChar(u'-'), QChar(u'·'));
            while(keys.contains(name)) name.append("_");
            keys.insert(name);
            return name;
        };

        QByteArray gpk;
        QDataStream stream(&gpk, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        // 基础信息
        stream.writeRawData("GPK", 4);
        stream << quint16(3) << quint16(0);
        stream << "【Anran233】禁用修仙机缘皮肤特效补丁";
        stream << "Anran233";
        stream << date.toString("yyyy.MM.dd").toUtf8();
        stream << "sbty的修仙机缘特效越来越逆天，又卡又挡视野的，搞个补丁把皮肤特效全禁用。\n"
                  "不想禁的皮肤（比如自己要用的皮肤）可以找到对应子补丁去掉勾就行。\n"
                  "本补丁由【禁用修仙机缘皮肤特效补丁生成器】自动生成，后续TY添加了新皮肤，就自己用生成器更新补丁\n"
                  "这个补丁和补丁的生成器下载地址在 https://gitee.com/anran_233/300HeroTools/raw/main/data/talentSkinBan.zip";
        // 预览图
        stream << quint32(1);
        stream << ReadFile(":/img.png");
        // 子补丁
        stream << skinList.size();
        for (int i = 0; i < skinList.size(); ++i) {
            auto &skin = skinList[i];
            stream << checkKey(QString(u8"【禁用】【%1】【%2】%3").arg(levelMap.value(skin.level, u8"特殊")).arg(skin.id).arg(skin.name)).toLocal8Bit();
            stream << quint32(0);
            stream << quint8(1);
            stream << quint32(1);
            stream << quint32(i);
            qDebug().noquote() << levelMap.value(skin.level, u8"特殊") << skin.id << skin.name;
        }
        // 补丁文件
        stream << skinList.size();
        for (int i = 0; i < skinList.size(); ++i) {
            auto &skin = skinList[i];
            QByteArray dpk;
            WriteDpkData(skin.dpk, dpk);
            QByteArray comp(z_compressBound(dpk.size()), '\0');
            ulong compLen = comp.size();
            int result = z_compress((uchar*)comp.data(), &compLen, (uchar*)dpk.data(), dpk.size());
            if (result == Z_OK) {
                comp.resize(compLen);
                stream << patch;
                stream << quint32(0);
                stream << quint32(dpk.size());
                stream << comp;
            }
            else {
                qDebug().noquote() << u8"失败：" << result << skin.name;
                stream << patch;
                stream << quint32(0);
                stream << quint32(0);
                stream << quint32(0);
            }
        }
        WriteFile(u8"./Patch/【Anran233】禁用修仙机缘皮肤特效补丁.gpk", gpk);
    }

    qDebug() << u8"成功打包补丁：【Anran233】禁用修仙机缘皮肤特效补丁.gpk";
    qDebug() << u8"成功将补丁安装在Patch文件夹中！";
    system("pause");

    return 0;
}
