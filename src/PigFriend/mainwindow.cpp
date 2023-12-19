#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "patch2.h"
#include <QDialog>
#include <QDebug>
#include <QColorDialog>
#include <QMessageBox>
#include <QPainter>
#include <QProgressDialog>
#include <QToolTip>
#include <QStackedWidget>
#include <QFileDialog>
#include <QThread>
#include <QKeyEvent>
#include <QJsonDocument>
#include <QJsonObject>
#include <QBuffer>
#include <QtZlib/zlib.h>

struct PatchItem {
    QByteArray patch;   ///< 补丁路径
    QByteArray data;    ///< 压缩数据
    qint32 compLen = 0; ///< 压缩大小
    qint32 fileLen = 0; ///< 文件大小
};

struct PatchScheme {
    int id = 0;         ///< 编号
    QByteArray name;    ///< 名称
    QByteArray info;    ///< 信息
    PatchItem imga;     ///< 贴图a
    PatchItem imgb;     ///< 贴图b
    PatchItem modela;   ///< 模型a
    PatchItem modelb;   ///< 模型b
};

QFont g_font;
const QByteArray g_patch{"..\\Anran233\\PigFriend\\schemes.json"};
const QMap<int, QString> g_names{
    {0, u8"默认"},
    {1, u8"向日葵"},
    {2, u8"樱花伞"},
    {3, u8"鲜血更衣"},
    {4, u8"神经兔"},
    {5, u8"doge"},
    {6, u8"花魁"},
    {7, u8"疯狂之月"},
    {8, u8"莹锤"},
    {9, u8"秋月炮"},
    {10, u8"伊丽莎白"},
    {11, u8"POP子与PIPI美"},
    {12, u8"斗鱼娘"},
    {13, u8"霍克"},
    {14, u8"邪神酱"},
    {15, u8"小狮子"},
    {16, u8"白之约定"},
    {17, u8"星歌"},
    {18, u8"祢豆子"},
    {19, u8"哲也二号"},
    {20, u8"点点"},
    {21, u8"杰克南瓜灯"},
    {22, u8"圣天使"},
    {23, u8"琳芙斯II"},
    {24, u8"星之眼"},
    {25, u8"小寿司"},
    {26, u8"WINNER"},
    {27, u8"Gamer"},
    {28, u8"WINNER[2021]"},
    {29, u8"小可"},
    {30, u8"无人机"},
    {31, u8"树(西兰花)"},
    {32, u8"武士刀"},
    {33, u8"卖萌兔"},
    {34, u8"永恒之刃"},
    {35, u8"暴食"},
    {36, u8"花生米"}
};

void GlobalInit() {
    static bool init = false;
    if (init) return;
    else init = true;
    g_font.setFamily(u8"微软雅黑");
    g_font.setPixelSize(100);
}

bool Texture(const bool &a, const int &id, Scheme &scheme, PatchItem &patch)
{
    // 获取贴图数据
    if (scheme.img.isNull()) scheme.render();
    QByteArray imgData;
    QBuffer buffer(&imgData);
    if (!buffer.open(QIODevice::WriteOnly)) return false;
    scheme.img.save(&buffer, "PNG");
    buffer.close();
    // 添加到patch
    ulong &&compLen = compressBound(imgData.size());
    patch.data.resize(compLen);
    if (compress((uchar*)patch.data.data(), &compLen, (uchar*)imgData.data(), imgData.size())) return false;
    patch.data.resize(compLen);
    patch.compLen = compLen;
    patch.fileLen = imgData.size();
    patch.patch = QString("..\\data\\character\\monster\\war_fyt\\war_yan\\war_yan_%1_name%2.png")
            .arg(a ? "a" : "b").arg(id, 2, 10, QChar('0')).toLocal8Bit();
    return true;
}

bool JumpX(const bool &a, const int &id, PatchItem &patch)
{
    struct BuffInfo {
        ulong headLen;
        ulong dataLen;
        ulong headCompLen;
        ulong dataCompLen;
    };
    // 打开jumpx文件
    QFile file(a ? ":/war_yan_a_skin.x" : ":/war_yan_b_skin.x");
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QByteArray &jumpx = file.readAll();
    file.close();
    // 读取信息
    const quint32 &jumpxSize = jumpx.size();
    if (jumpxSize < 88) return false;
    const char *jumpxData = jumpx.data();
    const quint32 &infoLen = *(quint32*)(jumpxData + 84);
    if (jumpxSize < 88 + infoLen + 16) return false;
    const BuffInfo &buffInfo = *(BuffInfo*)(jumpxData + 88 + infoLen);
    if (jumpxSize < 88 + infoLen + 16 + buffInfo.headCompLen + buffInfo.dataCompLen) return false;
    BuffInfo newInfo = buffInfo;
    QByteArray headData(buffInfo.headLen, '\0');
    if (uncompress((uchar*)headData.data(), &newInfo.headLen, (uchar*)(jumpxData + 88 + infoLen + 16), buffInfo.headCompLen)) return false;
    if (newInfo.headLen != buffInfo.headLen) return false;
    // 修改贴图
    headData.replace(QByteArray("_name00.png"), QString("_name%1.png").arg(id, 2, 10, QChar('0')).toLocal8Bit());
    newInfo.headCompLen = compressBound(newInfo.dataLen);
    QByteArray headComp(newInfo.headCompLen, '\0');
    if (compress((uchar*)headComp.data(), &newInfo.headCompLen, (uchar*)headData.data(), newInfo.headLen)) return false;
    // 合成新jumpx文件
    QByteArray newJumpx(jumpxData, 88 + infoLen);
    newJumpx.append((char*)&newInfo, 16);
    newJumpx.append(headComp.data(), newInfo.headCompLen);
    newJumpx.append(jumpxData + 88 + infoLen + 16 + buffInfo.headCompLen, buffInfo.dataCompLen);
    // 添加到patch
    ulong &&compLen = compressBound(newJumpx.size());
    patch.data.resize(compLen);
    if (compress((uchar*)patch.data.data(), &compLen, (uchar*)newJumpx.data(), newJumpx.size())) return false;
    patch.data.resize(compLen);
    patch.compLen = compLen;
    patch.fileLen = newJumpx.size();
    patch.patch = QString("..\\data\\character\\monster\\war_fyt\\war_yan\\war_yan_%1%2.x")
            .arg(a ? "a" : "b").arg(id ? QString("_skin%1").arg(id) : "").toLocal8Bit();
    return true;
}

bool CreatePatchScheme(const int &id, Scheme &schemea, Scheme &schemeb, PatchScheme &patch)
{
    const QString &name = QString(u8"%1×%2").arg(schemea.text.size() ? schemea.text : u8"(空)", schemeb.text.size() ? schemeb.text : u8"(空)");
    patch.id = id;
    patch.name = QString("%1.%2").arg(id, 2, 10, QChar('0')).arg(name).toLocal8Bit();
    patch.info = name.toLocal8Bit();
    if (!Texture(true, id, schemea, patch.imga)) return false;
    if (!Texture(false, id, schemeb, patch.imgb)) return false;
    if (!JumpX(true, id, patch.modela)) return false;
    if (!JumpX(false, id, patch.modelb)) return false;
    return true;
}

bool EncryptConfigJson(const SchemeMap &schemes, PatchItem &patch)
{
    // 生成json
    QJsonObject objSchemes;
    for (auto it = schemes.begin(), itend = schemes.end(); it != itend; ++it) {
        if (it.key() < 0) continue;
        QJsonObject objSchemeA, objSchemeB;
        for (int i = 0; i < 2; ++i) {
            auto &objScheme = i ? objSchemeB : objSchemeA;
            auto &scheme = it.value()[i];
            objScheme.insert("text", scheme.text);
            objScheme.insert("font_family", scheme.font.family());
            objScheme.insert("font_size", scheme.font.pixelSize());
            objScheme.insert("font_bold", scheme.font.bold());
            objScheme.insert("font_color", scheme.color.name(QColor::HexArgb));
            objScheme.insert("stroke_size", scheme.strokeSize);
            objScheme.insert("stroke_color", scheme.strokeColor.name(QColor::HexArgb));
            objScheme.insert("line", scheme.line);
        }
        objSchemes.insert(QString::number(it.key()), QJsonObject{{"a", objSchemeA},{"b", objSchemeB}});
    }
    const QByteArray &jsonData = QJsonDocument(QJsonObject{{"name", "PigFriend"},{"author","Anran233"},{"version","1.0"},{"schemes",objSchemes}}).toJson();
    // 添加到patch
    ulong &&compLen = compressBound(jsonData.size());
    patch.data.resize(compLen);
    if (compress((uchar*)patch.data.data(), &compLen, (uchar*)jsonData.data(), jsonData.size())) return false;
    patch.data.resize(compLen);
    patch.compLen = compLen;
    patch.fileLen = jsonData.size();
    patch.patch = g_patch;
    return true;
}

bool DecryptConfigJson(const PatchItem &patch, SchemeMap &schemes)
{
    QByteArray jsonData;
    if (patch.fileLen >= 0) { // 从patch解压
        ulong fileLen = patch.fileLen;
        jsonData.resize(fileLen);
        if (uncompress((uchar*)jsonData.data(), &fileLen, (uchar*)patch.data.data(), patch.compLen)) return false;
        jsonData.resize(fileLen);
    }
    else jsonData = patch.data; // 无压缩
    // 解析json
    const QJsonObject &objConfig = QJsonDocument::fromJson(jsonData).object();
    if (objConfig.isEmpty()) return false;
    const auto &objSchemes = objConfig["schemes"].toObject();
    for (auto it = objSchemes.begin(), itend = objSchemes.end(); it != itend; ++it) {
        bool is_ok;
        const int& id = it.key().toInt(&is_ok);
        if (!is_ok) continue;
        for (int i = 0; i < 2; ++i) {
            const auto &obj = it.value()[i ? "b" : "a"];
            auto &scheme = schemes[id][i];
            scheme.text = obj["text"].toString();
            scheme.font.setFamily(obj["font_family"].toString(g_font.family()));
            scheme.font.setPixelSize(obj["font_size"].toInt(g_font.pixelSize()));
            scheme.font.setBold(obj["font_bold"].toBool(g_font.bold()));
            scheme.color = QColor(obj["font_color"].toString(scheme.color.name(QColor::HexArgb)));
            scheme.strokeSize = obj["stroke_size"].toInt(scheme.strokeSize);
            scheme.strokeColor = QColor(obj["stroke_color"].toString(scheme.strokeColor.name(QColor::HexArgb)));
            scheme.line = obj["line"].toDouble(scheme.line);
        }
    }
    return true;
}

bool ImportPatch2(const QString &strFilePath, SchemeMap &schemes)
{
    QFile file(strFilePath);
    CActionSpoce spoce([&]{ if (file.isOpen()) file.close(); });
    if (!file.open(QIODevice::ReadOnly)) return false;
    if (file.size() < 120) return false;
    if (file.read(13) != "300PATCH V0.2") return false;
    if (!file.seek(116)) return false;
    quint32 dataLen = 0;
    file.read((char*)&dataLen, 4);
    if (file.size() < 120 + dataLen) return false;
    if (!file.seek(120 + dataLen)) return false;
    const QStringList &infos = QString::fromLocal8Bit(Patch2::decrypt(file.read(file.size() - dataLen - 120).data()).toString()).split("\r\n");
    for (auto& info : infos) {
        const QStringList &s = info.split('|');
        if (s.size() < 4) continue;
        if (s[0] != g_patch) continue;
        PatchItem patch;
        patch.compLen = s[2].toInt();
        patch.fileLen = s[3].toInt();
        file.seek(120 + s[1].toInt());
        patch.data = file.read(patch.compLen);
        if (!DecryptConfigJson(patch, schemes)) continue;
        return true;
    }
    return false;
}

bool ExportPatch2(SchemeMap &schemes, const QString &strSavePath)
{
    // 生成补丁文件列表
    QList<PatchItem> patchs;
    for (auto it = schemes.begin(), itend = schemes.end(); it != itend; ++it) {
        const int &id = it.key();
        if (id < 0) continue;
        if (!Texture(true, id, it.value()[0], (patchs += PatchItem{}).back())) return false;
        if (!Texture(false, id, it.value()[1], (patchs += PatchItem{}).back())) return false;
        if (!JumpX(true, id, (patchs += PatchItem{}).back())) return false;
        if (!JumpX(false, id, (patchs += PatchItem{}).back())) return false;
    }
    if (!EncryptConfigJson(schemes, (patchs += PatchItem{}).back())) return false;
    // 处理数据
    static const uchar patch2Head[112] = { // patch2文件头
        0x33, 0x30, 0x30, 0x50, 0x41, 0x54, 0x43, 0x48, 0x20, 0x56, 0x30, 0x2e, 0x32, 0x20, 0x20, 0x20,
        0x20, 0xb4, 0xcb, 0xb2, 0xb9, 0xb6, 0xa1, 0xc0, 0xb4, 0xd7, 0xd4, 0x33, 0x30, 0x30, 0xcd, 0xe2,
        0xcd, 0xc5, 0x20, 0xcf, 0xa3, 0xcd, 0xfb, 0xb4, 0xf3, 0xbc, 0xd2, 0xd6, 0xa7, 0xb3, 0xd6, 0x20,
        0x20, 0x20, 0x57, 0x57, 0x57, 0x2e, 0x4a, 0x55, 0x4d, 0x50, 0x57, 0x2e, 0x43, 0x4f, 0x4d, 0x20,
        0x20, 0x20, 0xd4, 0xda, 0xb4, 0xcb, 0xc4, 0xa4, 0xb0, 0xdd, 0xcc, 0xf8, 0xd4, 0xbe, 0xb3, 0xcc,
        0xd0, 0xf2, 0xd4, 0xb3, 0x57, 0x55, 0x59, 0x41, 0x58, 0x49, 0xc8, 0xfd, 0xb4, 0xce, 0x21, 0x57,
        0x45, 0x49, 0x42, 0x4f, 0x2e, 0x43, 0x4f, 0x4d, 0x2f, 0x57, 0x55, 0x59, 0x41, 0x58, 0x49, 0x54,};
    static const char Lovely[20] = { // 个人标志(Lovely is justice!)
        0x4c, 0x6f, 0x76, 0x65, 0x6c, 0x79, 0x20, 0x69, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x69, 0x63, 0x65, 0x21, 0x00, 0x00};
    quint32 patchSize = patchs.size();
    quint32 dataLen = 20;
    QByteArray plain;
    for (auto &patch : patchs) {
        plain += QString("%1|%2|%3|%4\r\n").arg(patch.patch.data()).arg(dataLen).arg(patch.compLen).arg(patch.fileLen).toLocal8Bit();
        dataLen += patch.compLen;
    }
    QByteArray cipher(Patch2::encrypt(plain.data()).toString());
    if (cipher.isEmpty()) return false;
    // 写入补丁
    QFile file(strSavePath);
    if (!file.open(QIODevice::WriteOnly)) return false;
    file.write((const char*)patch2Head, 112);
    file.write((const char*)(&patchSize), 4);
    file.write((const char*)(&dataLen), 4);
    file.write(Lovely, 20);
    for (auto &patch : patchs) file.write(patch.data);
    file.write(cipher);
    file.close();
    return true;
}

bool ImportGpk(const QString &strFilePath, SchemeMap &schemes)
{
    static auto readInt = [](QFile& file){
        int num;
        file.read((char*)(&num), 4);
        return num;
    };
    static auto readData = [](QFile& file){ return file.seek(readInt(file) + file.pos()); };
    QFile file(strFilePath);
    CActionSpoce spoce([&]{ if (file.isOpen()) file.close(); });
    if (!file.open(QIODevice::ReadOnly)) return false;
    if (file.read(8) != QByteArray("\x47\x50\x4B\x00\x03\x00\x00\x00", 8)) return false;
    if (!readData(file)) return false; // 标题
    if (!readData(file)) return false; // 作者
    if (!readData(file)) return false; // 版本
    if (!readData(file)) return false; // 信息
    for (int i = 0, size = readInt(file); i < size; ++i) if (!readData(file)) return false; // 预览图
    for (int i = 0, size = readInt(file); i < size; ++i) { // 子补丁列表
        if (!readData(file)) return false; // 名称
        if (!readData(file)) return false; // 信息
        if (!file.seek(file.pos() + 1)) return false; // 是否启用
        if (!file.seek(readInt(file) * 4 + file.pos())) return false; // 包含文件
    }
    for (int i = 0, size = readInt(file); i < size; ++i) {
        if (file.read(readInt(file)) != g_patch) {
            if (!readData(file)) return false; // 备注
            if (!file.seek(file.pos() + 4)) return false; // 文件长度
            if (!readData(file)) return false; // 数据
        }
        else {
            if (!readData(file)) return false; // 备注
            PatchItem patch;
            patch.fileLen = readInt(file);
            patch.compLen = readInt(file);
            patch.data = file.read(patch.compLen);
            if (!DecryptConfigJson(patch, schemes)) continue;
            return true;
        }
    }
    return false;
}

bool ExportGpk(SchemeMap &schemes, const QString &strSavePath)
{
    // 生成子补丁列表
    QList<PatchScheme> patchs;
    for (auto it = schemes.begin(), itend = schemes.end(); it != itend; ++it) {
        if (it.key() < 0) continue;
        if (!CreatePatchScheme(it.key(), it.value()[0], it.value()[1], (patchs += PatchScheme{}).back())) return false;
    }
    PatchItem config;
    if (!EncryptConfigJson(schemes, config)) return false;
    // 处理数据
    static auto writeInt = [](QFile& file, const int& num){ file.write((char*)(&num), 4); };
    static auto writePatch = [](QFile& file, const PatchItem& patch){
        writeInt(file, patch.patch.size());
        file.write(patch.patch);
        writeInt(file, 0);
        writeInt(file, patch.fileLen);
        writeInt(file, patch.compLen);
        file.write(patch.data);
    };
    static const QByteArray head(
                // 头部： GPK V3 未加密
                "\x47\x50\x4B\x00\x03\x00\x00\x00"
                // 标题：猪比朋友观察站
                "\x0E\x00\x00\x00\xD6\xED\xB1\xC8\xC5\xF3\xD3\xD1\xB9\xDB\xB2\xEC\xD5\xBE"
                // 作者：Anran233
                "\x08\x00\x00\x00\x41\x6E\x72\x61\x6E\x32\x33\x33"
                // 版本：1.0
                "\x03\x00\x00\x00\x31\x2E\x30"
                // 信息：燃烧朋友，驱散灰暗的迷雾，照亮前行的道路。
                "\x2A\x00\x00\x00\xC8\xBC\xC9\xD5\xC5\xF3\xD3\xD1\xA3\xAC\xC7\xFD"
                "\xC9\xA2\xBB\xD2\xB0\xB5\xB5\xC4\xC3\xD4\xCE\xED\xA3\xAC\xD5\xD5"
                "\xC1\xC1\xC7\xB0\xD0\xD0\xB5\xC4\xB5\xC0\xC2\xB7\xA1\xA3", 91);
    QFile img(":/img_patch.png");
    if (!img.open(QIODevice::ReadOnly)) return false;
    const QByteArray &imgData = img.readAll();
    img.close();
    // 生成gpk补丁
    QFile file(strSavePath);
    if (!file.open(QIODevice::WriteOnly)) return false;
    file.write(head);
    writeInt(file, 1);
    writeInt(file, imgData.size());
    file.write(imgData);
    writeInt(file, patchs.size());
    for (int i = 0, size = patchs.size(); i < size; ++i) {
        auto &patch = patchs[i];
        writeInt(file, patch.name.size());
        file.write(patch.name);
        writeInt(file, patch.info.size());
        file.write(patch.info);
        file.write("\x01", 1);
        writeInt(file, 4);
        writeInt(file, i * 4 + 0);
        writeInt(file, i * 4 + 1);
        writeInt(file, i * 4 + 2);
        writeInt(file, i * 4 + 3);
    }
    writeInt(file, patchs.size() * 4 + 1);
    for (auto &patch : patchs) {
        writePatch(file, patch.imga);
        writePatch(file, patch.imgb);
        writePatch(file, patch.modela);
        writePatch(file, patch.modelb);
    }
    writePatch(file, config);
    file.close();
    return true;
}

QString ColorToCss(const QColor &color) {
    return QString("background-color: rgba(%1,%2,%3,%4);")
            .arg(color.red())
            .arg(color.green())
            .arg(color.blue())
            .arg(color.alpha());
}

QColor CssToColor(const QString &css) {
    QColor color;
    const int& pos1 = css.indexOf('(');
    const int& pos2 = css.indexOf(')');
    QStringList list = css.mid(pos1 + 1, pos2 - pos1 - 1).split(',');
    if (list.size() >= 1) color.setRed(list[0].trimmed().toInt());
    if (list.size() >= 2) color.setGreen(list[1].trimmed().toInt());
    if (list.size() >= 3) color.setBlue(list[2].trimmed().toInt());
    if (list.size() >= 4) color.setAlpha(list[3].trimmed().toInt());
    return color;
}

void ShowToolTip(QWidget *widget) {
    QToolTip::showText(widget->mapToGlobal(QPoint(0,0)), widget->toolTip(), widget);
}

QPixmap& Scheme::render()
{
    /**
     * QFontMetrics:
     *      -------------------------------------
     *                     leading
     *      +---------------------------+-------+
     *      |         *                 |       |
     *      |   *     *                 |       |
     *      |  * *    ****    ****   ascent     |
     *      | *****   *   *  *   *      |     height
     *      |*     *  ****    ****      |       |
     * (x,y)+--------------------*------+       |
     *      |                    *   descent    |
     *      +---------------------------+-------+
     */

    static const int scale = 4;
    static const int imgWidth = 512;
    static const int imgHeight = 512;
    static const int canvasWidth = imgWidth * scale;
    static const int canvasHeight = imgHeight * scale;

    QPixmap canvas(canvasWidth, canvasHeight);
    canvas.fill(QColor(0,0,0,0));
    QPainterPath rect;
    rect.addRect(canvas.rect());

    QFont fontX(font);
    fontX.setPixelSize(font.pixelSize() * scale);
    QFontMetrics metrics(fontX);
    const int& fontHeight = metrics.height();
    const int& fontAscent = metrics.ascent();

    QStringList&& texts = text.split('\n');
    const int& contentTop = 0.5 * (canvasHeight - line * fontHeight * texts.size());
    for (int i = 0, num = texts.size(); i < num; ++i) {
        const int& fontWidth = metrics.horizontalAdvance(texts[i]);
        const int& posX = 0.5 * (canvasWidth - fontWidth);
        const int& posY = line * fontHeight * i + fontAscent + contentTop;
        QPainterPath path;
        path.addText(posX, posY, fontX, texts[i]);
        if (strokeSize) {
            QPainter painter(&canvas);
            painter.setClipPath(rect - path);
            painter.strokePath(path, QPen(strokeColor, strokeSize * scale * 2, Qt::SolidLine, Qt::SquareCap, Qt::RoundJoin));
        }
        QPainter(&canvas).fillPath(path, color);
    }

    return img = canvas.scaled(imgWidth, imgHeight, Qt::KeepAspectRatio, Qt::SmoothTransformation);
}

void Scheme::clear()
{
    *this = Scheme{};
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    GlobalInit();

    ui->id_max->clear();
    connect(this, &MainWindow::indexChanged, this, &MainWindow::onIndexChanged);

    connect(ui->button_preview, &QPushButton::clicked,      this, [=]{ onPreview(); });
    connect(ui->id_max_tip, &QPushButton::clicked,          this, [=]{ ShowToolTip(ui->id_max_tip); });
    connect(ui->new_template_tip, &QPushButton::clicked,    this, [=]{ ShowToolTip(ui->new_template_tip); });
    connect(ui->button_addAll, &QPushButton::clicked,       this, &MainWindow::onButtonAll);
    connect(ui->button_open, &QPushButton::clicked,         this, &MainWindow::onButtonOpen);
    connect(ui->button_merge, &QPushButton::clicked,        this, &MainWindow::onButtonMerge);
    connect(ui->button_save, &QPushButton::clicked,         this, &MainWindow::onButtonSave);

    m_schemeUI[0] = SchemeUI{ui->a_box,ui->label_preview_a,ui->a_text,ui->a_family,ui->a_size,ui->a_color,ui->a_strokesize,ui->a_strokecolor,ui->a_line,ui->a_bold};
    m_schemeUI[1] = SchemeUI{ui->b_box,ui->label_preview_b,ui->b_text,ui->b_family,ui->b_size,ui->b_color,ui->b_strokesize,ui->b_strokecolor,ui->b_line,ui->b_bold};

    for (int i = 0; i <= 1; ++i) {
        connect(m_schemeUI[i].text, &QTextEdit::textChanged,                                this, [=]{onSchemeRender(i);});
        connect(m_schemeUI[i].family, &QFontComboBox::currentFontChanged,                   this, [=]{onSchemeRender(i);});
        connect(m_schemeUI[i].size,  QOverload<int>::of(&QSpinBox::valueChanged),           this, [=]{onSchemeRender(i);});
        connect(m_schemeUI[i].color, &QPushButton::clicked,                                 this, [=]{openColor(i, false);});
        connect(m_schemeUI[i].strokesize, QOverload<int>::of(&QSpinBox::valueChanged),      this, [=]{onSchemeRender(i);});
        connect(m_schemeUI[i].strokecolor, &QPushButton::clicked,                           this, [=]{openColor(i, true);});
        connect(m_schemeUI[i].line, QOverload<double>::of(&QDoubleSpinBox::valueChanged),   this, [=]{onSchemeRender(i);});
        connect(m_schemeUI[i].bold, &QCheckBox::clicked,                                    this, [=]{onSchemeRender(i);});
    }

    ui->label_selected->setText(u8"无");
    ui->id_max->setValue(g_names.lastKey());
    ui->new_template->clear();
    ui->new_template->addItem(u8"无");
    for(auto& item : ui->items->children()) item->deleteLater();
    for (int i = 0, size = g_names.size(); i < size; ++i) m_items.append(new SchemeItem(i, this, ui->items));
    ui->items->setMinimumHeight(m_items.size() * 30);
    connect(ui->id_max, &QSpinBox::editingFinished, this, &MainWindow::onMaxChanged);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::start()
{
    m_items[13]->onButton();
    m_scheme[13][0].text = u8"花枯";
    m_scheme[13][0].color = QColor(255, 100, 0);
    m_scheme[13][1].text = u8"千雨";
    m_scheme[13][1].color = QColor(0, 255, 255);
    setIndex(13);
    show();
}

void MainWindow::setIndex(const int &index)
{
    if (index == m_index) return;
    m_index = index;
    emit indexChanged();
}

void MainWindow::openColor(int type, bool stroke)
{
    if (m_bSwitch) return;
    QPushButton* button = stroke ? m_schemeUI[type].strokecolor : m_schemeUI[type].color;
    QColor& color = stroke ? m_scheme[m_index][type].strokeColor : m_scheme[m_index][type].color;
    QColor&& newColor = QColorDialog::getColor(color, this, u8"设置颜色", QColorDialog::ShowAlphaChannel | QColorDialog::DontUseNativeDialog);
    if (newColor.isValid()) {
        button->setStyleSheet(ColorToCss(color = newColor));
        m_scheme[m_index][type].render();
        m_schemeUI[type].img->setPixmap(m_scheme[m_index][type].img);
    }
}

void MainWindow::onPreview()
{
    const QPixmap img(":/preview_max.jpg");
    QDialog* preview = new QDialog;
    preview->setWindowFlags(Qt::FramelessWindowHint);
    preview->setAttribute(Qt::WA_DeleteOnClose);
    preview->setModal(true);
    preview->resize(img.width(), img.height());

    QLabel* label = new QLabel(preview);
    label->setPixmap(img);
    label->resize(img.width(), img.height());

    QLabel* labelA = new QLabel(preview);
    labelA->setPixmap(m_scheme[m_index][0].img);
    labelA->setScaledContents(true);
    labelA->resize(188, 188);
    labelA->move(45, 224);

    QLabel* labelB = new QLabel(preview);
    labelB->setPixmap(m_scheme[m_index][1].img);
    labelB->setScaledContents(true);
    labelB->resize(188, 188);
    labelB->move(571, 224);

    QPushButton *button = new QPushButton(preview);
    button->resize(img.width(), img.height());
    button->setStyleSheet("border: 0; background-color: #00000000;");
    connect(button, &QPushButton::clicked, preview, [=]{ preview->close(); });

    preview->show();
}

void MainWindow::onSchemeRender(int type)
{
    if (m_bSwitch) return;
    Scheme& scheme = m_scheme[m_index][type];
    SchemeUI& schemeUI = m_schemeUI[type];
    scheme.text = schemeUI.text->toPlainText();
    scheme.font.setFamily(schemeUI.family->currentFont().family());
    scheme.font.setPixelSize(schemeUI.size->value());
    scheme.font.setBold(schemeUI.bold->checkState());
    scheme.color = CssToColor(schemeUI.color->styleSheet());
    scheme.strokeSize = schemeUI.strokesize->value();
    scheme.strokeColor = CssToColor(schemeUI.strokecolor->styleSheet());
    scheme.line = schemeUI.line->value();
    schemeUI.img->setPixmap(scheme.render());
}

void MainWindow::onIndexChanged()
{
    const QString& name = g_names.contains(m_index) ? g_names[m_index] : "";
    const QString& text = m_index < 0 ? u8"无" : QString("%1%2").arg(m_index, 2, 10, QChar(u'0')).arg(name.size() ? ("." + name) : "");
    ui->label_selected->setText(text);
    ui->label_selected->setToolTip(name.size() ? text : "");
    const bool &bRender = !m_scheme.contains(m_index);
    for (int i = 0; i <= 1; ++i) {
        m_bSwitch = true;
        Scheme& scheme = m_scheme[m_index][i];
        SchemeUI& schemeUI = m_schemeUI[i];
        schemeUI.box->setEnabled(m_index >= 0);
        schemeUI.text->setText(scheme.text);
        schemeUI.family->setCurrentFont(scheme.font);
        schemeUI.size->setValue(scheme.font.pixelSize());
        schemeUI.bold->setChecked(scheme.font.bold());
        schemeUI.color->setStyleSheet(ColorToCss(scheme.color));
        schemeUI.strokesize->setValue(scheme.strokeSize);
        schemeUI.strokecolor->setStyleSheet(ColorToCss(scheme.strokeColor));
        schemeUI.img->setPixmap(bRender ? scheme.render() : scheme.img);
        m_bSwitch = false;
        onSchemeRender(i);
    }
}

void MainWindow::onMaxChanged()
{
    const int& value = ui->id_max->value() + 1;
    if (value < m_items.size()) {
        if (m_index >= value) setIndex(-1);
        while(m_items.size() > value) delete m_items.takeLast();
        ui->items->setMinimumHeight(m_items.size() * 30);
    }
    else if (value > m_items.size()) {
        for (int i = m_items.size(); i < value; ++i) m_items.append(new SchemeItem(i, this, ui->items)), m_items[i]->show();
        ui->items->setMinimumHeight(m_items.size() * 30);
    }
}

void MainWindow::onTemplateChanged()
{
    const QString& currentText = ui->new_template->currentIndex() > 0 ? ui->new_template->currentText() : u8"无";
    ui->new_template->clear();
    ui->new_template->addItem(u8"无");
    for (auto& item : m_items) if (item->m_state) ui->new_template->addItem(QString("%1").arg(item->m_index, 2, 10, QChar(u'0')));
    if (ui->new_template->findText(currentText)) ui->new_template->setCurrentText(currentText);
    else ui->new_template->setCurrentIndex(0);
}

void MainWindow::onButtonAll()
{
    for (auto& item : m_items) {
        if (item->m_state) continue;
        item->onButton();
    }
}

void MainWindow::onButtonOpen()
{
    const QString& strFilePath = QFileDialog::getOpenFileName(this, u8"打开", nullptr, u8"补丁文件(*.gpk *.patch2)");
    if (strFilePath.isEmpty()) return;
    const bool &bGpk = strFilePath.right(3) == "gpk";
    ProgressBar *progress = new ProgressBar(this, u8"正在打开补丁...");
    connect(progress, &ProgressBar::started, progress, [=]{
        bool result = true;
        SchemeMap schemes;
        if (bGpk) result = ImportGpk(strFilePath, schemes);
        else result = ImportPatch2(strFilePath, schemes);
        if (result) std::swap(schemes, m_scheme);
        emit progress->finished(result);
    });
    connect(progress, &ProgressBar::finished, this, [=](QVariant result){
        if (!result.toBool()) QMessageBox::critical(this, u8"错误", u8"打开失败！");
        else {
            setIndex(-1);
            const int &max = qMin(99, qMax(g_names.lastKey(), m_scheme.lastKey()));
            ui->id_max->setValue(max);
            onMaxChanged();
            for (auto &item : m_items) {
                if (m_scheme.contains(item->m_index)) {
                    item->m_state = 1;
                    emit item->stateChanged();
                }
                else item->setState(0);
            }
            ui->new_template->setCurrentIndex(0);
            onTemplateChanged();
        }
        delete progress;
    });
    progress->start();
}

void MainWindow::onButtonMerge()
{
    const QString& strFilePath = QFileDialog::getOpenFileName(this, u8"打开", nullptr, u8"补丁文件(*.gpk *.patch2)");
    if (strFilePath.isEmpty()) return;
    const bool &bGpk = strFilePath.right(3) == "gpk";
    SchemeMap *schemes = new SchemeMap;
    ProgressBar *progress = new ProgressBar(this, u8"正在导入补丁...");
    connect(progress, &ProgressBar::started, progress, [=]{
        if (bGpk) emit progress->finished(ImportGpk(strFilePath, *schemes));
        else emit progress->finished(ImportPatch2(strFilePath, *schemes));
    });
    connect(progress, &ProgressBar::finished, this, [=](QVariant result){
        if (!result.toBool()) QMessageBox::critical(this, u8"错误", u8"导入失败！");
        else {
            bool bCover = false;
            for (auto it = schemes->begin(), itend = schemes->end(); it != itend; ++it) {
                if (!m_scheme.contains(it.key())) continue;
                bCover = QMessageBox::question(this, u8"询问", u8"部分观察站配置重复！是否覆盖旧配置？") == QMessageBox::Yes;
                break;
            }
            const int &max = qMin(99, qMax(ui->id_max->value(), schemes->lastKey()));
            ui->id_max->setValue(max);
            onMaxChanged();
            for (auto &item : m_items) {
                if (!schemes->contains(item->m_index)) continue;
                if (!bCover && m_scheme.contains(item->m_index)) continue;
                std::swap(m_scheme[item->m_index], (*schemes)[item->m_index]);
                if (item->m_state == 0) item->setState(1);
                else if (item->m_state == 1) emit item->stateChanged();
                else {
                    emit item->stateChanged();
                    onIndexChanged();
                }
            }
            onTemplateChanged();
        }
        delete schemes;
        delete progress;
    });
    progress->start();
}

void MainWindow::onButtonSave()
{
    // 检查列表是否为空
    bool bEmpty = true;
    for (int i = 0, size = m_items.size(); i < size && bEmpty; ++i) if (m_items[i]->m_state) bEmpty = false;
    if (bEmpty) { QMessageBox::information(this, u8"提示", u8"列表为空！"); return; }
    // 设置保存路径
    const QString& strFilePath = QFileDialog::getSaveFileName(this, u8"保存", u8"猪比朋友观察站", u8"动态补丁(*.gpk);;外团补丁(*.patch2)");
    if (strFilePath.isEmpty()) return;
    // 保存补丁
    const bool &bGpk = strFilePath.right(3) == "gpk";
    ProgressBar *progress = new ProgressBar(this, u8"正在保存补丁...");
    connect(progress, &ProgressBar::started, progress, [=]{
        if (bGpk) emit progress->finished(ExportGpk(m_scheme, strFilePath));
        else emit progress->finished(ExportPatch2(m_scheme, strFilePath));
    });
    connect(progress, &ProgressBar::finished, this, [=](QVariant result){
        if (result.toBool()) QMessageBox::information(this, u8"提示", u8"保存成功！");
        else QMessageBox::critical(this, u8"错误", u8"保存失败！");
        delete progress;
    });
    progress->start();
}

SchemeItem::SchemeItem(const int &index, MainWindow *main, QWidget *parent)
    : QWidget(parent), m_index(index), m_main(main)
{
    // this
    setMinimumSize(160, 30);
    move(0, index * 30);
    connect(this, &SchemeItem::stateChanged, this, &SchemeItem::onStateChanged);
    connect(main, &MainWindow::indexChanged, this, &SchemeItem::onIndexChanged);
    connect(main->m_schemeUI[0].text, &QTextEdit::textChanged, this, &SchemeItem::onTextChanged);
    connect(main->m_schemeUI[1].text, &QTextEdit::textChanged, this, &SchemeItem::onTextChanged);

    // background
    {
        static const char* css[3] {".QWidget:enabled{background-color:#F8F8F8;}",
                                   ".QWidget:enabled{background-color:#EEEEEE;}",
                                   "background-color:#E5F1FB;border-left:1px solid #0078D7;border-right:1px solid #0078D7;"};
        m_backgrounds = new QStackedWidget(this);
        m_backgrounds->resize(160, 30);
        m_backgrounds->move(0, 0);
        m_backgrounds->setEnabled(false);
        for (int i = 0; i < 3; ++i) {
            QWidget *background = new QWidget(this);
            m_backgrounds->addWidget(background);
            background->resize(160, 30);
            background->move(0, 0);
            background->setStyleSheet(css[i]);
        }
    }

    // text
    m_text = new QPushButton(this);
    m_text->resize(129, 30);
    m_text->move(0, 0);
    m_text->setFocusPolicy(Qt::FocusPolicy::NoFocus);
    m_text->setStyleSheet(".QPushButton{border:0px;background-color:#00000000;text-align:left;padding:0px 2px;color:#123;}.QPushButton:!enabled{color:#AAA;}");
    connect(m_text, &QPushButton::clicked, this, &SchemeItem::onSelected);

    // button
    {
        static const char* css[2] {".QPushButton{border:0px;background-color:#00000000;image:url(:/icon_add_1.png);}"
                                   ".QPushButton:hover{background-color:#7F7;image:url(:/icon_add_2.png);}"
                                   ".QPushButton:pressed{background-color:#3E3;}",
                                   ".QPushButton{border:0px;background-color:#00000000;image:url(:/icon_sub_1.png);}"
                                   ".QPushButton:hover{background-color:#F77;image:url(:/icon_sub_2.png);}"
                                   ".QPushButton:pressed{background-color:#E33;}"};
        m_buttons = new QStackedWidget(this);
        m_buttons->resize(30, 30);
        m_buttons->move(129, 0);
        m_buttons->setVisible(false);
        for (int i = 0; i < 2; ++i) {
            QPushButton *button = new QPushButton(this);
            m_buttons->addWidget(button);
            button->resize(30, 30);
            button->move(0, 0);
            button->setFocusPolicy(Qt::FocusPolicy::NoFocus);
            button->setStyleSheet(css[i]);
            button->setToolTip(i ? u8"删除" : u8"添加");
            connect(button, &QPushButton::clicked, this, &SchemeItem::onButton);
        }
    }

    // border
    m_border_top = new QWidget(this);
    m_border_top->resize(160, 1);
    m_border_top->move(0, 0);
    m_border_top->setStyleSheet("background-color:#0078D7;");
    m_border_bottom = new QWidget(this);
    m_border_bottom->resize(160, 1);
    m_border_bottom->move(0, 29);
    m_border_bottom->setStyleSheet("background-color:#0078D7;");

    onStateChanged();
}

SchemeItem::~SchemeItem()
{

}

void SchemeItem::setState(const int &state)
{
    if (m_state == state) return;
    m_state = qBound(0, state, 2);
    emit stateChanged();
}

void SchemeItem::onIndexChanged()
{
    if (m_state == 0) return;
    if (m_index == m_main->m_index) setState(2);
    else setState(1);
}

void SchemeItem::onStateChanged()
{
    m_backgrounds->setCurrentIndex(m_state);
    m_buttons->setCurrentIndex(m_state ? 1 : 0);
    m_text->setEnabled(m_state);
    m_border_top->setVisible(m_state == 2);
    m_border_bottom->setVisible(m_state == 2);
    updateText();
}

void SchemeItem::onTextChanged()
{
    if (m_main->m_index != m_index) return;
    updateText();
}

void SchemeItem::onSelected()
{
    if (m_state != 1) return;
    m_main->setIndex(m_index);
}

void SchemeItem::onButton()
{
    if (m_state == 0) { // add
        const int& index = m_main->ui->new_template->currentIndex() > 0 ? m_main->ui->new_template->currentText().toInt() : -1;
        m_main->m_scheme[m_index][0] = m_main->m_scheme[index][0];
        m_main->m_scheme[m_index][1] = m_main->m_scheme[index][1];
        setState(1);
        m_main->onTemplateChanged();
    }
    else { // sub
        if (m_index == m_main->m_index) m_main->setIndex(-1);
        setState(0);
        m_main->onTemplateChanged();
        m_main->m_scheme.remove(m_index);
    }
}

void SchemeItem::enterEvent(QEvent *)
{
    m_backgrounds->setEnabled(true);
    m_buttons->setVisible(true);
}

void SchemeItem::leaveEvent(QEvent *)
{
    m_backgrounds->setEnabled(false);
    m_buttons->setVisible(false);
}

void SchemeItem::updateText()
{
    if (m_state == 0) {
        const QString& name = g_names.contains(m_index) ? g_names[m_index] : "";
        m_text->setText(QString("%1.(%2)").arg(m_index, 2, 10, QChar(u'0')).arg(name.size() ? name : u8"未添加"));
        this->setToolTip("");
    }
    else {
        const QString& text0 = m_main->m_scheme[m_index][0].text;
        const QString& text1 = m_main->m_scheme[m_index][1].text;
        QString&& text = QString(u8"%1.%2×%3").arg(m_index, 2, 10, QChar(u'0')).arg(text0.size() ? text0 : u8"(空)", text1.size() ? text1 : u8"(空)");
        m_text->setText(text.replace(QChar(u'\n'), QChar(u' ')));
        this->setToolTip(text);
    }
}

ProgressBar::ProgressBar(QObject *parent, const QString &labelText) : m_thread(new QThread())
{
    if (parent) connect(parent, &QObject::destroyed, this, [this]{ delete this; }, Qt::DirectConnection);
    if (!labelText.isEmpty()) {
        m_progress = new QProgressDialog(labelText, nullptr, 0, 0, (QWidget*)parent, Qt::Dialog | Qt::FramelessWindowHint);
        m_progress->installEventFilter(EventFilter::Instance());
        m_progress->setWindowModality(Qt::WindowModal);
        m_progress->setMinimumDuration(0);
    }
    connect(m_thread, &QThread::started, this, &ProgressBar::started);
}

ProgressBar::~ProgressBar()
{
    if (m_thread) {
        m_thread->quit();
        m_thread->wait();
        delete m_thread;
    }
    if (m_progress) {
        m_progress->close();
        delete m_progress;
    }
}

void ProgressBar::start()
{
    if (m_thread->isRunning()) return;
    this->moveToThread(m_thread);
    if (m_progress) m_progress->show();
    m_thread->start();
}

bool EventFilter::eventFilter(QObject *, QEvent *event) {
    if (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease) {
        if (((QKeyEvent *)event)->key() == Qt::Key_Escape ) return true;
    }
    return false;
}

EventFilter *EventFilter::Instance()
{
    static EventFilter d;
    return &d;
}
