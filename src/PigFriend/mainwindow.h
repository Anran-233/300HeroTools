#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>
#include <QVariant>
#include <array>

extern QFont g_font;

class QGroupBox;
class QLabel;
class QTextEdit;
class QFontComboBox;
class QSpinBox;
class QPushButton;
class QDoubleSpinBox;
class QCheckBox;
class QStackedWidget;
class SchemeItem;
class QProgressDialog;

struct Scheme {
    QPixmap img;                            ///< 渲染图片
    QString text;                           ///< 文本内容
    QFont font = g_font;                    ///< 字体族类、字体大小、字体加粗
    QColor color = QColor(255,0,0);         ///< 字体颜色
    int strokeSize = 2;                     ///< 描边大小
    QColor strokeColor = QColor(0,0,0,128); ///< 描边颜色
    double line = 1.0;                      ///< 行倍间距
    QPixmap& render();
    void clear();
};
typedef QMap<int, std::array<Scheme, 2>> SchemeMap;

struct SchemeUI {
    QGroupBox* box = nullptr;
    QLabel* img = nullptr;
    QTextEdit* text = nullptr;
    QFontComboBox* family = nullptr;
    QSpinBox* size = nullptr;
    QPushButton* color = nullptr;
    QSpinBox* strokesize = nullptr;
    QPushButton* strokecolor = nullptr;
    QDoubleSpinBox* line = nullptr;
    QCheckBox* bold = nullptr;
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    friend SchemeItem;
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void start();
    void setIndex(const int &index);

signals:
    void indexChanged();

private:
    void openColor(int type, bool stroke);

private slots:
    /// 预览大图
    void onPreview();
    /// 渲染方案预览图片 (type [0.真眼][1.假眼])
    void onSchemeRender(int type);
    /// 更新当前选中方案
    void onIndexChanged();
    /// 更新可用方案上限
    void onMaxChanged();
    /// 更新新建方案模板
    void onTemplateChanged();
    /// 添加全部空白方案
    void onButtonAll();
    /// 打开补丁
    void onButtonOpen();
    /// 合并补丁
    void onButtonMerge();
    /// 保存补丁
    void onButtonSave();

private:
    Ui::MainWindow *ui;
    bool m_bSwitch = false;
    int m_index = -1;
    SchemeMap m_scheme;
    std::array<SchemeUI, 2> m_schemeUI;
    QList<SchemeItem*> m_items;
};

class SchemeItem : public QWidget
{
    Q_OBJECT

public:
    friend MainWindow;
    SchemeItem(const int &index, MainWindow *main, QWidget *parent = nullptr);
    ~SchemeItem();

    void setState(const int &state);

signals:
    void stateChanged();

private slots:
    void onIndexChanged();
    void onStateChanged();
    void onTextChanged();
    void onSelected();
    void onButton();

private:
    void enterEvent(QEvent *) override;
    void leaveEvent(QEvent *) override;
    void updateText();

private:
    int m_index = -1;                           ///< 编号
    int m_state = 0;                            ///< 0.未添加 1.已添加 2.已选中
    MainWindow* m_main = nullptr;               ///< 主界面
    QWidget* m_border_top = nullptr;            ///< 上边框
    QWidget* m_border_bottom = nullptr;         ///< 下边框
    QPushButton *m_text = nullptr;              ///< 文字
    QStackedWidget *m_backgrounds = nullptr;    ///< 背景
    QStackedWidget *m_buttons = nullptr;        ///< 按钮 add/sub
};

/**
 * @brief 进度条
 */
class ProgressBar : public QObject
{
    Q_OBJECT
public:
    ProgressBar(QObject *parent = nullptr, const QString &labelText = "");
    ~ProgressBar();
    void start();
signals:
    void started();
    void finished(QVariant result = {});
private:
    QThread* m_thread = nullptr;
    QProgressDialog* m_progress = nullptr;
};

/**
 * @brief 事件筛选器
 */
class EventFilter : public QObject {
    bool eventFilter(QObject *, QEvent *event) override;
public: static EventFilter *Instance();
};

/**
 * @brief 作用域清理
 */
class CActionSpoce {
    std::function<void()> m_delete = nullptr;
public:
    CActionSpoce(std::function<void()> fun) : m_delete(fun) {}
    ~CActionSpoce() { if (m_delete) m_delete(); }
    void execute() { if (m_delete) m_delete(); clear(); }
    void clear() { if (m_delete) m_delete = nullptr; }
};

#endif // MAINWINDOW_H
