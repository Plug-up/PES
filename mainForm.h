#ifndef MAINFORM_H
#define MAINFORM_H

//*If Linux OS & Qt4
#include <QtGui>
//*/

/*if Windows OS & Qt5
#include <QtWidgets>
//*/

#include "pup_encryption_functions.h"
#define IMAGES_DIR ":/images/"


class mainForm : public QMainWindow{

public:
    mainForm();
    ~mainForm();

public slots:
    void showEncGui();
    void showDecGui();
    void selectSimpleFile();
    void removeFiles();
    void clearFilesListSlot();
    void encryptFiles();
    void decryptFiles();
    void confPup();
    void chgPupPass();
    void showPesInfo(QListWidgetItem *i);
    void closePesInfo();
    void showHelpContent();
    void exitApp();

private:
    Q_OBJECT

    QWidget *w_home,*w_encDec;
    QPushButton *b_enc,*b_dec,*b_conf,*b_chPass,*b_exit,*b_help,
                *b_selectFiles,
                *b_encFiles,*b_decFiles,
                *b_rem, *b_remAll,
                *b_closePesInfo;

    QLabel *l_op_result, *l_operation_type;
    QListWidget *files_list;
    QRadioButton *r_usePlugUp, *r_usePassKey;
    QTextBrowser *pesInfo;

    QString last_selected_dir, pesInfotxt;
    hid_device *h;
    struct hid_device_info *lh;
    char lastPass[50], lastSN[50];
    int operation_type;//1:enc gui, 2:dec gui, 3:end crypto
    int fileType;//1:file

    void init();
    void resizeGui(int i);
    int selectPup();
    void freePup();
    void showEncDec();
    void selectFiles(int fileType);
    void clearFilesList();
    void cryptoEncDec(int encDec);
    void decryptWithoutPlugup();
};

#endif // MAINFORM_H
