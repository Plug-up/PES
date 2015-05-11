#include "mainForm.h"
#include <QThread>

class Sleeper : public QThread
{
public:
    static void usleep(unsigned long usecs){QThread::usleep(usecs);}
    static void msleep(unsigned long msecs){QThread::msleep(msecs);}
    static void sleep(unsigned long secs){QThread::sleep(secs);}
};

mainForm::mainForm(){

    //General
    this->setWindowTitle(tr("PES"));
    this->setWindowIcon(QIcon(IMAGES_DIR + tr("pes.png")));
    this->setFixedSize(158,232);

    w_home = new QWidget(this);
    w_home->setGeometry(0,0,158,232);

    b_enc = new QPushButton(QIcon(IMAGES_DIR + tr("encrypt.png")),"",w_home);
    b_enc->setIconSize(QSize(50,50));
    b_enc->setGeometry(10,10,64,64);
    b_enc->setToolTip(tr("Encrypt files or directories using your encryption plug-up"));

    b_dec = new QPushButton(QIcon(IMAGES_DIR + tr("decrypt.png")),"",w_home);
    b_dec->setIconSize(QSize(50,50));
    b_dec->setGeometry(84,10,64,64);
    b_dec->setToolTip(tr("Decrypt PES files using encryption plug-up or pass key"));

    b_conf = new QPushButton(QIcon(IMAGES_DIR + tr("config.png")),"",w_home);
    b_conf->setIconSize(QSize(50,50));
    b_conf->setGeometry(10,84,64,64);
    b_conf->setToolTip(tr("Configure plug-up for encryption"));

    b_chPass = new QPushButton(QIcon(IMAGES_DIR + tr("changePass.png")),"",w_home);
    b_chPass->setIconSize(QSize(50,50));
    b_chPass->setGeometry(84,84,64,64);
    b_chPass->setToolTip(tr("Change your plug-up password"));

    b_help = new QPushButton(QIcon(IMAGES_DIR + tr("help.png")),"",w_home);
    b_help->setIconSize(QSize(50,50));
    b_help->setGeometry(10,158,64,64);
    b_help->setToolTip(tr("Get help content"));

    b_exit = new QPushButton(QIcon(IMAGES_DIR + tr("exit.png")),"",w_home);
    b_exit->setIconSize(QSize(50,50));
    b_exit->setGeometry(84,158,64,64);
    b_exit->setToolTip(tr("Exit"));

    w_encDec = new QWidget(this);
    w_encDec->setGeometry(158,0,467,232);

    files_list = new QListWidget();
    files_list->setParent(w_encDec);

    b_selectFiles = new QPushButton(tr("Select files"),w_encDec);
    b_selectFiles->setGeometry(247,190,64,32);

    b_encFiles = new QPushButton(tr("Encrypt"),w_encDec);
    b_encFiles->setGeometry(321,190,64,32);

    b_decFiles = new QPushButton(tr("Decrypt"),w_encDec);
    b_decFiles->setGeometry(321,190,64,32);

    b_rem = new QPushButton(QIcon(IMAGES_DIR + tr("remove.png")),"",w_encDec);
    b_rem->setIconSize(QSize(20,20));
    b_rem->setGeometry(395,35,32,32);
    b_rem->setToolTip(tr("Remove selected files"));

    b_remAll = new QPushButton(QIcon(IMAGES_DIR + tr("clear.png")),"",w_encDec);
    b_remAll->setIconSize(QSize(20,20));
    b_remAll->setGeometry(395,77,32,32);
    b_remAll->setToolTip(tr("Clear files list"));

    l_op_result = new QLabel("",w_encDec);
    l_op_result->setGeometry(100,190,311,32);

    l_operation_type = new QLabel("",w_encDec);
    l_operation_type->setGeometry(10,10,375,15);
    l_operation_type->setStyleSheet("font-weight:bold");

    r_usePlugUp = new QRadioButton("Use plug-up",w_encDec);
    r_usePlugUp->setGeometry(10,163,100,15);
    r_usePlugUp->setChecked(true);

    r_usePassKey = new QRadioButton("Use pass key",w_encDec);
    r_usePassKey->setGeometry(120,163,100,15);
    r_usePassKey->setChecked(false);

    pesInfo = new QTextBrowser(w_encDec);
    b_closePesInfo = new QPushButton("Back",w_encDec);
    b_closePesInfo->setGeometry(363,190,64,32);

    //plug-up
    this->lh = NULL;

    //Import files from
    last_selected_dir = QDir::homePath();

    //Events
    QObject::connect(this->b_enc,SIGNAL(clicked()),this,SLOT(showEncGui()));
    QObject::connect(this->b_dec,SIGNAL(clicked()),this,SLOT(showDecGui()));
    QObject::connect(this->b_selectFiles,SIGNAL(clicked()),this,SLOT(selectSimpleFile()));
    QObject::connect(this->b_rem,SIGNAL(clicked()),this,SLOT(removeFiles()));
    QObject::connect(this->b_remAll,SIGNAL(clicked()),this,SLOT(clearFilesListSlot()));
    QObject::connect(this->b_encFiles,SIGNAL(clicked()),this,SLOT(encryptFiles()));
    QObject::connect(this->b_decFiles,SIGNAL(clicked()),this,SLOT(decryptFiles()));
    QObject::connect(this->b_conf,SIGNAL(clicked()),this,SLOT(confPup()));
    QObject::connect(this->b_chPass,SIGNAL(clicked()),this,SLOT(chgPupPass()));
    QObject::connect(this->r_usePlugUp,SIGNAL(clicked()),this,SLOT(clearFilesListSlot()));
    QObject::connect(this->r_usePassKey,SIGNAL(clicked()),this,SLOT(clearFilesListSlot()));
    QObject::connect(this->files_list,SIGNAL(itemDoubleClicked(QListWidgetItem*)),this,SLOT(showPesInfo(QListWidgetItem*)));
    QObject::connect(this->b_closePesInfo,SIGNAL(clicked()),this,SLOT(closePesInfo()));
    QObject::connect(this->b_help,SIGNAL(clicked()),this,SLOT(showHelpContent()));
    QObject::connect(this->b_exit,SIGNAL(clicked()),this,SLOT(exitApp()));
}

mainForm::~mainForm(){
    delete b_enc;
    delete b_dec;
    delete b_conf;
    delete b_chPass;
    delete b_exit;
    delete b_help;
    delete b_selectFiles;
    delete b_encFiles;
    delete b_decFiles;
    delete b_rem;
    delete b_remAll;
    delete b_closePesInfo;
    delete l_op_result;
    delete l_operation_type;
    delete files_list;
    delete r_usePlugUp;
    delete r_usePassKey;
    delete pesInfo;
    delete w_home;
    delete w_encDec;
}

void mainForm::init(){

    //Hide
    l_operation_type->setHidden(true);
    files_list->setHidden(true);
    b_selectFiles->setHidden(true);
    b_encFiles->setHidden(true);
    b_decFiles->setHidden(true);
    b_rem->setHidden(true);
    b_remAll->setHidden(true);
    r_usePlugUp->setHidden(true);
    r_usePassKey->setHidden(true);
    l_op_result->setHidden(true);
    pesInfo->setHidden(true);
    b_closePesInfo->setHidden(true);

    return;
}

void mainForm::resizeGui(int i){

    if(i==1){
        while(this->width() != 158){
            if(this->width() > 158)
                this->setFixedWidth(this->width()-5);
            else
                this->setFixedWidth(this->width()+5);
            Sleeper::msleep(15);
        }
    }
    if(i==2){
        while(this->width() != 553){
            if(this->width() > 553)
                this->setFixedWidth(this->width()-5);
            else
                this->setFixedWidth(this->width()+5);
            Sleeper::msleep(15);
        }
    }
    if(i==3){
        while(this->width() != 593){
            if(this->width() > 593)
                this->setFixedWidth(this->width()-5);
            else
                this->setFixedWidth(this->width()+5);
            Sleeper::msleep(15);
        }
    }

    return;
}

int mainForm::selectPup(){

    int plug_up_detected = 0;

    if(!(lh=hid_enumerate(0,0))){
        plug_up_detected = 0;
    }
    else{
        while(lh){
            //printf("\n%d",lh->product_id);
            if(lh->product_id == 6151){
                plug_up_detected = 1;
                //*if Linux OS
                lh=lh->next;
                //*/
                break;
            }
            lh=lh->next;
        }
    }

    if(plug_up_detected){
        //printf("\nFirst detected plug-up selected !");
    }
    else{
        //printf("\nNo plug-up inserted !");
        return 0;
    }

    if(!(h=hid_open_path(lh->path))){
        printf("\nCheck udev rule if Linux OS !");
        return -1;
    }

    return 1;
}

void mainForm::freePup(){
    hid_close(h);
    hid_free_enumeration(lh);
}

void mainForm::removeFiles(){
    QList<QListWidgetItem*> items = this->files_list->selectedItems();
    if(items.size()==0){
        QMessageBox::warning(this,tr("Error"),"No file selected !");
        return;
    }
    for (int i = 0; i < items.size(); i++){
        delete items.at(i);
    }

    if(files_list->count()==0){
        b_rem->setEnabled(false);
        b_remAll->setEnabled(false);
        b_encFiles->setEnabled(false);
        b_decFiles->setEnabled(false);
    }

    return;
}

void mainForm::clearFilesList(){
    files_list->clear();
    return;
}

void mainForm::clearFilesListSlot(){
    clearFilesList();
    b_rem->setEnabled(false);
    b_remAll->setEnabled(false);
    b_encFiles->setEnabled(false);
    b_decFiles->setEnabled(false);
    return;
}

void mainForm::showEncGui(){

    init();
    clearFilesList();
    operation_type = 1;
    l_operation_type->setText("Files encryption..");
    files_list->setGeometry(10,35,375,145);
    //Disable
    b_enc->setEnabled(false);
    b_dec->setEnabled(true);
    b_rem->setEnabled(false);
    b_remAll->setEnabled(false);
    b_encFiles->setEnabled(false);
    b_decFiles->setEnabled(false);
    //Hide
    l_operation_type->setHidden(false);
    files_list->setHidden(false);
    b_selectFiles->setHidden(false);
    b_encFiles->setHidden(false);
    b_rem->setHidden(false);
    b_remAll->setHidden(false);

    resizeGui(3);

    return;
}

void mainForm::showDecGui(){

    init();
    clearFilesList();
    operation_type = 2;
    l_operation_type->setText("Files decryption..");
    files_list->setGeometry(10,35,375,113);
    //Disable
    b_dec->setEnabled(false);
    b_enc->setEnabled(true);
    b_rem->setEnabled(false);
    b_remAll->setEnabled(false);
    b_encFiles->setEnabled(false);
    b_decFiles->setEnabled(false);
    //Hide
    l_operation_type->setHidden(false);
    files_list->setHidden(false);
    b_selectFiles->setHidden(false);
    b_decFiles->setHidden(false);
    b_rem->setHidden(false);
    b_remAll->setHidden(false);
    r_usePlugUp->setHidden(false);
    r_usePassKey->setHidden(false);

    r_usePlugUp->setChecked(true);
    resizeGui(3);

    return;
}

void mainForm::selectSimpleFile(){
    selectFiles(0);
    return;
}

/*void mainForm::selectDir(){
    selectFiles(1);
    return;
}*/

void mainForm::selectFiles(int fileType){

        QFileDialog fileDlg;
        QString type, op_string;

        //encryption case
        if(operation_type==1) {
            type = tr("All files(*.*)");
            op_string = tr("Files encryption");
        }
        //decryption case
        if(operation_type==2) {
            type = tr("PES files(*.pes)");
            op_string = tr("Files decryption");
        }

        /*if(fileType){
            QString importedDirName = fileDlg.getExistingDirectory(this,tr("Select directory"),last_selected_dir);

            if(importedDirName.size() == 0){
                QMessageBox::warning(this,op_string,"No file imported !");
                return;
            }

            QFileInfo fi = importedDirName;
            last_selected_dir = fi.absolutePath();

            this->files_list->addItem(importedDirName);
        }
        else*/ if(!(r_usePassKey->isChecked()) || (operation_type==1)){

            QStringList importedFileNames = fileDlg.getOpenFileNames(this,tr("Select files"),last_selected_dir,type);

            if(importedFileNames.size() == 0){
                QMessageBox::warning(this,op_string,"No file imported !");
                return;
            }

            QFileInfo fi = importedFileNames.at(0);
            last_selected_dir = fi.absolutePath();

            for (int i = 0; i < importedFileNames.size(); i++){
                this->files_list->addItem(importedFileNames.at(i));
            }
        }

        if((r_usePassKey->isChecked()) && (operation_type==2)){

            QString importedFileName = fileDlg.getOpenFileName(this,tr("Select files"),last_selected_dir,type);

            if(importedFileName.size() == 0){
                QMessageBox::warning(this,op_string,"No file imported !");
                return;
            }

            QFileInfo fi = importedFileName;
            last_selected_dir = fi.absolutePath();

            this->files_list->addItem(importedFileName);
        }

        /*GUI*/
        //encryption case
        if(operation_type==1) {
            b_encFiles->setEnabled(true);
        }
        //decryption case
        if(operation_type==2) {
            b_decFiles->setEnabled(true);
        }
        b_rem->setEnabled(true);
        b_remAll->setEnabled(true);

        return;
}

void mainForm::showPesInfo(QListWidgetItem* i){

    if(!(i->text()).endsWith(".pes")){
        return;
    }

    //check if plug-up inserted
    int ret=selectPup();
    if(ret == 0){
        QMessageBox::warning(this,"PES Infos",tr("No plug-up inserted !"));
        return;
    }

    //*If Linux OS
    if(ret == -1){
        QMessageBox::warning(this,"PES Infos",tr("It seems that no udev rule is set !\n\nFollow the \"How_To_Add_udev_Rule.txt\" steps in order to fix this problem."));
        //return;
    }
    //*/

    /*If Windows OS
    if(ret == -1){
        QMessageBox::warning(this,"PES Infos",tr("Cannot open plug-up device !"));
        return;
    }
    //*/

    //check if encryption plug-up
    int r = isAnEncryptionPup(h,ENC_KEYSET_VERSION);
    if(r==0){
        QMessageBox::warning(this,"PES Infos",tr("Not an encryption plug-up !\nConfigure your plug-up please."));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }
    if(r==2){
        QMessageBox::warning(this,"PES Infos",tr("An error occured when trying to verify plug-up configuration.\nBefore using your plug-up, you must configure it :\nConfiguration > Create an encryption plug-up\n\nIf you have already configure your plug-up, remove it, reinsert it then retry."));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }

    /*check for SN & pass (if an encryption plug-up is successfuly authenticated, dont ask for pass until the app
    restarted or the plug-up replaced with another)*/
    char getSN_data[255*2+1]="", getSN_sw[2*2+1]="";
    exchangeApdu(h,"80e6000012",getSN_data,getSN_sw);
    if(strcmp(getSN_sw,"9000")){
        QMessageBox::warning(this,"PES Infos",tr("Cannot retreive plug-up SN !\nRemove plug-up, reinsert it, then retry."));
        freePup();
        return;
    }
    if(strcmp(getSN_data,this->lastSN)){
        bool ok;
        QString pin = QInputDialog::getText(this, tr("Enter your password"),tr("Plug-up password:"), QLineEdit::Password,"",&ok);
        if(ok){
            //open SC to PASS_KEYSET to verify user pass
            if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,pin.toStdString().c_str())){
                QMessageBox::warning(this,"PES Infos","Authentication error ! Make sure that you enter the right password. Remove plug-up, reinsert it, then retry.");
                freePup();
                return;
            }
            else{
                strcpy(this->lastSN,getSN_data);
                strcpy(this->lastPass,pin.toStdString().c_str());
            }
        }
        else{
            freePup();
            return;
        }
    }

    //open SC to PASS_KEYSET
    if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,this->lastPass)){
        QMessageBox::warning(this,"PES Infos","Authentication error ! Remove plug-up, reinsert it, then retry.");
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }

    char fileEncryptionKey[16*2+1]="";
    if(!retreiveFileEncryptionKeyFromEncryptedFile(h,i->text().toStdString().c_str(),ENC_KEYSET_VERSION,fileEncryptionKey)){
        QMessageBox::warning(this,"PES Infos","Cannot retreive file encryption key.");
        freePup();
        return;
    }

    /*GUI*/
    pesInfotxt.clear();
    pesInfotxt.append("<html><b>");
    pesInfotxt.append(i->text());
    pesInfotxt.append("</b><br/><br/>If you want to share this encrypted file with someone, ");
    pesInfotxt.append("send him <b><font color=red>securely</font></b> the following key in order to decrypt the file.<br/><br/>");
    pesInfotxt.append("For example, you can use email for sharing the encrypted file and sms message to send the decryption key.");
    pesInfotxt.append("<br/><br/><b>DECRYPTION KEY:<br/><font color=green>");
    pesInfotxt.append(tr(fileEncryptionKey));
    pesInfotxt.append("</font></b></html>");
    pesInfo->setText(pesInfotxt);
    pesInfo->setGeometry(10,10,417,170);
    init();
    pesInfo->setHidden(false);
    b_closePesInfo->setHidden(false);
    resizeGui(3);

    freePup();
    return;
}

void mainForm::closePesInfo(){

    init();

    files_list->setHidden(false);

    if(operation_type==3){
        l_op_result->setHidden(false);
        resizeGui(2);
    }
    else
    {
        l_operation_type->setHidden(false);
        b_selectFiles->setHidden(false);
        b_rem->setHidden(false);
        b_remAll->setHidden(false);

        if(operation_type==1){
            //Hide
            b_encFiles->setHidden(false);
            //b_selectDir->setHidden(false);
        }

        if(operation_type==2){
            //Hide
            b_decFiles->setHidden(false);
            r_usePlugUp->setHidden(false);
            r_usePassKey->setHidden(false);
        }
    }

    return;
}

void mainForm::encryptFiles(){

    cryptoEncDec(1);
    return;

}

void mainForm::decryptFiles(){

    if(r_usePlugUp->isChecked()) cryptoEncDec(0);
    if(r_usePassKey->isChecked()) decryptWithoutPlugup();
    return;

}

void mainForm::cryptoEncDec(int encDec){

    QString op_string, op_string2;

    if(encDec){
        op_string = tr("Encryption");
        op_string2 = tr("encrypted");
    }
    else{
        op_string = tr("Decryption");
        op_string2 = tr("decrypted");
    }

    //check if plug-up inserted
    int ret=selectPup();
    if(ret == 0){
        QMessageBox::warning(this,"Files "+op_string,tr("No plug-up inserted !"));
        return;
    }

    //*If Linux OS
    if(ret == -1){
        QMessageBox::warning(this,"Files "+op_string,tr("It seems that no udev rule is set !\n\nFollow the \"How_To_Add_udev_Rule.txt\" steps in order to fix this problem."));
        //return;
    }
    //*/

    /*If Windows OS
    if(ret == -1){
        QMessageBox::warning(this,"Files "+op_string,tr("Cannot open plug-up device !"));
        return;
    }
    //*/

    //check if encryption plug-up
    int r = isAnEncryptionPup(h,ENC_KEYSET_VERSION);
    if(r==0){
        QMessageBox::warning(this,"Files "+op_string,tr("Not an encryption plug-up !\nConfigure your plug-up please."));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }
    if(r==2){
        QMessageBox::warning(this,"Files "+op_string,tr("An error occured when trying to verify plug-up configuration.\nBefore using your plug-up, you must configure it :\nConfiguration > Create an encryption plug-up\n\nIf you have already configure your plug-up, remove it, reinsert it then retry."));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }

    /*check for SN & pass (if an encryption plug-up is successfuly authenticated, dont ask for pass until the app
    restarted or the plug-up replaced with another)*/
    char getSN_data[255*2+1]="", getSN_sw[2*2+1]="";
    exchangeApdu(h,"80e6000012",getSN_data,getSN_sw);
    if(strcmp(getSN_sw,"9000")){
        QMessageBox::warning(this,"Files "+op_string,tr("Cannot retreive plug-up SN !\nRemove plug-up, reinsert it, then retry."));
        freePup();
        return;
    }
    if(strcmp(getSN_data,this->lastSN)){
        bool ok;
        QString pin = QInputDialog::getText(this, tr("Enter your password"),tr("Plug-up password:"), QLineEdit::Password,"",&ok);
        if(ok){
            //open SC to PASS_KEYSET to verify user pass
            if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,pin.toStdString().c_str())){
                QMessageBox::warning(this,"Files "+op_string,"Authentication error ! Make sure that you enter the right password. Remove plug-up, reinsert it, then retry.");
                freePup();
                return;
            }
            else{
                strcpy(this->lastSN,getSN_data);
                strcpy(this->lastPass,pin.toStdString().c_str());
            }
        }
        else{
            freePup();
            return;
        }
    }

    //open SC to PASS_KEYSET
    if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,this->lastPass)){
        QMessageBox::warning(this,"Files "+op_string,"Authentication error ! Remove plug-up, reinsert it, then retry.");
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }

    /*use it : encryption/decryption*/
    //Operation progress
    QProgressDialog *progress = new QProgressDialog(op_string+"...","Abort",0,files_list->count(),this);
    progress->setWindowTitle(op_string+"..");
    progress->setWindowFlags(Qt::Tool | Qt::WindowTitleHint);
    progress->setLabelText(op_string+" is in progress...");
    progress->setModal(Qt::ApplicationModal);
    progress->show();
    progress->setValue(0);


    //encryption/decryption
    int ko=0;
    for (int i = 0; i < files_list->count(); i++){

        QString file = this->files_list->item(i)->text().toLocal8Bit();

        progress->setValue(i);//for progress bar
        qApp->processEvents();
        if (progress->wasCanceled()){
            break;
        }

        /*/For directory
        QFileInfo fi = file;
        if(fi.isDir()){
            FolderCompressor *fCompress = new FolderCompressor();
            if(!fCompress->compressFolder(file)){
                qDebug("\nCompressing folder error !");
            }
        }*/

        if(fileEncryption(h,file.toStdString().c_str(),ENC_KEYSET_VERSION,encDec)){

            if(encDec){
                /*if(fi.isDir()){
                    QFile encryptedDir(files_list->item(i)->text());
                    files_list->item(i)->setText(files_list->item(i)->text().append(".pesd"));
                    encryptedDir.rename(files_list->item(i)->text());
                }
                else{*/
                    files_list->item(i)->setText(files_list->item(i)->text().append(".pes"));
                //}
            }

            if(!encDec){
                if(files_list->item(i)->text().endsWith(".pes")){
                    files_list->item(i)->setText(files_list->item(i)->text().remove(files_list->item(i)->text().length()-4,4));
                }
            }

            this->files_list->item(i)->setTextColor(QColor("green"));
        }
        else{
            this->files_list->item(i)->setTextColor(QColor("red"));
            ko++;
        }

        qApp->processEvents();
    }

    progress->setValue(files_list->count()); //for progress bar


    if(ko){
        l_op_result->setText("Some files cannot be "+op_string2+" !");
        l_op_result->setStyleSheet("color:red;font-weight:bold;text-align:center;");
    }else{
        l_op_result->setText("All files are successfuly "+op_string2+".");
        l_op_result->setStyleSheet("color:green;font-weight:bold;text-align:center;");
    }

    operation_type = 3;

    /*GUI*/
    init();
    if(encDec){
        l_operation_type->setText("Files encryption..");
        b_enc->setEnabled(true);
    }
    if(!encDec){
        l_operation_type->setText("Files decryption..");
        b_dec->setEnabled(true);
    }
    l_operation_type->setHidden(false);
    files_list->setHidden(false);
    l_op_result->setHidden(false);
    files_list->setGeometry(10,35,375,145);
    resizeGui(2);

    freePup();
    return;
}

void mainForm::confPup(){

    QMessageBox::information(this,tr("Configure plug-up for encryption"),tr("To create an encryption plug-up, insert a plug-up key with firmware version 1.1.4 (or greater) and click ok."));

    //check if plug-up inserted
    int ret=selectPup();
    if(ret == 0){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("No plug-up inserted !"));
        return;
    }

    //*If Linux OS
    if(ret == -1){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("It seems that no udev rule is set !\n\nFollow the \"How_To_Add_udev_Rule.txt\" steps in order to fix this problem."));
        return;
    }
    //*/

    /*If Windows OS
    if(ret == -1){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Cannot open plug-up device !"));
        return;
    }
    //*/

    //*/check if not an encryption plug-up
    int r = isAnEncryptionPup(h,ENC_KEYSET_VERSION);
    if(r==1){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("The connected plug-up is already configured for encryption !"));
        freePup();
        return;
    }
    if(r==2){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("An error occured when trying to verify plug-up configuration.\nMake sure that the plug-up you have inserted is a compatible one.\nIf this is the case, remove it, reinsert it then retry."));
        freePup();
        return;
    }
    //*/

    //get plug-up SN
    char getSN_data[255*2+1]="", getSN_sw[2*2+1]="";
    exchangeApdu(h,"80e6000012",getSN_data,getSN_sw);
    if(strcmp(getSN_sw,"9000")){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Cannot retreive plug-up SN !\nRemove plug-up, reinsert it, then retry."));
        freePup();
        return;
    }

    //create plug-up password
    QString pin,pin2;
    int t = 0, dif=1;
    while(dif){
    pin = tr("");
    t=0;
        while(pin.length()<8){
            if(t) {QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Password must contain at least 8 characters !"));}
                bool ok;
                pin = QInputDialog::getText(this, tr("Configure plug-up for encryption"),tr("Enter new password:"), QLineEdit::Password,"",&ok);
                if(!ok){
                    freePup();
                    return;
                }
                t=1;
        }
        bool ok2;
        pin2 = QInputDialog::getText(this, tr("Configure plug-up for encryption"),tr("Enter the password again:"), QLineEdit::Password,"",&ok2);
        if(ok2){
            if(strcmp(pin.toStdString().c_str(),pin2.toStdString().c_str())){
                dif = 1;
                QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("The two passwords do not match ! Retry.."));
            }
            else{
                dif = 0;
            }
        }
        else{
            freePup();
            return;
        }
    }

    //create password keyset
    if(!createPlugUpAccess(h,pin.toStdString().c_str())){
        QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Cannot create password for plug-up ! "));
        freePup();
        return;
    }
    else{
        //open password keyset
        if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,pin.toStdString().c_str())){
            QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Authentication error ! "));
            freePup();
            return;
        }
        //create encryption keyset
        char encMasterKey[255*2+1]="";
        if(!createEncryptionMasterKey(h,encMasterKey)){
            QMessageBox::warning(this,tr("Configure plug-up for encryption"),tr("Cannot configure plug-up for encryption !"));
            //delete PASS_KEYSET
            freePup();
            return;
        }
        QMessageBox::information(this,tr("Configure plug-up for encryption"),tr("Your plug-up will use the following key to encrypt files.\nIf you lose your plug-up you cannot recover your files. To avoid this, print the following key, keep it secret and put it in a safe place. So it can be used to recover your encryption plug-up.\n\nKey : ")+encMasterKey);
        QMessageBox::information(this,tr("Configure plug-up for encryption"),tr("Your plug-up is successfuly configured for encryption and it is ready to use."));
    }

    //set lastSN & lastPass
    strcpy(this->lastSN,getSN_data);
    strcpy(this->lastPass,pin.toStdString().c_str());

    freePup();
}

void mainForm::chgPupPass(){

    //check if plug-up inserted
    int ret=selectPup();
    if(ret == 0){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("No plug-up inserted !"));
        return;
    }

    //*If Linux OS
    if(ret == -1){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("It seems that no udev rule is set !\n\nFollow the \"How_To_Add_udev_Rule.txt\" steps in order to fix this problem."));
        return;
    }
    //*/

    /*If Windows OS
    if(ret == -1){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("Cannot open plug-up device !"));
        return;
    }
    //*/

    //check if encryption plug-up
    int r = isAnEncryptionPup(h,ENC_KEYSET_VERSION);
    if(r==0){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("Not an encryption plug-up !\nConfigure your plug-up : Configuration > Create an encryption plug-up"));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }
    if(r==2){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("An error occured when trying to verify plug-up configuration.\nBefore using your plug-up, you must configure it :\nConfiguration > Create an encryption plug-up\n\nIf you have already configure your plug-up, remove it, reinsert it then retry."));
        strcpy(this->lastSN,"");
        strcpy(this->lastPass,"");
        freePup();
        return;
    }

    //get plug-up SN
    char getSN_data[255*2+1]="", getSN_sw[2*2+1]="";
    exchangeApdu(h,"80e6000012",getSN_data,getSN_sw);
    if(strcmp(getSN_sw,"9000")){
        QMessageBox::warning(this,tr("Change plug-up password"),tr("Cannot retreive plug-up SN !\nRemove plug-up, reinsert it, then retry."));
        freePup();
        return;
    }

    //Check pass
    bool ok;
    QString pin = QInputDialog::getText(this, tr("Enter your password"),tr("Plug-up password:"), QLineEdit::Password,"",&ok);
    if(ok){
        //open SC to PASS_KEYSET to verify user pass
        if(!openSC_UsingPass(h,PASS_KEYSET_VERSION,pin.toStdString().c_str())){
            QMessageBox::warning(this,tr("Change plug-up password"),"Authentication error ! Make sure that you enter the right password. Remove plug-up, reinsert it, then retry.");
            freePup();
            return;
        }
        else{
            //set new password
            QString pin1,pin2;
            int t = 0, dif=1;
            while(dif){
            pin1 = tr("");
            t=0;
                while(pin1.length()<8){
                    if(t) {QMessageBox::warning(this,tr("Change plug-up password"),tr("Password must contain at least 8 characters !"));}
                        bool ok;
                        pin1 = QInputDialog::getText(this, tr("Change plug-up password"),tr("Enter new password:"), QLineEdit::Password,"",&ok);
                        if(!ok){
                            freePup();
                            return;
                        }
                        t=1;
                }
                bool ok2;
                pin2 = QInputDialog::getText(this, tr("Change plug-up password"),tr("Enter the password again:"), QLineEdit::Password,"",&ok2);
                if(ok2){
                    if(strcmp(pin1.toStdString().c_str(),pin2.toStdString().c_str())){
                        dif = 1;
                        QMessageBox::warning(this,tr("Change plug-up password"),tr("The two passwords do not match ! Retry.."));
                    }
                    else{
                        //delete password keyset
                        if(!deleteKeyset(h,PASS_KEYSET_VERSION)){
                            QMessageBox::warning(this,tr("Change plug-up password"),"Cannot delete old password.");
                            freePup();
                            return;
                        }
                        dif = 0;
                    }
                }
                else{
                    freePup();
                    return;
                }
            }

            //create password keyset
            if(!createPlugUpAccess(h,pin1.toStdString().c_str())){
                QMessageBox::warning(this,tr("Change plug-up password"),tr("Cannot change plug-up password !"));
                freePup();
                return;
            }
            else{
                QMessageBox::warning(this,tr("Change plug-up password"),tr("Password changed successfuly !"));
                strcpy(this->lastSN,getSN_data);
                strcpy(this->lastPass,pin1.toStdString().c_str());
            }
        }
    }
    else{
        freePup();
        return;
    }

    freePup();
}

void mainForm::decryptWithoutPlugup(){

    QString file = files_list->item(0)->text().toLocal8Bit();
    int tryPassKey = 0;
    bool ok;
    while(tryPassKey < 3){
        QString passKey = QInputDialog::getText(this, tr("Enter pass key"),tr("File decryption key:"), QLineEdit::Password,"",&ok);
        if(ok){
            //Decrypt using pass key
            if(!fileDecryptionUsingPassKey((char*)file.toStdString().c_str(),(char*)passKey.toStdString().c_str())){
                tryPassKey++;
                QMessageBox::warning(this,tr("Files decryption"),tr("Cannot decrypt file !\nMake sure you enter the right decryption key."));
            }
            else{
                files_list->item(0)->setTextColor(QColor("green"));
                files_list->item(0)->setText(files_list->item(0)->text().remove(files_list->item(0)->text().length()-4,4));
                l_op_result->setText("The file is successfuly decrypted.");
                l_op_result->setStyleSheet("color:green;font-weight:bold;text-align:center;");
                break;
            }

            operation_type = 3;

        }
        else{
            return;
        }
    }

    if(tryPassKey >= 3){
        files_list->item(0)->setTextColor(QColor("red"));
        l_op_result->setText("The file cannot be decrypted !");
        l_op_result->setStyleSheet("color:red;font-weight:bold;text-align:center;");
    }

    /*GUI*/
    init();
    l_operation_type->setText("Files decryption..");
    b_dec->setEnabled(true);
    l_operation_type->setHidden(false);
    files_list->setHidden(false);
    l_op_result->setHidden(false);
    files_list->setGeometry(10,35,375,145);
    resizeGui(2);

    return;
}

void mainForm::showHelpContent(){

    QMessageBox::information(this,tr("PuP Encryption software"),tr("Plug-up Encryption software for files encryption using a plug-up key. This software uses the OpenSSL library to encrypt files using the AES-CBC-128 algorithm.\n\nDeveloper: Saada BENAMAR\n<s.benamar@plug-up.com>\n<saada.benamar@gmail.com>\n\nSoftware icons designed by : Florian AUMONT\n<f.aumont@plug-up.com>\n\nPlug-up International 2013"));

    return;
}

void mainForm::exitApp(){
    resizeGui(1);
    this->close();
    return;
}



