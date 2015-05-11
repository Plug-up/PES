#include <QApplication>
#include "mainForm.h"

using namespace std;

int main(int argc,char* argv[]){

    QApplication gui(argc,argv);
    mainForm mf;
    mf.show();
    return gui.exec();

}

