#include "cryptographiccalculator.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    CryptographicCalculator w;
    w.show();

    return a.exec();
}
