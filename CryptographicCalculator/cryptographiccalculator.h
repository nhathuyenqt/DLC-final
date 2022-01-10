#ifndef CRYPTOGRAPHICCALCULATOR_H
#define CRYPTOGRAPHICCALCULATOR_H

#include <QMainWindow>

namespace Ui {
class CryptographicCalculator;
}

class CryptographicCalculator : public QMainWindow
{
    Q_OBJECT

public:
    explicit CryptographicCalculator(QWidget *parent = 0);
    ~CryptographicCalculator();

private slots:
    void on_actionAbout_triggered();

    void on_actionExit_triggered();

    void on_pushButton_clicked();

    void on_actionRSA_triggered();

    void on_actionHashes_triggered();

    void on_button_genkey_clicked();

    void on_btn_encrypt_rsa_clicked();

    void on_actionECDSA_triggered();

    void on_actionDES_triggered();

    void on_encrypt_btn_clicked();

    void on_decrypt_btn_clicked();

    void on_genKeyBtn_clicked();

    void on_signBtn_clicked();

    void on_verifyBtn_clicked();

    void on_clearBtn_clicked();

    void on_btn_decrypt_rsa_clicked();

    void on_btn_sign_rsa_clicked();

    void on_btn_verify_rsa_clicked();

    bool check_empty(QString str);

    bool check_key_empty(QString str);

    bool check_hex_format(QString str);


    void on_actionAES_triggered();

    void on_aes_encrypt_Button_clicked();

    void on_aes_decrypt_button_clicked();

    void on_actionFIle_triggered();

    void on_file_encrypt_clicked();

    void on_file_decrypt_clicked();

    void on_hmac_calc_button_clicked();

private:
    Ui::CryptographicCalculator *ui;
};

#endif // CRYPTOGRAPHICCALCULATOR_H
