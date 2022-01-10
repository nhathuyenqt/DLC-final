#include "cryptographiccalculator.h"
#include "ui_cryptographiccalculator.h"
#include "QMessageBox"
#include "QString"
#include "QCryptographicHash"
#include "gmp.h"
#include "time.h"
#include "rsaengine.h"
#include "desengine.h"
#include "ecdsaengine.h"
#include <QDebug>
#include "aesengine.h"
#include <string.h>
#include "hmacengine.h"

#define RSA_PKCS1_PADDING_SIZE 11


CryptographicCalculator::CryptographicCalculator(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::CryptographicCalculator)
{
    ui->setupUi(this);
//    ui->comboBox->addItem("MD4");
    QStringList list=(QStringList()<<"MD4"<<"MD5"<<"SHA1"<<"SHA224"<<"SHA256"<<"SHA384"<<"SHA512");
    ui->comboBox->addItems(list);
    ui->comboBox_sign->addItems(list);
}

CryptographicCalculator::~CryptographicCalculator()
{
    delete ui;
}

void CryptographicCalculator::on_actionAbout_triggered()
{
    QMessageBox::information(this,"About us", "We are vCryptis Team!");
}

void CryptographicCalculator::on_actionExit_triggered()
{
    QApplication::quit();
}

bool CryptographicCalculator::check_empty(QString str){
    if (str.isEmpty()){
        QMessageBox::critical(this,"Cryptographical Calculator: Data size error!  ", "Input data field empty.\nAction canceled.");
        return 1;
    }
    return 0;
}
bool CryptographicCalculator::check_key_empty(QString str){
    if (str.isEmpty()){
        QMessageBox::critical(this,"Cryptographical Calculator: Key is empty  ", "Key fields are empty. Please generate key first!\nAction canceled.");
        return 1;
    }
    return 0;
}
bool CryptographicCalculator::check_hex_format(QString str){
    QRegExp hexMatcher("^[0-9A-Fa-f]*$", Qt::CaseInsensitive);
    if (!hexMatcher.exactMatch(str))
    {
        QMessageBox::critical(this,"Cryptographical Calculator: Data format error!  ", "Data field contains non-hexadecimal character.\nAction canceled.");
        return 0;
    }
    return 1;
}

QCryptographicHash::Algorithm get_hash_method(int index){
    QCryptographicHash::Algorithm method;
    switch (index) {
        case 0:
            method = QCryptographicHash::Md4;
            break;
        case 1:
            method = QCryptographicHash::Md5;
            break;
        case 2:
            method = QCryptographicHash::Sha1;
            break;
        case 3:
            method = QCryptographicHash::Sha224;
            break;
        case 4:
            method = QCryptographicHash::Sha256;
            break;
        case 5:
            method = QCryptographicHash::Sha384;
            break;
        case 6:
            method = QCryptographicHash::Sha512;
            break;
        default:
            method = QCryptographicHash::Md5;
    }
    return method;
}

void CryptographicCalculator::on_pushButton_clicked()
{
    QString str = ui->textData->toPlainText();
    QCryptographicHash::Algorithm method;
    method = get_hash_method(ui->comboBox->currentIndex());


    QString hash_string = QString(QCryptographicHash::hash((str.toUtf8()),method).toHex());
    ui->textResult->setText(hash_string);
}

void CryptographicCalculator::on_actionRSA_triggered()
{
    ui->label_main->setText("RSA");
    ui->stackedWidget->setCurrentIndex(1);
}

void CryptographicCalculator::on_actionHashes_triggered()
{
    ui->label_main->setText("HASH CALCULATOR");
    ui->stackedWidget->setCurrentIndex(0);
}

void CryptographicCalculator::on_button_genkey_clicked(){

    unsigned int key_length = ui->txt_keylength->value();
    unsigned int e = (ui->txt_e->text()).toInt();
    RSAengine rsa;
    mpz_t n, d;
    char *str=0;
    rsa.genKey(n, d, key_length, e);
    str = mpz_get_str(NULL, 16, n);
    QString s=QString(str);
    ui->txt_n->setPlainText(s);
    qDebug() << "genkey: " << s;
    str = mpz_get_str(NULL, 16, d);
    s=QString(str);
    ui->txt_d->setPlainText(s);

}
//char * padding(char *m, char *n, char *e){
//    int k = strlen(n);
//    int mLen = strlen(m);
//    if (mLen > k -11)
//}

void CryptographicCalculator::on_btn_encrypt_rsa_clicked()
{
    if (check_empty(ui->txt_rsa_enc->toPlainText()) || check_key_empty(ui->txt_n->toPlainText()) || check_key_empty(ui->txt_e->text())){
        return;
    }
    if (!check_hex_format(ui->txt_d->toPlainText()) || !check_hex_format(ui->txt_e->text()) || !check_hex_format(ui->txt_n->toPlainText())){
        return;
    }
    // Get the ID of the checked button, Defaults to -2, -3
    int btn_id = ui->buttonGroup->checkedId();
    QString str = ui->txt_rsa_enc->toPlainText();
    const char *str_m, *str_n, *str_e;
    str_m = str.toStdString().c_str();
    std::string tmp = ui->txt_n->toPlainText().toStdString();
    str_n = tmp.c_str();
    str_e = ui->txt_e->text().toStdString().c_str();

    RSAengine rsa;
    if (btn_id == -2){ // hexadecimal
        if (check_hex_format(str))
        {
            QString result = QString(rsa.encrypt_rsa(str_m,str_n,str_e));
            ui->textResult->setText(result);
            ui->txt_rsa_dec->setPlainText(result);
        }
        else {
            return;
        }
    }
    else { // Ascii
        QString result = QString(rsa.encrypt_rsa_ascii(str_m, str_n, str_e));
        ui->textResult->setText(result);
        ui->txt_rsa_dec->setPlainText(result);
    }
}

void CryptographicCalculator::on_actionECDSA_triggered()
{
    ui->label_main->setText("ECDSA");
    ui->stackedWidget->setCurrentIndex(3);
}

void CryptographicCalculator::on_actionDES_triggered()
{
    ui->label_main->setText("DES - Algorithm");
    ui->stackedWidget->setCurrentIndex(2);
}

void CryptographicCalculator::on_encrypt_btn_clicked()
{
    std::string str = ui->DES_input->toPlainText().toStdString();
    const char *plaintext = str.c_str();
    std::string str2 =ui->DES_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    qDebug("text %s, key %s", plaintext, key);
    DESengine des = DESengine();
    QString result = QString(des.desAlg(plaintext, key, 1));
    ui->textResult->setText(result);
}


void CryptographicCalculator::on_decrypt_btn_clicked()
{
    std::string str = ui->DES_input->toPlainText().toStdString();
    const char *ciphertext = str.c_str();
    std::string str2 =ui->DES_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    qDebug("decrypt cipher  %s, key %s", ciphertext, key);
    DESengine des = DESengine();
    QString result = QString(des.desAlg(ciphertext, key, 2));
    ui->textResult->setText(result);
}

void CryptographicCalculator::on_genKeyBtn_clicked()
{
    ECDSAengine ec = ECDSAengine();
    ec.generate_key_pair();
    qDebug("ECDSA key ");
    char*d = (char*)malloc(SIZE);
    char*Qx = (char*)malloc(SIZE);
    char*Qy = (char*)malloc(SIZE);

    mpz_get_str(d, 16, ec.d);
    mpz_get_str(Qx, 16, ec.Q.x);
    mpz_get_str(Qy, 16, ec.Q.y);

    ui->privKeyText->setText(d);
    ui->publicKeyX->setText(Qx);
    ui->publicKeyY->setText(Qy);

}

void CryptographicCalculator::on_signBtn_clicked()
{

    QString message = ui->ECDSA_input->toPlainText();
    qDebug("text " + message.toLatin1());
    ECDSAengine ecAlg = ECDSAengine();
    std::string priv = ui->privKeyText->toPlainText().toStdString();
    const char* priv_str = priv.c_str();
    mpz_set_str(ecAlg.d, priv_str, 16);
    qDebug("Sign with Private %s", priv_str);
    gmp_printf("check key %#Zx\n", ecAlg.d);
    ecAlg.sign(message);
    char* s = (char*)malloc(SIZE);
    mpz_get_str(s, 16, ecAlg.s);
    char* r = (char*)malloc(SIZE);
    mpz_get_str(r, 16, ecAlg.r);
    QString h = QString(QCryptographicHash::hash((message.toUtf8()), QCryptographicHash::Sha256).toHex());
    ui->textResult->append("Message Digest:");
    ui->textResult->append(h);
    QString result = QString("r : ") + QString(r);
    ui->textResult->append("Signature:");
    ui->textResult->append(result);
    result = QString("s : ") + QString(s);
    ui->textResult->append(result);
    ui->textResult->append("________________________");
    ui->rText->setText(r);
    ui->sText->setText(s);
    ui->derText->setText(ecAlg.der);
}

void CryptographicCalculator::on_verifyBtn_clicked()
{
    QString message = ui->ECDSA_input->toPlainText();
    ECDSAengine ecAlg = ECDSAengine();

    mpz_t r, s;
    mpz_inits(r, s, NULL);
    std::string priv = ui->privKeyText->toPlainText().toStdString();
    const char* priv_str = priv.c_str();
    std::string Q_x = ui->publicKeyX->toPlainText().toStdString();
    const char* Qx = Q_x.c_str();
    std::string Q_y = ui->publicKeyY->toPlainText().toStdString();
    const char* Qy = Q_y.c_str();
    mpz_set_str(ecAlg.d, priv_str, 16);
    mpz_set_str(ecAlg.Q.x, Qx, 16);
    mpz_set_str(ecAlg.Q.y, Qy, 16);
    qDebug("privD %s",priv_str);
    qDebug("pub x %s",Qx);
    qDebug("pub y %s",Qy);
    int tab = ui->sigTab->currentIndex();
    if (tab == 0){
        std::string str1 = ui->rText->toPlainText().toStdString();
        const char *r_str = str1.c_str();
        std::string str2 = ui->sText->toPlainText().toStdString();
        const char *s_str = str2.c_str();

        mpz_set_str(r, r_str, 16);
        mpz_set_str(s, s_str, 16);
        qDebug("Verify1\ns = %s\nr = %s\n", s_str, r_str);
    }else{
        std::string str = ui->derText->toPlainText().toStdString();
        const char *der_str = str.c_str();
        ecAlg.convertDerToRaw(der_str, r, s);

    }

    bool v = ecAlg.verify(message, r, s);
    if (v){
        ui->textResult->append("Signature Verified !!");
        ui->textResult->append("________________________");
    }else{
        ui->textResult->append("Signature Invalid !!");
        ui->textResult->append("________________________");
    }

}



void CryptographicCalculator::on_clearBtn_clicked()
{
    ui->textResult->clear();
}

void CryptographicCalculator::on_btn_decrypt_rsa_clicked()
{
    if (check_empty(ui->txt_rsa_dec->toPlainText()) || check_key_empty(ui->txt_n->toPlainText()) || check_key_empty(ui->txt_e->text())){
         return;
    }
    if (!check_hex_format(ui->txt_d->toPlainText()) || !check_hex_format(ui->txt_e->text()) || !check_hex_format(ui->txt_n->toPlainText())){
        return;
    }
    std::string tmp = ui->txt_n->toPlainText().toStdString();
    const char *str_n = tmp.c_str();
    qDebug() << "n = " << str_n;
    std::string tmp1 = ui->txt_rsa_dec->toPlainText().toStdString();
    const char *str_c = tmp1.c_str();
    std::string tmp2 = ui->txt_d->toPlainText().toStdString();
    const char *str_d = tmp2.c_str();
    RSAengine rsa;
    QString result = QString(rsa.decrypt_rsa(str_c, str_n, str_d));
    ui->textResult->setText(result);
}

void CryptographicCalculator::on_btn_sign_rsa_clicked()
{
    if (check_empty(ui->txt_rsa_sign->toPlainText()) || check_key_empty(ui->txt_n->toPlainText()) || check_key_empty(ui->txt_e->text())){
        return;
    }
    // Get the ID of the checked button, Defaults to -2, -3
    int btn_id = ui->buttonGroup->checkedId();
    if (btn_id == -2){ // hexadecimal
        if (!check_hex_format(ui->txt_rsa_sign->toPlainText())) return;
    }
    QCryptographicHash::Algorithm method;
    method = get_hash_method(ui->comboBox_sign->currentIndex());
    qDebug() << "combo index: " << ui->comboBox_sign->currentIndex();
    QString hash_string = QString(QCryptographicHash::hash((ui->txt_rsa_sign->toPlainText().toUtf8()),method).toHex());

    std::string tmp0 = hash_string.toStdString();
    qDebug() << "Hash sign: " << hash_string;
    const char *str_hash = tmp0.c_str();
    std::string tmp = ui->txt_n->toPlainText().toStdString();
    const char *str_n = tmp.c_str();
    std::string tmp1 = ui->txt_d->toPlainText().toStdString();
    const char *str_d = tmp1.c_str();

    //Padding PKCS-v1_5
    int k = strlen(str_n);
    int mLen = strlen(str_hash);
    if (mLen > k - RSA_PKCS1_PADDING_SIZE) {
        QMessageBox::critical(this,"Cryptographical Calculator: Data format error!  ", "Message too long.\nAction canceled.");
        return;
    }

    char *res = (char*)malloc(k*4*sizeof(char));
    char* PS = (char*)malloc(k*sizeof(char));
    for (int i = 0; i < k-mLen-3; i++) PS[i]='f';
    strcpy(res, "0002");
    strcat(res, PS);
    strcat(res,"00");
    strcat(res, str_hash);

    RSAengine rsa;
    QString result = QString(rsa.sign_rsa(res,str_d, str_n));
    ui->textResult->setText("Hashed String:   " + hash_string + "\nMessage Signature:   " + result);
    ui->txt_rsa_hash->setPlainText(hash_string);
    ui->txt_rsa_verify->setPlainText(result);
    // Free the memory
    free(res);
    free(PS);


}

void CryptographicCalculator::on_btn_verify_rsa_clicked()
{
    if (!check_hex_format(ui->txt_rsa_hash->toPlainText()) || !check_hex_format(ui->txt_rsa_verify->toPlainText())){
        return;
    }   
    if (check_empty(ui->txt_rsa_verify->toPlainText()) || check_key_empty(ui->txt_n->toPlainText()) || check_key_empty(ui->txt_e->text())){
            return;
    }
    std::string tmp0 =  ui->txt_rsa_verify->toPlainText().toStdString();
    const char *str_sign = tmp0.c_str();
    std::string tmp = ui->txt_n->toPlainText().toStdString();
    const char *str_n = tmp.c_str();
    std::string tmp1 = ui->txt_e->text().toStdString();
    const char *str_e = tmp1.c_str();
    std::string tmp2 = ui->txt_rsa_hash->toPlainText().toStdString();
    const char *str_hash = tmp2.c_str();

    //Padding PKCS-v1_5
    int k = strlen(str_n);
    int mLen = strlen(str_hash);
    if (mLen > k - RSA_PKCS1_PADDING_SIZE) {
        QMessageBox::critical(this,"Cryptographical Calculator: Data format error!  ", "Message too long.\nAction canceled.");
        return;
    }

    char *res = (char*)malloc(k*4*sizeof(char));

    RSAengine rsa;
    const char* hashFromSignature = rsa.verify_rsa(str_sign,str_e, str_n);
    qDebug() << "Hash " << str_hash;
    qDebug() << "str_sign " << str_sign;
    qDebug() << "from Sign: " << hashFromSignature;
    strcpy(res, &hashFromSignature[strlen(hashFromSignature) - strlen(str_hash)]);
    qDebug() << "res: " << res;
    if (!strcmp(str_hash, res))
        ui->textResult->setText("Verifying message - SUCCESSFUL.");
    else
        ui->textResult->setText("Verifying message - FAIL.");
    // Free the memory
    free(res);
}

void CryptographicCalculator::on_actionAES_triggered()
{
    ui->label_main->setText("AES-CBC");
    ui->stackedWidget->setCurrentIndex(4);
}

void CryptographicCalculator::on_aes_encrypt_Button_clicked()
{
    std::string str = ui->aes_enc_input->toPlainText().toStdString();
    const char *plaintext = str.c_str();
    std::string str2 =ui->aes_enc_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    std::string str3 =ui->aes_enc_iv->toPlainText().toStdString();
    const char *initvector = str3.c_str();
    qDebug("text %s, key %s, iv %s", plaintext, key, initvector);

    unsigned long keysize;
    if (ui->comboBox_2->currentText() == "256 bits"){
        keysize = 256;
    }
    else {
        keysize = 128;
    }

    if (strlen(plaintext) == 0) {
        ui->textResult->setText("Empty plaintext");
    }
    else if (strlen(key)*8 != keysize){
        ui->textResult->setText("Key size not matching");
    }
    else if (strlen(initvector)*8 != 128) {
        ui->textResult->setText("IV size must be 128 bits");
    }
    else {
        AESengine aes = AESengine();
        int cipher_len;
        const char *result = (const char *)aes.encrypt(plaintext, strlen(plaintext), keysize, key, initvector,&cipher_len);
        QByteArray array((const char *)result, cipher_len);
        ui->textResult->setText(QString(array.toHex()));
    }
}

void CryptographicCalculator::on_aes_decrypt_button_clicked()
{
    std::string str = ui->aes_dec_input->toPlainText().toStdString();
    const char *ciphertext = str.c_str();
    std::string str2 =ui->aes_dec_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    std::string str3 =ui->aes_dec_iv->toPlainText().toStdString();
    const char *initvector = str3.c_str();
    qDebug("text %s, key %s, iv %s", ciphertext, key, initvector);
    unsigned long keysize;
    if (ui->comboBox_3->currentText() == "256 bits"){
        keysize = 256;
    }
    else {
        keysize = 128;
    }

    if (strlen(ciphertext) == 0) {
        ui->textResult->setText("Empty ciphertext");
    }
    else if (strlen(key)*8 != keysize){
        ui->textResult->setText("Key size not matching");
    }
    else if (strlen(initvector)*8 != 128) {
        ui->textResult->setText("IV size must be 128 bits");
    }
    else if (strlen(ciphertext)%16 != 0){
        ui->textResult->setText("ciphertext invalid length");
    }
    else {
        AESengine aes = AESengine();
        int plaintext_len;
        const char *result = (const char *)aes.decrypt(ciphertext, strlen(ciphertext)/2, keysize, key, initvector,&plaintext_len);
        ui->textResult->setText(QString(result));
    }
}


void CryptographicCalculator::on_actionFIle_triggered()
{
    ui->label_main->setText("File Encrypt/Decrypt using AES");
    ui->stackedWidget->setCurrentIndex(5);
}

void CryptographicCalculator::on_file_encrypt_clicked()
{
    std::string str = ui->input_file_enc->text().toStdString();
    const char *filepath = str.c_str();
    std::string str2 =ui->file_enc_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    std::string str3 =ui->file_enc_iv->toPlainText().toStdString();
    const char *initvector = str3.c_str();

    unsigned long keysize;
    if (ui->comboBox_file_keysize_enc->currentText() == "256 bits"){
        keysize = 256;
    }
    else {
        keysize = 128;
    }

    const char *mode;
    if (ui->comboBox_file_mode_enc->currentText() == "ECB"){
        mode = "ECB";
    }
    else {
        mode = "CBC";
    }

    if (strlen(filepath) == 0) {
        ui->textResult->setText("Empty filepath");
    }
    else if (strlen(key)*8 != keysize){
        ui->textResult->setText("Key size not matching");
    }
    else if (strlen(initvector)*8 != 128) {
        ui->textResult->setText("IV size must be 128 bits");
    }
    else {
        AESengine aes = AESengine();
        char *result = aes.encrypt_file(filepath, mode, keysize, key, initvector);
        std::string notistr = "File " + str +" encrypt result:\n" + std::string(result) ;
        ui->textResult->setText(QString::fromStdString(notistr));
    }
}

void CryptographicCalculator::on_file_decrypt_clicked()
{
    std::string str = ui->input_file_dec->text().toStdString();
    const char *filepath = str.c_str();
    std::string str2 =ui->file_dec_key->toPlainText().toStdString();
    const char *key = str2.c_str();
    std::string str3 =ui->file_dec_iv->toPlainText().toStdString();
    const char *initvector = str3.c_str();

    unsigned long keysize;
    if (ui->comboBox_file_keysize_dec->currentText() == "256 bits"){
        keysize = 256;
    }
    else {
        keysize = 128;
    }

    const char *mode;
    if (ui->comboBox_file_mode_dec->currentText() == "ECB"){
        mode = "ECB";
    }
    else {
        mode = "CBC";
    }

    if (strlen(filepath) == 0) {
        ui->textResult->setText("Empty filepath");
    }
    else if (strlen(key)*8 != keysize){
        ui->textResult->setText("Key size not matching");
    }
    else if (strlen(initvector)*8 != 128) {
        ui->textResult->setText("IV size must be 128 bits");
    }
    else {
        AESengine aes = AESengine();
        char *result = aes.decrypt_file(filepath, mode, keysize, key, initvector);
        std::string notistr = "File " + str +" decrypted result:\n" + std::string(result) ;
        ui->textResult->setText(QString::fromStdString(notistr));
    }
}

void CryptographicCalculator::on_hmac_calc_button_clicked()
{
    std::string str = ui->hmac_input_file->text().toStdString();
    const char *filepath = str.c_str();
    std::string str2 =ui->hmac_key->toPlainText().toStdString();
    const char *key = str2.c_str();

    int mode;
    if (ui->comboBox_hmac_mode->currentText() == "SHA1"){
        mode = 1;
    }
    else if (ui->comboBox_hmac_mode->currentText() == "SHA256") {
        mode = 2;
    }
    else mode = 0;

    if (strlen(filepath) == 0) {
        ui->textResult->setText("Empty filepath");
    }
    else {
        HMACengine hmacengine = HMACengine();
        int signal = 0;
        int hmac_len;
        unsigned char *result = hmacengine.calculate(filepath,key,&hmac_len,mode,&signal);
        if (signal == 0) {
            QByteArray array((const char *)result, hmac_len);
            ui->textResult->setText(QString("HMAC result:\n") + QString(array.toHex()));
        }
        else {
            std::string notistr = "HMAC result:\n" + std::string((const char*)result) ;
            ui->textResult->setText(QString::fromStdString(notistr));
        }

    }
}
