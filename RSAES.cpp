#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

// chuyển sang dạng hex
#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

// hỗ trợ tiếng việt
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

// làm việc với chuỗi
#include <sstream>
using std::ostringstream;

#ifdef _WIN32
// thư viện dùng dể setmode trong window
#include <io.h>
#include <fcntl.h>
// số byte cần bỏ trong stdin sau wcin trong window
#define DISCARD 2
// đồng bộ hóa cho wcin và wcout trong window
void io_syntax()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
}
#define IOSYNTAX io_syntax()
#elif __linux__
// số byte cần bỏ trong stdin sau wcin trong linux
#define DISCARD 1
// đồng bộ wcin và wcout cho linux
#define IOSYNTAX setlocale(LC_ALL, "")
#else
#endif

wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
wstring integer_to_wstring(const CryptoPP::Integer &t);
void InputPlainFromScreen(string &plain);
void InputCipherFromScreen(string &cipher);
template <typename T>
void ReadKeyFromFile(T &key, const string &filename);
void RSA_Encryption(const string &plain, string &cipher, RSA::PublicKey publicKey);
void RSA_Decryption(const string &cipher, string &recovered, RSA::PrivateKey privateKey);
void EncryptProcess();
void DecryptProcess();

int main()
{
    // đồng bộ với hệ điều hành
    IOSYNTAX;
    // khai báo các biến
    int choice;
    // main process
    wcout << "Welcome to RSA cryptography\n";
    while (true)
    {
        wcout << "---------------------\n\n";
        wcout << "1. Encrypt\n";
        wcout << "2. Decrypt\n";
        wcout << "3. Exit\n";
        wcout << "Select your choice: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            EncryptProcess();
            break;
        case 2:
            DecryptProcess();
            break;
        case 3:
            wcout << "Bye";
            return 0;
        default:
            wcout << "What did you choose!!!";
            exit(-1);
            break;
        }
    }

    return 0;
}
// chuyển INTEGER trong Cryptopp thành wstring
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // đưa t vào trong luồng oss
    std::string encoded(oss.str()); // khởi tạo một chuỗi với luồng oss
    return string_to_wstring(encoded);
}
// chuyển string thành wstring
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
// chuyển wstring thành string
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
// nhập plain text từ màn hình và lưu vào biến plain(string)
void InputPlainFromScreen(string &plain)
{
    //nhập plaintext từ bàn phím
    wstring wplain;
    wplain.clear();
    // nhập và kiểm tra plaintext
    int tmp = 0;
    do
    {
        if (tmp)
            wcout << "Input too long! Please input again: ";
        else
            wcout << "Please input plaintext: ";
        // bỏ các ký tự '\n' trong stdin tương ứng với từng hệ điều hành
        wcin.ignore(DISCARD - tmp);
        // nhập chuỗi
        getline(wcin, wplain);
        tmp = 1;
    } while (wplain.length() > 342);

    // chuyển wplain(wstring) về plain(string)
    plain = wstring_to_string(wplain);
}
// nhập cipher text từ màn hình và lưu vào biến cipher(string)
void InputCipherFromScreen(string &cipher)
{
    //nhập plaintext từ bàn phím
    wstring wcipher;
    wcipher.clear();
    // nhập và kiểm tra ciphertext
    wcout << "Please input ciphertext (hex number): ";
    // bỏ các ký tự '\n' trong stdin tương ứng với từng hệ điều hành
    wcin.ignore(DISCARD);
    // nhập chuỗi
    getline(wcin, wcipher);
    // chuyển wcipher(wstring) về cipher(string)
    string hexCipher = wstring_to_string(wcipher);
    // chuyển cipher từ hex string về ascii string
    cipher.clear();
    StringSource(hexCipher, true, new HexDecoder(new StringSink(cipher)));
}
// đọc key từ file
template <typename T>
void ReadKeyFromFile(T &key, const string &filename)
{
    FileSource fs(filename.c_str(), true);
    key.BERDecode(fs);
}
// Encrypt process
void EncryptProcess()
{
    try
    {
        clock_t start, end;
        string plain, encoded, cipher;
        RSA::PublicKey publicKey;
        int choice;
        wcout << "---------------------\n\n";
        wcout << "1. From file test342bytes.txt\n";
        wcout << "2. From console\n";
        wcout << "Select your plaintext: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            plain.clear();
            FileSource("test342bytes.txt", true, new StringSink(plain));
            break;
        case 2:
            InputPlainFromScreen(plain);
            break;
        default:
            break;
        }
        ReadKeyFromFile<RSA::PublicKey>(publicKey, "rsa-public.key");
        wcout << "---------------------\n\n";
        wcout << "Plain text size: " << plain.length() << endl;
        wcout << "Plain text: " << string_to_wstring(plain) << endl;
        wcout << "RSA key size: " << integer_to_wstring(publicKey.GetModulus().BitCount()) << endl;
        wcout << "Public modulo n: " << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << "Public key e: " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << "---------------------\n\n";
        // encrypt
        start = clock();
        for (int i = 0; i < 10000; ++i)
            RSA_Encryption(plain, cipher, publicKey);
        end = clock();
        // đưa chuỗi về dạng hex có thể đọc được
        encoded.clear();
        StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
        wcout << "cipher text:" << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
        // lưu cipher text vào file ciphertext.txt
        StringSource(cipher, true, new FileSink("ciphertext.txt"));
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
    catch (std::exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}
// Decrypt process
void DecryptProcess()
{
    try
    {
        clock_t start, end;
        string cipher, encoded, recovered;
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        int choice;
        wcout << "---------------------\n\n";
        wcout << "1. From file ciphertext.txt\n";
        wcout << "2. From console\n";
        wcout << "Select your ciphertext: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            cipher.clear();
            FileSource("ciphertext.txt", true, new StringSink(cipher));
            break;
        case 2:
            InputCipherFromScreen(cipher);
            break;
        default:
            break;
        }
        ReadKeyFromFile<RSA::PrivateKey>(privateKey, "rsa-private.key");
        ReadKeyFromFile<RSA::PublicKey>(publicKey, "rsa-public.key");
        // chuyển chuỗi cipher về dạng hex có thể đọc được
        StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
        wcout << "---------------------\n\n";
        wcout << "cipher text size: " << cipher.length() << endl;
        wcout << "cipher text: " << string_to_wstring(encoded) << endl;
        wcout << "RSA key size: " << integer_to_wstring(publicKey.GetModulus().BitCount()) << endl;
        wcout << "Public modulo n: " << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << "Public key e: " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << "Private prime number p: " << integer_to_wstring(privateKey.GetPrime1()) << endl;
        wcout << "Private prime number q: " << integer_to_wstring(privateKey.GetPrime2()) << endl;
        wcout << "Secret key d: " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        wcout << "---------------------\n\n";
        // decrypt
        start = clock();
        for (int i = 0; i < 10000; ++i)
            RSA_Decryption(cipher, recovered, privateKey);
        end = clock();
        wcout << "recover text: " << string_to_wstring(recovered) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
    catch (std::exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}
// RSA encryption
void RSA_Encryption(const string &plain, string &cipher, RSA::PublicKey publicKey)
{
    try
    {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        cipher.clear();
        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)));
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}
// RSA decryption
void RSA_Decryption(const string &cipher, string &recovered, RSA::PrivateKey privateKey)
{
    try
    {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        recovered.clear();
        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)));
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}
