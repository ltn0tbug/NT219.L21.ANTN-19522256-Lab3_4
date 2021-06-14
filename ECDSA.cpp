
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::byte;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/hex.h"
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

#include <time.h>

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

wstring integer_to_wstring(const CryptoPP::Integer &t);
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);
void SignProcess();
void VerifyProcess();
bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const string &message, string &signature);
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &publicKey, const string &message, const string &signature);

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
        wcout << "1. Signature\n";
        wcout << "2. Verify\n";
        wcout << "3. Exit\n";
        wcout << "Select your choice: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            SignProcess();
            break;
        case 2:
            VerifyProcess();
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
// quá trình tạo signature
void SignProcess()
{
    try
    {
        // khai báo các biến
        ECDSA<ECP, SHA256>::PrivateKey privateKey;
        string signature, message, encoded;
        clock_t start, end;
        // lấy private key từ file ec-private.key (PKCS#9 and X.509 format)
        privateKey.Load(FileSource("ec-private.key", true).Ref());
        // lấy chuỗi từ file test342bytes.txt
        FileSource("test342bytes.txt", true, new StringSink(message));

        DL_GroupParameters_EC<ECP> params = privateKey.GetGroupParameters();
        wcout << "---------------------\n\n";
        wcout << "Message: " << string_to_wstring(message) << endl;
        wcout << endl;
        wcout << "Private Exponent: " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        wcout << endl;
        wcout << "Modulus: " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;
        wcout << "Coefficient A: " << integer_to_wstring(params.GetCurve().GetA()) << endl;
        wcout << "Coefficient B: " << integer_to_wstring(params.GetCurve().GetB()) << endl;
        wcout << "Gx: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl;
        wcout << "Gy: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;
        wcout << "Subgroup Order: " << integer_to_wstring(params.GetSubgroupOrder()) << endl;
        wcout << "Cofactor: " << integer_to_wstring(params.GetCofactor()) << endl;
        wcout << "---------------------\n\n";

        // tạo chữ ký
        bool signSuccess;
        start = clock();
        for (int i = 0; i < 10000; i++)
            signSuccess = SignMessage(privateKey, message, signature);
        end = clock();
        // tạo chữ ký thành công
        if (signSuccess)
            wcout << "Sign succesed" << endl;
        else
        {
            wcout << "Sign failed" << endl;
            exit(-1);
        }
        // chuyển signature sang chuỗi hex và in ra màn hình
        StringSource(signature, true, new HexEncoder(new StringSink(encoded)));
        wcout << "Signature: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;

        // lưu signature và fiel signature.txt
        StringSource(signature, true, new FileSink("signature.txt"));
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
// quá trình tạo verify
void VerifyProcess()
{
    try
    {
        // khai báo các biến
        ECDSA<ECP, SHA256>::PublicKey publicKey;
        string signature, message, encoded;
        clock_t start, end;
        // lấy public key key từ file ec-public.key (PKCS#9 and X.509 format)
        publicKey.Load(FileSource("ec-public.key", true).Ref());
        // lấy chuỗi từ file test342bytes.txt
        FileSource("test342bytes.txt", true, new StringSink(message));
        // lấy sign trong file signature.txt
        FileSource("signature.txt", true, new StringSink(signature));

        // chuyển signature sang chuỗi hex
        StringSource(signature, true, new HexEncoder(new StringSink(encoded)));
        DL_GroupParameters_EC<ECP> params = publicKey.GetGroupParameters();
        wcout << "---------------------\n\n";
        wcout << "Message: " << string_to_wstring(message) << endl;
        wcout << "Signature: " << string_to_wstring(encoded) << endl;
        wcout << endl;
        wcout << "Public key Qx : " << integer_to_wstring(publicKey.GetPublicElement().x) << endl;
        wcout << "Public key Qy : " << integer_to_wstring(publicKey.GetPublicElement().y) << endl;
        wcout << endl;
        wcout << "Modulus: " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;
        wcout << "Coefficient A: " << integer_to_wstring(params.GetCurve().GetA()) << endl;
        wcout << "Coefficient B: " << integer_to_wstring(params.GetCurve().GetB()) << endl;
        wcout << "Gx: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl;
        wcout << "Gy: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;
        wcout << "Subgroup Order: " << integer_to_wstring(params.GetSubgroupOrder()) << endl;
        wcout << "Cofactor: " << integer_to_wstring(params.GetCofactor()) << endl;
        wcout << "---------------------\n\n";

        // xác thực chữ ký
        bool verifySuccess;
        start = clock();
        for (int i = 0; i < 10000; i++)
            verifySuccess = VerifyMessage(publicKey, message, signature);
        end = clock();
        // xác thực thành công
        if (verifySuccess)
            wcout << "Verify succesed" << endl;
        else
        {
            wcout << "Verify failed" << endl;
            exit(-1);
        }
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
// tạo signature
bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const string &message, string &signature)
{

    try
    {
        AutoSeededRandomPool prng;
        signature.clear();
        StringSource(message, true,
                     new SignerFilter(prng,
                                      ECDSA<ECP, SHA256>::Signer(privateKey),
                                      new StringSink(signature)));
        return !signature.empty();
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}
// xác thực message
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey &publicKey, const string &message, const string &signature)
{

    try
    {
        bool result = false;
        StringSource(signature + message, true,
                     new SignatureVerificationFilter(
                         ECDSA<ECP, SHA256>::Verifier(publicKey),
                         new ArraySink((byte *)&result, sizeof(result))));
        return result;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(-1);
    }
}