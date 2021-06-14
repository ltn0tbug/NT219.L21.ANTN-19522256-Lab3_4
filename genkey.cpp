#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;


#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/oids.h> 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

void Save(const string& filename, const BufferedTransformation& bt);
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key );

int main()
{
    AutoSeededRandomPool prng;
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(prng, 3072);
    RSA::PublicKey rsaPublic(rsaPrivate);
    SavePrivateKey("rsa-private.key", rsaPrivate);
    SavePublicKey("rsa-public.key", rsaPublic);

    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.Initialize( prng, ASN1::secp256r1());
    privateKey.MakePublicKey( publicKey);

    SavePrivateKey( "ec-private.key", privateKey );
    SavePublicKey( "ec-public.key", publicKey );
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}