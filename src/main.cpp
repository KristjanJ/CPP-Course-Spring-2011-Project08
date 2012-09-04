/*!
\file main.cpp
\brief This file contains all functions for the FileSecure command-line application.
*/

#include <iostream>
#include <fstream>
#include <string>

#include "randpool.h"
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "osrng.h"
#include "modes.h"

using namespace CryptoPP;

/*!
\brief Returns the AES key and IV in the same buffer.
\returns The AES key and IV in the same buffer.
*/
unsigned char* AES_GenerateKey(void);

/*!
\brief Encrypts data.
\param input Input data.
\param length Length of input data.
\param fullKey AES key from AES_GenerateKey.
\returns Encrypted data.
*/
unsigned char* AES_Encrypt(const unsigned char* input, unsigned int length, const unsigned char* fullKey);

/*!
\brief Decrypts data.
\param input Input data.
\param length Length of input data.
\param fullKey AES key from AES_GenerateKey.
\returns Decrypted data.
*/
unsigned char* AES_Decrypt(const unsigned char* input, unsigned int length, const unsigned char* fullKey);

/*!
\brief Encrypts a file.
\param inFileName Input file.
\param outFileName Output file.
\param publicKeyFileName Public key file.
*/
void EncryptFile(const std::string& inFileName, const std::string& outFileName, const std::string& publicKeyFileName);

/*!
\brief Decrypts a file.
\param inFileName Input file.
\param outFileName Output file.
\param privateKeyFileName Private key file.
*/
void DecryptFile(const std::string& inFileName, const std::string& outFileName, const std::string& privateKeyFileName);

/*!
\brief Signs a file.
\param inFileName Input file.
\param signatureFileName Signature file.
\param privateKeyFileName Private key file.
*/
void SignFile(const std::string& inFileName, const std::string& signatureFileName, const std::string& privateKeyFileName);

/*!
\brief Verifies a file.
\param inFileName Input file.
\param signatureFileName Signature file.
\param publicKeyFileName Public key file.
*/
void VerifyFile(const std::string& inFileName, const std::string& signatureFileName, const std::string& publicKeyFileName);

/*!
\brief Function from Crypto++'s test.cpp. Generates a RSA keypair.
\param keyLength Key length.
\param privFilename Private key file.
\param pubFilename Public key file.
\param seed Seed.
*/
void GenerateRSAKey(unsigned int keyLength, const char* privFilename, const char* pubFilename, const char* seed);

/*!
\brief Function from Crypto++'s test.cpp. Encrypts a string using RSA.
\param pubFilename Public key file.
\param seed Seed.
\param message Message.
\returns Encrypted string.
*/
std::string RSAEncryptString(const char* pubFilename, const char* seed, const char* message);

/*!
\brief Function from Crypto++'s test.cpp. Decrypts a string using RSA.
\param privFilename Private key file.
\param ciphertext Ciphertext.
\returns Decrypted string.
*/
std::string RSADecryptString(const char* privFilename, const char* ciphertext);

/*!
\brief Function from Crypto++'s test.cpp. Signs a file using RSA.
\param privFilename Private key file.
\param messageFilename Message file.
\param signatureFilename Signature file.
*/
void RSASignFile(const char* privFilename, const char* messageFilename, const char* signatureFilename);

/*!
\brief Function from Crypto++'s test.cpp. Verifies a file using RSA.
\param pubFilename Public key file.
\param messageFilename Message file.
\param signatureFilename Signature file.
*/
bool RSAVerifyFile(const char* pubFilename, const char* messageFilename, const char* signatureFilename);

/*!
\brief Main function.
\param argc Argument count.
\param argv Arguments.
\returns Error code.
*/
int main(int argc, char** argv)
{
    std::string help;
    std::string rsaPublic;
    std::string rsaPrivate;
    std::string encrypt;
    std::string decrypt;
    std::string sign;
    std::string verify;
    std::string out;
    std::string withkey;
    std::string sigfile;

    for (int i = 1; i < argc; i++)
    {
        std::string argument(argv[i]);

        if (argument == "--help")
        {
            help = "help";
        }
        else if (argument == "--genkey" && argc >= (i + 3))
        {
            i++;
            rsaPublic = argv[i];
            i++;
            rsaPrivate = argv[i];
        }
        else if (argument == "--encrypt" && argc >= (i + 2))
        {
            i++;
            encrypt = argv[i];
        }
        else if (argument == "--decrypt" && argc >= (i + 2))
        {
            i++;
            decrypt = argv[i];
        }
        else if (argument == "--sign" && argc >= (i + 2))
        {
            i++;
            sign = argv[i];
        }
        else if (argument == "--verify" && argc >= (i + 2))
        {
            i++;
            verify = argv[i];
        }
        else if (argument == "--out" && argc >= (i + 2))
        {
            i++;
            out = argv[i];
        }
        else if (argument == "--withkey" && argc >= (i + 2))
        {
            i++;
            withkey = argv[i];
        }
        else if (argument == "--sigfile" && argc >= (i + 2))
        {
            i++;
            sigfile = argv[i];
        }
    }

    std::cout << "\nFileSecure\n" << std::endl;

    if (help != "")
    {
        std::cout << "Getting help: " << std::endl;
        std::cout << "filesecure --help" << std::endl;

        std::cout << "\nGenerating RSA keypair: " << std::endl;
        std::cout << "filesecure --genkey pubkeyfile privkeyfile" << std::endl;

        std::cout << "\nEncrypting files: " << std::endl;
        std::cout << "filesecure --encrypt infile --out outfile --withkey pubkeyfile" << std::endl;

        std::cout << "\nDecrypting files: " << std::endl;
        std::cout << "filesecure --decrypt infile --out outfile --withkey privkeyfile" << std::endl;

        std::cout << "\nSigning files: " << std::endl;
        std::cout << "filesecure --sign infile --withkey privkeyfile --sigfile sigfile" << std::endl;

        std::cout << "\nVerifying files: " << std::endl;
        std::cout << "filesecure --verify infile --withkey pubkeyfile --sigfile sigfile" << std::endl;
    }
    else if (rsaPublic != "" && rsaPrivate != "")
    {
        std::cout << "Generating RSA keypair. public: " << rsaPublic << " private: " << rsaPrivate << std::endl;
        GenerateRSAKey(1024, rsaPrivate.c_str(), rsaPublic.c_str(), "asdfasdf12345678");
    }
    else if (encrypt != "" && out != "" && withkey != "")
    {
        std::cout << "Encrypting file. in: " << encrypt << " out: " << out << " key: " << withkey << std::endl;
        EncryptFile(encrypt, out, withkey);
    }
    else if (decrypt != "" && out != "" && withkey != "")
    {
        std::cout << "Decrypting file. in: " << decrypt << " out: " << out << " key: " << withkey << std::endl;
        DecryptFile(decrypt, out, withkey);
    }
    else if (sign!= "" && sigfile != "" && withkey != "")
    {
        std::cout << "Signing file. in: " << sign << " signature: " << sigfile << " key: " << withkey << std::endl;
        SignFile(sign, sigfile, withkey);
    }
    else if (verify!= "" && sigfile != "" && withkey != "")
    {
        std::cout << "Verifying file. in: " << verify << " signature: " << sigfile << " key: " << withkey << std::endl;
        VerifyFile(verify, sigfile, withkey);
    }
    else
    {
        std::cout << "For help use: filesecure --help" << std::endl;

    }

    return 0;
}

//Generates AES key and IV in the same buffer.
unsigned char* AES_GenerateKey(void)
{
    int fullKeyLength = AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE;
    unsigned char* fullKey = new unsigned char[fullKeyLength];

    AutoSeededRandomPool autoSeededRandomPool;
    autoSeededRandomPool.GenerateBlock(fullKey, AES::DEFAULT_KEYLENGTH);
    autoSeededRandomPool.GenerateBlock(fullKey + AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);

    return fullKey;
}

//Encrypts data using AES.
unsigned char* AES_Encrypt(const unsigned char* input, unsigned int length, const unsigned char* fullKey)
{
    unsigned char* encrypted = new unsigned char[length];

    CFB_Mode<AES>::Encryption cfbEncryption(fullKey, AES::DEFAULT_KEYLENGTH, fullKey + AES::DEFAULT_KEYLENGTH);
    cfbEncryption.ProcessData(encrypted, input, length);

    return encrypted;
}

//Decrypts data using AES.
unsigned char* AES_Decrypt(const unsigned char* input, unsigned int length, const unsigned char* fullKey)
{
    unsigned char* decrypted = new unsigned char[length];

    CFB_Mode<AES>::Decryption cfbDecryption(fullKey, AES::DEFAULT_KEYLENGTH, fullKey + AES::DEFAULT_KEYLENGTH);
    cfbDecryption.ProcessData(decrypted, input, length);

    return decrypted;
}

//Encrypts file using AES. The AES key will be encrypted using RSA.
void EncryptFile(const std::string& inFileName, const std::string& outFileName, const std::string& publicKeyFileName)
{
    std::ifstream inFile;
    std::ofstream outFile;
    std::ifstream publicKeyFile;

    inFile.open(inFileName.c_str(), std::ios_base::binary);

    if (inFile.is_open())
    {
        int inFileSize = 0;
        inFile.seekg(0, std::ios_base::end);
        inFileSize = inFile.tellg();
        inFile.seekg(0, std::ios_base::beg);
        char* inData = new char[inFileSize];
        inFile.read(inData, inFileSize);
        inFile.close();

        publicKeyFile.open(publicKeyFileName.c_str(), std::ios_base::binary);

        if (publicKeyFile.is_open())
        {
            publicKeyFile.close();
            int AES_keyLength = AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE;
            unsigned char* AES_key = AES_GenerateKey();
            std::string AES_encryptedKey = RSAEncryptString(publicKeyFileName.c_str(), "asdfasdf12345678", std::string((char*) AES_key, AES_keyLength).c_str());
            char* encryptedData = (char*) AES_Encrypt((unsigned char*) inData, inFileSize, AES_key);

            outFile.open(outFileName.c_str(), std::ios_base::binary);

            if (outFile.is_open())
            {
                outFile.write(AES_encryptedKey.data(), 256);
                outFile.write(encryptedData, inFileSize);
                outFile.close();

                std::cout << "Successfully encrypted file." << std::endl;
            }
            else
            {
                std::cout << "An error occurred while trying to open the output file." << std::endl;
            }

            delete [] AES_key;
            AES_key = 0;
            delete [] encryptedData;
            encryptedData = 0;
        }
        else
        {
            std::cout << "An error occurred while trying to open the public key file." << std::endl;
        }

        delete [] inData;
        inData = 0;
    }
    else
    {
        std::cout << "An error occurred while trying to open the input file." << std::endl;
    }
}

//Decrypts a file using AES. The AES key will be decrypted using RSA.
void DecryptFile(const std::string& inFileName, const std::string& outFileName, const std::string& privateKeyFileName)
{
    std::ifstream inFile;
    std::ofstream outFile;
    std::ifstream privateKeyFile;

    inFile.open(inFileName.c_str(), std::ios_base::binary);

    if (inFile.is_open())
    {
        int inFileSize = 0;
        inFile.seekg(0, std::ios_base::end);
        inFileSize = inFile.tellg();
        inFile.seekg(0, std::ios_base::beg);
        char* inData = new char[inFileSize];
        inFile.read(inData, inFileSize);
        inFile.close();

        privateKeyFile.open(privateKeyFileName.c_str(), std::ios_base::binary);

        if (privateKeyFile.is_open())
        {
            privateKeyFile.close();
            std::string AES_decryptedKey = RSADecryptString(privateKeyFileName.c_str(), std::string(inData, 256).c_str());

            int dataSize = inFileSize - 256;
            char* decryptedData = (char*) AES_Decrypt((unsigned char*) (inData + 256), dataSize, (unsigned char*) AES_decryptedKey.data());

            outFile.open(outFileName.c_str(), std::ios_base::binary);

            if (outFile.is_open())
            {
                outFile.write(decryptedData, dataSize);
                outFile.close();

                std::cout << "Successfully decrypted file." << std::endl;
            }
            else
            {
                std::cout << "An error occurred while trying to open the output file." << std::endl;
            }

            delete [] decryptedData;
            decryptedData = 0;
        }
        else
        {
            std::cout << "An error occurred while trying to open the private key file." << std::endl;
        }

        delete [] inData;
        inData = 0;
    }
    else
    {
        std::cout << "An error occurred while trying to open the input file." << std::endl;
    }
}

//Signs a file using RSA.
void SignFile(const std::string& inFileName, const std::string& signatureFileName, const std::string& privateKeyFileName)
{
    std::ifstream inFile(inFileName.c_str());

    if (inFile.is_open())
    {
        inFile.close();
        std::ifstream privateKeyFile(privateKeyFileName.c_str());

        if (privateKeyFile.is_open())
        {
            privateKeyFile.close();
            RSASignFile(privateKeyFileName.c_str(), inFileName.c_str(), signatureFileName.c_str());
        }
        else
        {
            std::cout << "An error occurred while trying to open the private key file." << std::endl;
        }
    }
    else
    {
        std::cout << "An error occurred while trying to open the input file." << std::endl;
    }
}

//Verifies a file using RSA.
void VerifyFile(const std::string& inFileName, const std::string& signatureFileName, const std::string& publicKeyFileName)
{
    std::ifstream inFile(inFileName.c_str());

    if (inFile.is_open())
    {
        inFile.close();
        std::ifstream publicKeyFile(publicKeyFileName.c_str());

        if (publicKeyFile.is_open())
        {
            publicKeyFile.close();
            std::ifstream signatureFile(signatureFileName.c_str());

            if (signatureFile.is_open())
            {
                signatureFile.close();
                bool verified = RSAVerifyFile(publicKeyFileName.c_str(), inFileName.c_str(), signatureFileName.c_str());

                if (verified)
                {
                    std::cout << "File successfully verified." << std::endl;
                }
                else
                {
                    std::cout << "File cannot be verified." << std::endl;
                }
            }
            else
            {
                std::cout << "An error occurred while trying to open the signature file." << std::endl;
            }
        }
        else
        {
            std::cout << "An error occurred while trying to open the public key file." << std::endl;
        }
    }
    else
    {
        std::cout << "An error occurred while trying to open the input file." << std::endl;
    }
}

void GenerateRSAKey(unsigned int keyLength, const char* privFilename, const char* pubFilename, const char* seed)
{
	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}

std::string RSAEncryptString(const char* pubFilename, const char* seed, const char* message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	std::string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

std::string RSADecryptString(const char* privFilename, const char* ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	std::string result;

	OFB_Mode<AES>::Encryption globalRNG;
	globalRNG.SetKeyWithIV((byte*) "asdfasdf12345678", 16, (byte*) "asdfasdf12345678");
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(globalRNG, priv, new StringSink(result))));
	return result;
}

void RSASignFile(const char* privFilename, const char* messageFilename, const char* signatureFilename)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA>::Signer priv(privFile);

	OFB_Mode<AES>::Encryption globalRNG;
	globalRNG.SetKeyWithIV((byte*) "asdfasdf12345678", 16, (byte*) "asdfasdf12345678");

	FileSource f(messageFilename, true, new SignerFilter(globalRNG, priv, new HexEncoder(new FileSink(signatureFilename))));
}

bool RSAVerifyFile(const char* pubFilename, const char* messageFilename, const char* signatureFilename)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA>::Verifier pub(pubFile);

	FileSource signatureFile(signatureFilename, true, new HexDecoder);
	if (signatureFile.MaxRetrievable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size());

	VerifierFilter *verifierFilter = new VerifierFilter(pub);
	verifierFilter->Put(signature, pub.SignatureLength());
	FileSource f(messageFilename, true, verifierFilter);

	return verifierFilter->GetLastResult();
}


