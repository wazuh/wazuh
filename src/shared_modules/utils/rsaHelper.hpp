/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * January 24, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSA_HELPER_HPP
#define _RSA_HELPER_HPP

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

constexpr int RSA_PRIVATE {0};
constexpr int RSA_PUBLIC  {1};
constexpr int RSA_CERT    {2};

namespace Utils
{
    /**
     * Extracts the public key from a X.509 certificate
     *
     * @param rsaPublicKey  The RSA structure for the public key 
     * @param certFile      The file pointer to the certificate 
     */
    static void getPubKeyFromCert(RSA* &rsaPublicKey, FILE *certFile)
    {
        // Read the X.509 certificate from the file
        X509 *x509Certificate = PEM_read_X509(certFile, NULL, NULL, NULL);

        if (!x509Certificate) {
            throw std::runtime_error("Error reading X.509 certificate");
        }

        // Extract the public key from the X.509 certificate
        EVP_PKEY *evpPublicKey = X509_get_pubkey(x509Certificate);

        if (!evpPublicKey) {
            X509_free(x509Certificate);
            throw std::runtime_error("Error reading public key");
        }

        // Check the type of key
        if (EVP_PKEY_base_id(evpPublicKey) == EVP_PKEY_RSA) {
            // Extract RSA structure from the EVP_PKEY
            rsaPublicKey = EVP_PKEY_get1_RSA(evpPublicKey);

            if (!rsaPublicKey) {
                EVP_PKEY_free(evpPublicKey);
                X509_free(x509Certificate);
                throw std::runtime_error("Error extracting RSA public key from EVP_PKEY");
            }

        } else {
            EVP_PKEY_free(evpPublicKey);
            X509_free(x509Certificate);
            throw std::runtime_error("Unsupported key type");
        }

        EVP_PKEY_free(evpPublicKey);
        X509_free(x509Certificate);
    }


    /**
     * Creates the RSA structure from a certificate or key file
     *
     * @param rsaPublicKey  The RSA structure for the public key 
     * @param filePath  The path to the file key string to encrypt the value
     * @param type      The type of file (RSA_PRIVATE, RSA_PUBLIC, RSA_CERT)
     */
    static void createRSA(RSA* &rsaKey, std::string filePath, int type)
    {

        FILE *keyFile = fopen(filePath.c_str(), "r");
        if (!keyFile) {
            throw std::runtime_error("Failed to open RSA file");
        }

        switch (type) {
            case RSA_PRIVATE:
                rsaKey = PEM_read_RSAPrivateKey(keyFile, NULL, NULL, NULL);
                if (!rsaKey) {
                    fclose(keyFile);
                    throw std::runtime_error("Error reading RSA private key");
                }
                break;
            case RSA_PUBLIC:
                rsaKey = PEM_read_RSA_PUBKEY(keyFile, NULL, NULL, NULL);
                if (!rsaKey) {
                    fclose(keyFile);
                    throw std::runtime_error("Error reading RSA public key");
                }
                break;
            case RSA_CERT:
                try
                {
                    getPubKeyFromCert(rsaKey, keyFile);
                }
                catch(std::exception& e)
                {
                    fclose(keyFile);
                    throw std::runtime_error("Error getting RSA public key from certificate");
                }
                break;
            default:
                break;
        }
        fclose(keyFile);
    }

    /**
     * Encrypts the input vector with the provided key
     *
     * @param filePath  The path to the file key string to encrypt the value
     * @param input     The entry to be encrypted
     * @param output    The resulting encrypted value
     * @param cert      If the public key is in a certificate
     * @return          The size of the encrypted output, -1 if error
     */
    int rsaEncrypt(const std::string& filePath, const std::string& input, 
                   std::string& output, bool cert = false) {

        RSA* rsa;
        try
        {
            createRSA(rsa, filePath, cert ? RSA_CERT : RSA_PUBLIC);
        }
        catch(const std::exception& e)
        {
            throw std::runtime_error("Failed to obtain RSA for encryption: " + std::string(e.what()));
        }

        const char *plaintext = input.c_str();
        size_t plaintext_len = strlen(plaintext);

        // Allocate memory for the encryptedValue
        unsigned char *encryptedValue = (unsigned char *)malloc(RSA_size(rsa));

        int encrypted_len = RSA_public_encrypt(plaintext_len, (const unsigned char *)plaintext, encryptedValue, rsa, RSA_PKCS1_PADDING);
        
        if (encrypted_len < 0) {
            RSA_free(rsa);
            free(encryptedValue);
            throw std::runtime_error("RSA encryption failed");
        }

        output = std::string(reinterpret_cast<char const*>(encryptedValue),encrypted_len);

        RSA_free(rsa);
        free(encryptedValue);

        return encrypted_len;
    }

    /**
     * Decrypts the input vector with the provided key
     *
     * @param filePath  The path to the file key string to decrypt the value
     * @param input  The entry to be decrypted
     * @param output The resulting decrypted value
     * @return       The size of the decrypted output, -1 if error
     */
    int rsaDecrypt(const std::string& filePath, std::string& input, std::string& output){

        RSA* rsa;
        try
        {
            createRSA(rsa, filePath, RSA_PRIVATE);
        }
        catch(const std::exception& e)
        {
            throw std::runtime_error("Failed to obtain RSA for decryption: " + std::string(e.what()));
        }

        std::string decrypted_text(RSA_size(rsa), 0); // Initialize with zeros

        // Decrypt the ciphertext using RSA private key
        int decrypted_len = RSA_private_decrypt(256,  reinterpret_cast<const unsigned char *>(input.data()),
                                                reinterpret_cast<unsigned char *>(&decrypted_text[0]), rsa, RSA_PKCS1_PADDING);
        
        if(decrypted_len < 0){
            RSA_free(rsa);
            throw std::runtime_error("RSA decryption failed");
        }

        // Display the decrypted plaintext
        output = decrypted_text.substr(0, decrypted_len);

        RSA_free(rsa);

        return decrypted_len;
    }
}

#endif // _RSA_HELPER_HPP
