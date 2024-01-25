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

#ifndef _RSA_HELPER_H
#define _RSA_HELPER_H

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

constexpr int RSA_PUBLIC  {1};
constexpr int RSA_PRIVATE {0};

namespace Utils
{
    static RSA * createRSA(unsigned char * key,int pub)
    {
        RSA *rsa= NULL;
        BIO *keybio ;

        keybio = BIO_new_mem_buf(key, -1);
        if (keybio==NULL)
        {
            return 0;
        }

        if(pub)
        {
            rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
        }
        else
        {
            rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
        }

        BIO_free(keybio);

        return rsa;
    }

    /**
     * Encrypts the input vector with the provided key
     *
     * @param key    The public key string to encrypt the value
     * @param input  The entry to be encrypted
     * @param output The resulting encrypted value
     * @return       The size of the encrypted output, -1 if error
     */
    int rsaEncrypt(const std::string& key, std::array<unsigned char, 128>& input, std::array<unsigned char, 256>& output){
        int result;
        unsigned char c_output[256];

        RSA * rsa = createRSA((unsigned char *)key.c_str(), RSA_PUBLIC);
        if(!rsa){
            throw std::runtime_error("Failed to obtain RSA for encryption");
        }

        result = RSA_public_encrypt(input.size(), input.data(), c_output, rsa, RSA_PKCS1_PADDING);
        if(result < 0){
            throw std::runtime_error("RSA encryption failed");
        }
        std::copy(std::begin(c_output), std::end(c_output), output.begin());

        RSA_free(rsa);

        return result;
    }

    /**
     * Decrypts the input vector with the provided key
     *
     * @param key    The private key string to encrypt the value
     * @param input  The entry to be decrypted
     * @param output The resulting decrypted value
     * @return       The size of the decrypted output, -1 if error
     */
    int rsaDecrypt(const std::string& key, std::array<unsigned char, 256>& input, std::array<char, 256>& output){
        int result;
        unsigned char c_output[256];

        RSA * rsa = createRSA((unsigned char *)key.c_str(), RSA_PRIVATE);
        if(!rsa){
            throw std::runtime_error("Failed to obtain RSA for decryption");
        }

        RSA_private_decrypt(input.size(), input.data(), c_output, rsa, RSA_PKCS1_PADDING);
        if(result < 0){
            throw std::runtime_error("RSA encryption failed");
        }
        std::copy(std::begin(c_output), std::end(c_output), output.begin());

        RSA_free(rsa);

        return result;
    }
}

#endif // _RSA_HELPER_H
