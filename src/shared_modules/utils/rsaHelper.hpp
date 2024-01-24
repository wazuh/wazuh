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
     */
    void rsaEncrypt(const std::string& key, std::vector<char>& input, std::vector<char>& output){
        int result;

        if(output.size() < 256){
            throw std::runtime_error("Ouput vector too small");
        }

        RSA * rsa = createRSA((unsigned char *)key.c_str(), 1);
        if(!rsa){
            throw std::runtime_error("Failed to obtain RSA");
        }

        result = RSA_public_encrypt(input.size(), (const unsigned char *)&input[0], (unsigned char *)&output[0], rsa, RSA_PKCS1_PADDING);
        if(result){
            throw std::runtime_error("RSA encryption failed");
        }
    }

    /**
     * Decrypts the input vector with the provided key
     *
     * @param key    The private key string to encrypt the value
     * @param input  The entry to be decrypted
     * @param output The resulting decrypted value
     */
    void rsaDecrypt(const std::string& key, std::vector<char>& input, std::vector<char>& output){
        int result;

        if(output.size() < 256){
            throw std::runtime_error("Ouput vector too small");
        }

        RSA * rsa = createRSA((unsigned char *)key.c_str(), 0);
        if(!rsa){
            throw std::runtime_error("Failed to obtain RSA");
        }

        RSA_private_decrypt(input.size(), (const unsigned char *)&input[0], (unsigned char *)&output[0], rsa, RSA_PKCS1_PADDING);
        if(result){
            throw std::runtime_error("RSA encryption failed");
        }
    }
}

#endif // _RSA_HELPER_H
