/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 10, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EVPHELPER_HPP
#define _EVPHELPER_HPP

#include "defer.hpp"
#include <array>
#include <opensslPrimitives.hpp>
#include <stdexcept>
#include <string>
#include <vector>

constexpr auto CIPHER_KEY_SIZE {32};
constexpr auto CIPHER_IV_SIZE {16};
constexpr auto OPENSSL_SUCCESS {1};

template<typename T = OpenSSLPrimitives>
class EVPHelper final : public T
{
public:
    explicit EVPHelper() = default;
    ~EVPHelper() override = default;

    /**
     * Encrypts the input string.
     * Basically we are using AES-256-CBC encryption and the key and iv are generated randomly
     * The output will be the key + iv + ciphertext
     *
     * @param input     The entry to be encrypted
     * @param output    The resulting encrypted value (key + iv + ciphertext)
     */
    void encryptAES256(const std::string& input, std::vector<char>& output)
    {
        EVP_CIPHER_CTX* ctx;
        int len;
        int ciphertextLen;
        std::vector<unsigned char> ciphertext(input.length() + T::AES_BLOCK_LENGTH, 0);
        std::array<unsigned char, CIPHER_KEY_SIZE> key {};
        std::array<unsigned char, CIPHER_IV_SIZE> iv {};

        if (OPENSSL_SUCCESS != T::RAND_bytes(key.data(), key.size()) ||
            OPENSSL_SUCCESS != T::RAND_bytes(iv.data(), iv.size()))
        {
            throw std::runtime_error("Error generating random bytes for key/iv");
        }

        if (!(ctx = T::EVP_CIPHER_CTX_new()))
        {
            throw std::runtime_error("Error creating EVP_CIPHER_CTX");
        }

        // Defered Free
        DEFER([&]() { T::EVP_CIPHER_CTX_free(ctx); });

        if (OPENSSL_SUCCESS != T::EVP_EncryptInit_ex(ctx, T::EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
        {
            throw std::runtime_error("Error initializing encryption operation");
        }

        if (OPENSSL_SUCCESS !=
            T::EVP_EncryptUpdate(
                ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(input.data()), input.size()))
        {
            throw std::runtime_error("Error encrypting message");
        }

        ciphertextLen = len;

        if (OPENSSL_SUCCESS != T::EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        {
            throw std::runtime_error("Error finalizing encryption");
        }
        ciphertextLen += len;

        // Save the key + iv + ciphertext in the output
        output.resize(key.size() + iv.size() + ciphertextLen);
        std::copy(key.begin(), key.end(), output.begin());
        std::copy(iv.begin(), iv.end(), output.begin() + key.size());
        std::copy(ciphertext.begin(), ciphertext.begin() + ciphertextLen, output.begin() + key.size() + iv.size());
    }

    /**
     * Decrypts the input vector.
     *
     * @param input  The entry to be decrypted (key + iv + ciphertext)
     * @param output The resulting decrypted value
     */
    void decryptAES256(const std::vector<char>& input, std::string& output)
    {
        EVP_CIPHER_CTX* ctx;

        int len;

        const auto* key = reinterpret_cast<const unsigned char*>(input.data());
        const unsigned char* iv = key + CIPHER_KEY_SIZE;
        const unsigned char* ciphertext = iv + CIPHER_IV_SIZE;
        const auto ciphertextLen = input.size() - CIPHER_KEY_SIZE - CIPHER_IV_SIZE;
        std::vector<unsigned char> plaintext(ciphertextLen, 0);
        int plaintextLen;

        if (!(ctx = T::EVP_CIPHER_CTX_new()))
        {
            throw std::runtime_error("Error creating EVP_CIPHER_CTX");
        }

        DEFER([&]() { T::EVP_CIPHER_CTX_free(ctx); });

        if (OPENSSL_SUCCESS != T::EVP_DecryptInit_ex(ctx, T::EVP_aes_256_cbc(), NULL, key, iv))
        {
            throw std::runtime_error("Error initializing decryption operation");
        }

        if (OPENSSL_SUCCESS != T::EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertextLen))
        {
            throw std::runtime_error("Error decrypting message");
        }

        plaintextLen = len;

        if (OPENSSL_SUCCESS != T::EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        {
            throw std::runtime_error("Error finalizing decryption");
        }
        plaintextLen += len;

        plaintext.resize(plaintextLen);
        output.assign(plaintext.begin(), plaintext.end());
    }
};

#endif // _EVPHELPER_HPP
