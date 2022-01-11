#ifndef __SERIALIZATION_UTIL_H
#define __SERIALIZATION_UTIL_H
#include <stdint.h>

static void serialize_unsigned(uint8_t **dest, uint64_t num) {
    const uint8_t N_HIGH_BIT_MASK = 0X7F;
    do {
        uint8_t byte = ((uint8_t)num) & N_HIGH_BIT_MASK;
        num = num >> 7;
        byte |= (num > 0) << 7;
        **dest = byte;
        *dest += 1;
    } while (num);
}

static uint64_t deserialize_unsigned(uint8_t **source) {
    const uint8_t HIGH_BIT_MASK = 0X80;
    const uint8_t N_HIGH_BIT_MASK = 0X7F;
    uint8_t byte = 0;
    uint32_t count = 0;
    int endByte = 0;
    uint64_t num = 0;
    do {
        byte = **source;
        *source += 1;
        endByte = (byte & HIGH_BIT_MASK);
        byte &= N_HIGH_BIT_MASK;
        num |= (byte) << (7 * count++);
    } while (endByte);

    return num;
}

static void serialize_signed(uint8_t **dest, int64_t num) {
    const uint8_t N_HIGH_BIT_MASK = 0X7F;
    const uint8_t SIGN_BIT_MASK = 0X40;
    const uint8_t SIX_BIT_MASK = 0X3F;

    uint8_t byte = 0 | (SIGN_BIT_MASK & (num >> (sizeof(num) * 8 - 7)));

    if (byte)
        num = -num;

    byte |= (uint8_t)num & SIX_BIT_MASK;
    num = num >> 6;
    byte |= (num > 0) << 7;
    **dest = byte;
    *dest += 1;

    while (num > 0) {
        byte = ((uint8_t)num) & N_HIGH_BIT_MASK;
        num = num >> 7;
        byte |= (num > 0) << 7;
        **dest = byte;
        *dest += 1;
    }
}

static int64_t deserialize_signed(uint8_t **src) {
    const uint8_t N_HIGH_BIT_MASK = 0X7F;
    const uint8_t HIGH_BIT_MASK = 0X80;
    const uint8_t SIGN_BIT_MASK = 0X40;
    const uint8_t SIX_BIT_MASK = 0X3F;

    uint8_t byte = **src;
    *src += 1;
    int flipSign = byte & SIGN_BIT_MASK;
    int endByte = (byte & HIGH_BIT_MASK);

    int64_t num = 0;
    num |= byte & SIX_BIT_MASK;
    int count = 6;
    while (endByte) {
        byte = **src;
        *src += 1;

        endByte = (byte & HIGH_BIT_MASK);
        byte &= N_HIGH_BIT_MASK;
        num |= (byte) << (count);
        count += 7;
    }

    if (flipSign)
        num = -num;

    return num;
}
#endif
