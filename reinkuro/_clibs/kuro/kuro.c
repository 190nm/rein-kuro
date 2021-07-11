#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "kuro.h"

void
StringToMaskBytes(uint16_t *maskString, uint32_t maskLen, uint8_t *maskBytes, int32_t bytesLength)
{
    uint8_t *a;
    uint8_t b;
    uint16_t _char;
    uint32_t i, k;
    uint64_t l, j;
    uint32_t m_len;

    if (maskString != 0) {
        m_len = maskLen;
        if (0 < (int)m_len) {
            i = 0;
            j = 0;
            k = bytesLength + -1;
            do {
                _char = maskString[(uint32_t)j];
                j += 1;
                maskBytes[i] = (uint8_t)_char;
                i += 2;
                maskBytes[k] = ~(uint8_t)_char;
                k += -2;
            } while (m_len != j);
        }
        if (0 < bytesLength) {
            l = (uint64_t)(uint32_t)bytesLength;
            m_len = 0xbb;
            j = l;
            a = maskBytes;
            do {
                j -= 1;
                m_len = ((m_len & 1) << 7 | (int32_t)m_len >> 1) ^ (uint32_t)*a;
                a = a + 1;
            } while (j != 0);
            if (0 < bytesLength) {
                b = 0;
                do {
                    l -= 1;
                    maskBytes[b] = maskBytes[b] ^ (uint8_t)m_len;
                    b = b + 1;
                } while (l != 0);
            }
        }
        return;
    }
}

void
CryptByString(uint8_t *input, int32_t input_len, uint8_t **output, uint8_t *maskString, uint8_t maskStringlen, int32_t offset, uint64_t streamPos, uint64_t headerLength) // int32_t count
{
    int i, k;
    // int j;
    uint32_t byteslen;
    uint8_t *maskBytes;

    uint8_t* buffer = (uint8_t *)malloc(input_len);
    memcpy(buffer, input, input_len);

    if (buffer[0] == 0x32) {
        headerLength = input_len;
        // printf("CryptType.Version1Full\n");
    } else if (buffer[0] != 0x31) {
        headerLength = input_len;
        // printf("CryptType.Raw\n");
        *output = buffer;
        return;
    }

    byteslen = maskStringlen << 1;
    maskBytes = (uint8_t *)malloc(byteslen);
    memset(maskBytes, 0x00, byteslen);
    StringToMaskBytes((uint16_t *)maskString, maskStringlen, maskBytes, byteslen);
    i = 0;
    // int count=256;
    do {
        // if (count <= i){
        //     return;
        // }
        // j = offset + i;
        k = 0;
        if (byteslen != 0) {
            k = (streamPos + i/byteslen);
        }
        (buffer + offset)[i] = maskBytes[(streamPos + i) - k * byteslen] ^ (buffer + offset)[i];
        i++;
    } while (streamPos + i < headerLength);
    buffer[0] = 0x55;
    *output = buffer;
    free(maskBytes); //first byte seems to be manually overwritten with 0x55
    return;
}
