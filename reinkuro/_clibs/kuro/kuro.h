#ifndef _KURO_H_
#define _KURO_H_

void StringToMaskBytes(uint16_t *maskString, uint32_t maskLen, uint8_t *maskBytes, int32_t bytesLength);
void CryptByString(uint8_t *input, int32_t input_len, uint8_t **output, uint8_t *maskString, uint8_t maskStringlen, int32_t offset, uint64_t streamPos, uint64_t headerLength);

#endif // _KURO_H_
