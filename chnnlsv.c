/* Copyright (c) 2012- PPSSPP Project.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.0 or later versions.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License 2.0 for more details.
 *
 * A copy of the GPL 2.0 should have been included with the program.
 * If not, see http://www.gnu.org/licenses/
 *
 * Official git repository and contact information can be found at
 * https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.
 */

/* vita: convert C++ to C, remove unused functions, use C comment style */

#include <string.h>
#include "chnnlsv.h"
#include "libkirk/kirk_engine.h"

typedef enum {false, true} bool;

unsigned char dataBuf[2048 + 20];
unsigned char *dataBuf2 = dataBuf + 20;

static const unsigned char hash198C[16] = {0xFA, 0xAA, 0x50, 0xEC, 0x2F, 0xDE,
  0x54, 0x93, 0xAD, 0x14, 0xB2, 0xCE, 0xA5, 0x30, 0x05, 0xDF};

static const unsigned char hash19BC[16] = {0xCB, 0x15, 0xF4, 0x07, 0xF9, 0x6A,
  0x52, 0x3C, 0x04, 0xB9, 0xB2, 0xEE, 0x5C, 0x53, 0xFA, 0x86};

static const unsigned char key19CC[16] = {0x70, 0x44, 0xA3, 0xAE, 0xEF, 0x5D,
  0xA5, 0xF2, 0x85, 0x7F, 0xF2, 0xD6, 0x94, 0xF5, 0x36, 0x3B};

static const unsigned char key19DC[16] = {0xEC, 0x6D, 0x29, 0x59, 0x26, 0x35,
  0xA5, 0x7F, 0x97, 0x2A, 0x0D, 0xBC, 0xA3, 0x26, 0x33, 0x00};

static const unsigned char key199C[16] = {0x36, 0xA5, 0x3E, 0xAC, 0xC5, 0x26,
  0x9E, 0xA3, 0x83, 0xD9, 0xEC, 0x25, 0x6C, 0x48, 0x48, 0x72};

static const unsigned char key19AC[16] = {0xD8, 0xC0, 0xB0, 0xF3, 0x3E, 0x6B,
  0x76, 0x85, 0xFD, 0xFB, 0x4D, 0x7D, 0x45, 0x1E, 0x92, 0x03};

static void *memxor(void *dest, const void *src, size_t n)
{
    char const *s = src;
    char *d = dest;
    for (; n > 0; n--)
        *d++ ^= *s++;
    return dest;
}

/* The reason for the values from *FromMode calculations are not known. */
static int numFromMode(int mode)
{
    int num = 0;
    switch (mode) {
    case 1:
        num = 3;
        break;
    case 2:
        num = 5;
        break;
    case 3:
        num = 12;
        break;
    case 4:
        num = 13;
        break;
    case 6:
        num = 17;
        break;
    default:
        num = 16;
        break;
    }
    return num;
}

static int numFromMode2(int mode)
{
    int num = 18;
    if (mode == 1)
        num = 4;
    else if (mode == 3)
        num = 14;
    return num;
}

static int typeFromMode(int mode)
{
    return (mode == 1 || mode == 2) ? 83 :
      ((mode == 3 || mode == 4) ? 87 : 100);
}

static int kirkSendCmd(unsigned char *data, int length, int num, bool encrypt)
{
    *(int *)(data + 0) =
      encrypt ? KIRK_MODE_ENCRYPT_CBC : KIRK_MODE_DECRYPT_CBC;
    *(int *)(data + 4) = 0;
    *(int *)(data + 8) = 0;
    *(int *)(data + 12) = num;
    *(int *)(data + 16) = length;
    if (sceUtilsBufferCopyWithRange(data, length + 20, data, length + 20,
      encrypt ? KIRK_CMD_ENCRYPT_IV_0 : KIRK_CMD_DECRYPT_IV_0))
        return -257;
    return 0;
}

static int kirkSendFuseCmd(unsigned char *data, int length, bool encrypt)
{
    *(int *)(data + 0) =
      encrypt ? KIRK_MODE_ENCRYPT_CBC : KIRK_MODE_DECRYPT_CBC;
    *(int *)(data + 4) = 0;
    *(int *)(data + 8) = 0;
    *(int *)(data + 12) = 256;
    *(int *)(data + 16) = length;
    /* Note: CMD 5 and 8 are not available, will always return -1 */
    if (sceUtilsBufferCopyWithRange(data, length + 20, data, length + 20,
      encrypt ? KIRK_CMD_ENCRYPT_IV_FUSE : KIRK_CMD_DECRYPT_IV_FUSE))
        return -258;
    return 0;
}

static int sub_15B0(unsigned char *data, int alignedLen, unsigned char *buf, int val)
{
    unsigned char sp0[16];
    int res;
    memcpy(sp0, data + alignedLen + 4, 16);
    if ((res = kirkSendCmd(data, alignedLen, val, false)))
        return res;
    memxor(data, buf, 16);
    memcpy(buf, sp0, 16);
    return 0;
}

static int sub_0000(unsigned char *data_out, unsigned char *data,
  int alignedLen, unsigned char *data2, int *data3, int mode)
{
    unsigned char sp0[16], sp16[16];
    int i, res, type;
    memcpy(data_out + 20, data2, 16);
    /* Mode 1:2 is 83, 3:4 is 87, 5:6 is 100 */
    type = typeFromMode(mode);
    if (type == 87)
        memxor(data_out + 20, key19AC, 16);
    else if (type == 100)
        memxor(data_out + 20, key19DC, 16);
    /* Odd is Cmd, Even is FuseCmd */
    switch (mode) {
    case 2:
    case 4:
    case 6:
        res = kirkSendFuseCmd(data_out, 16, false);
        break;
    case 1:
    case 3:
    default:
        res = kirkSendCmd(data_out, 16, numFromMode2(mode), false);
        break;
    }
    if (type == 87)
        memxor(data_out, key199C, 16);
    else if (type == 100)
        memxor(data_out, key19CC, 16);
    if (res)
        return res;
    memcpy(sp16, data_out, 16);
    if (*data3 == 1) {
        memset(sp0, 0, 16);
    } else {
        memcpy(sp0, sp16, 12);
        *(unsigned int *)(sp0 + 12) = *data3 - 1;
    }
    if (alignedLen > 0)
        for (i = 20; i < alignedLen + 20; i += 16) {
            memcpy(data_out + i, sp16, 12);
            *(unsigned int *)(data_out + 12 + i) = *data3;
            (*data3)++;
        }
    res = sub_15B0(data_out, alignedLen, sp0, type);
    if (res)
        return res;
    if (alignedLen > 0)
        memxor(data, data_out, alignedLen);
    return 0;
}

static int sub_1510(unsigned char *data, int size, unsigned char *result,
  int num)
{
    int res;
    memxor(data + 20, result, 16);
    if ((res = kirkSendCmd(data, size, num, true)))
        return res;
    memcpy(result, data + size + 4, 16);
    return 0;
}

static int sub_17A8(unsigned char *data)
{
    return sceUtilsBufferCopyWithRange(data, 20, 0, 0, 14) ? -261 : 0;
}

int sceSdGetLastIndex_(pspChnnlsvContext1 *ctx, unsigned char *in_hash,
  unsigned char *in_key)
{
    int cond, i, num, res, ret, tmp1;
    unsigned char data1[16], data2[16], tmp2;
    if (ctx->keyLength >= 17)
        return -1026;
    num = numFromMode(ctx->mode);
    memset(dataBuf2, 0, 16);
    if ((res = kirkSendCmd(dataBuf, 16, num, true)))
        return res;
    memcpy(data1, dataBuf2, 16);
    tmp1 = (data1[0] & 0x80) ? 135 : 0;
    for (i = 0; i < 15; i++) {
        unsigned char val1 = data1[i] << 1;
        unsigned char val2 = data1[i + 1] >> 7;
        data1[i] = val1 | val2;
    }
    tmp2 = data1[15] << 1;
    tmp2 = tmp1 ^ tmp2;
    data1[15] = tmp2;
    if (ctx->keyLength < 16) {
        int oldKeyLength;
        tmp1 = 0;
        if ((signed char)data1[0] < 0)
            tmp1 = 135;
        for (i = 0; i < 15; i++) {
            unsigned char val1 = data1[i] << 1;
            unsigned char val2 = data1[i + 1] >> 7;
            data1[i] = val1 | val2;
        }
        tmp2 = data1[15] << 1;
        tmp2 = tmp1 ^ tmp2;
        data1[15] = tmp2;
        oldKeyLength = ctx->keyLength;
        *(signed char *)(ctx->key + ctx->keyLength) = -128;
        i = oldKeyLength + 1;
        if (i < 16)
            memset(ctx->key + i, 0, 16 - i);
    }

    memxor(ctx->key, data1, 16);
    memcpy(dataBuf2, ctx->key, 16);
    memcpy(data2, ctx->result, 16);

    if ((ret = sub_1510(dataBuf, 16, data2, num)))
        return ret;

    if (ctx->mode == 3 || ctx->mode == 4)
        memxor(data2, hash198C, 16);
    else if (ctx->mode == 5 || ctx->mode == 6)
        memxor(data2, hash19BC, 16);

    cond = ((ctx->mode ^ 0x2) < 1 || (ctx->mode ^ 0x4) < 1 || ctx->mode == 6);
    if (cond != 0) {
        memcpy(dataBuf2, data2, 16);
        if ((ret = kirkSendFuseCmd(dataBuf, 16, true)))
            return ret;
        if ((res = kirkSendCmd(dataBuf, 16, num, true)))
            return res;
        memcpy(data2, dataBuf2, 16);
    }

    if (in_key) {
        for (i = 0; i < 16; i++)
            data2[i] = in_key[i] ^ data2[i];
        memcpy(dataBuf2, data2, 16);
        if ((res = kirkSendCmd(dataBuf, 16, num, true)))
            return res;

        memcpy(data2, dataBuf2, 16);
    }
    memcpy(in_hash, data2, 16);
    sceSdSetIndex_(ctx, 0);
    return 0;
}

int sceSdSetIndex_(pspChnnlsvContext1 *ctx, int value)
{
    ctx->mode = value;
    memset(ctx->result, 0, 16);
    memset(ctx->key, 0, 16);
    ctx->keyLength = 0;
    return 0;
}

int sceSdRemoveValue_(pspChnnlsvContext1 *ctx, unsigned char *data, int length)
{
    int diff, i, len, newSize, num;
    if (ctx->keyLength >= 17)
        return -1026;
    if (ctx->keyLength + length < 17) {
        memcpy(ctx->key + ctx->keyLength, data, length);
        ctx->keyLength = ctx->keyLength + length;
        return 0;
    }
    num = numFromMode(ctx->mode);
    memset(dataBuf2, 0, 2048);
    memcpy(dataBuf2, ctx->key, ctx->keyLength);
    len = (ctx->keyLength + length) & 0xF;
    if (len == 0)
        len = 16;
    newSize = ctx->keyLength;
    ctx->keyLength = len;
    diff = length - len;
    memcpy(ctx->key, data + diff, len);
    for (i = 0; i < diff; i++) {
        if (newSize == 2048) {
            int res = sub_1510(dataBuf, 2048, ctx->result, num);
            if (res)
                return res;
            newSize = 0;
        }
        dataBuf2[newSize] = data[i];
        newSize++;
    }
    if (newSize)
        sub_1510(dataBuf, newSize, ctx->result, num);
    /* The RE code showed this always returning 0. I suspect it would want to
     * return res instead. */
    return 0;
}

int sceSdCreateList_(pspChnnlsvContext2 *ctx2, int mode, int uknw,
  unsigned char *data, unsigned char *cryptkey)
{
    ctx2->mode = mode;
    ctx2->unkn = 1;
    if (uknw == 2) {
        memcpy(ctx2->cryptedData, data, 16);
        if (cryptkey)
            memxor(ctx2->cryptedData, cryptkey, 16);
        return 0;
    } else if (uknw == 1) {
        unsigned char kirkHeader[37];
        unsigned char *kirkData = kirkHeader + 20;
        int res = sub_17A8(kirkHeader), type;
        if (res)
            return res;
        memcpy(kirkHeader + 20, kirkHeader, 16);
        memset(kirkHeader + 32, 0, 4);
        type = typeFromMode(mode);
        if (type == 87)
            memxor(kirkData, key199C, 16);
        else if (type == 100)
            memxor(kirkData, key19CC, 16);
        switch (mode) {
        case 2:
        case 4:
        case 6:
            res = kirkSendFuseCmd(kirkHeader, 16, true);
            break;
        case 1:
        case 3:
        default:
            res = kirkSendCmd(kirkHeader, 16, numFromMode2(mode), true);
            break;
        }
        if (type == 87)
            memxor(kirkData, key19AC, 16);
        else if (type == 100)
            memxor(kirkData, key19DC, 16);
        if (res)
            return res;
        memcpy(ctx2->cryptedData, kirkData, 16);
        memcpy(data, kirkData, 16);
        if (cryptkey)
            memxor(ctx2->cryptedData, cryptkey, 16);
    }
    return 0;
}

int sceSdSetMember_(pspChnnlsvContext2 *ctx, unsigned char *data, int alignedLen)
{
    unsigned char kirkData[20 + 2048];
    int i = 0, ctx_unkn, res;
    if (!alignedLen)
        return 0;
    if ((alignedLen & 0xF) != 0)
        return -1025;
    if ((unsigned int)alignedLen >= 2048)
        for (i = 0; alignedLen >= 2048; i += 2048) {
            ctx_unkn = ctx->unkn;
            res = sub_0000(kirkData, data + i, 2048, ctx->cryptedData,
              &ctx_unkn, ctx->mode);
            ctx->unkn = ctx_unkn;
            alignedLen -= 2048;
            if (res)
                return res;
        }
    if (!alignedLen)
        return 0;
    ctx_unkn = ctx->unkn;
    res = sub_0000(kirkData, data + i, alignedLen, ctx->cryptedData, &ctx_unkn,
      ctx->mode);
    ctx->unkn = ctx_unkn;
    return res;
}

int sceChnnlsv_21BE78B4_(pspChnnlsvContext2 *ctx)
{
    memset(ctx->cryptedData, 0, 16);
    ctx->unkn = 0;
    ctx->mode = 0;
    return 0;
}

