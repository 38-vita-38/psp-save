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

typedef struct pspChnnlsvContext1_s {
	/* Cipher mode */
	int mode;

	/* Context data */
	unsigned char result[0x10];
	unsigned char key[0x10];
	int keyLength;
} pspChnnlsvContext1;

typedef struct pspChnnlsvContext2_s {
	/* Context data */
	int mode;
	int unkn;
	unsigned char cryptedData[0x92];
} pspChnnlsvContext2;

int sceSdSetIndex_(pspChnnlsvContext1 *ctx, int value);
int sceSdRemoveValue_(pspChnnlsvContext1 *ctx, unsigned char *data, int length);
int sceSdCreateList_(pspChnnlsvContext2 *ctx2, int mode, int uknw, unsigned char *data, unsigned char *cryptkey);
int sceSdSetMember_(pspChnnlsvContext2 *ctx, unsigned char *data, int alignedLen);
int sceChnnlsv_21BE78B4_(pspChnnlsvContext2 *ctx);
int sceSdGetLastIndex_(pspChnnlsvContext1 *ctx, unsigned char* in_hash, unsigned char* in_key);

