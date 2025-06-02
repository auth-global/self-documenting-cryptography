#pragma once
/*
	Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#include <stddef.h>

int  hs_hashstring_hexDecode     (void *restrict dest, const char *restrict src, size_t srcLen);
int  hs_hashstring_hexDecodeLower(void *restrict dest, const char *restrict src, size_t srcLen);
int  hs_hashstring_hexDecodeUpper(void *restrict dest, const char *restrict src, size_t srcLen);
void hs_hashstring_hexEncode     (char *restrict dest, const void *restrict src, size_t srcLen);
void hs_hashstring_hexEncodeUpper(char *restrict dest, const void *restrict src, size_t srcLen);
