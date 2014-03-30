/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kazutils.h"

char *ksprintf(const char *fmt, ...)
{
	char smallbuf[256], *ret;
	va_list arg;
	int len;

	// determine the length (as well as fill-in the small buf)
	va_start(arg, fmt);
	len = vsnprintf(smallbuf, sizeof(smallbuf), fmt, arg);
	va_end(arg);
	if (len == -1)
		return NULL;

	// allocate
	if ((ret = malloc(len + 1)) == NULL)
		return NULL;

	// copy from small buf or reprint
	if (len < sizeof(smallbuf)) {
		memcpy(ret, smallbuf, len + 1);
	} else {
		va_start(arg, fmt);
		vsnprintf(ret, len + 1, fmt, arg);
		va_end(arg);
	}

	return ret;
}
