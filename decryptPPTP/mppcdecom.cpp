#include <windows.h>
#include "public_type.h"




void lamecopy(uint8_t *dst, uint8_t *src, uint32_t len)
{
	while (len--)
	{
		*dst++ = *src++;
	}
}



uint32_t getbits(const uint8_t *buf, const uint32_t n, uint32_t *i, uint32_t *l)
{
	static const uint32_t m[] = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
	uint32_t res, ol;

	ol = *l;
	if (*l >= n) 
	{
		*l = (*l) - n;
		res = (buf[*i] & m[ol]) >> (*l);
		if (*l == 0) 
		{
			*l = 8;
			(*i)++;
		}
	} 
	else 
	{
		*l = 8 - n + (*l);
		res = (buf[(*i)++] & m[ol]) << 8;
		res = (res | buf[*i]) >> (*l);
	}
	return res;
}






uint32_t getbyte(const uint8_t *buf, const uint32_t i, const uint32_t l)
{
	if (l == 8) 
	{
		return buf[i];
	} 
	else 
	{
		return (((buf[i] << 8) | buf[i+1]) >> l) & 0xff;
	}
}


int mppc_decompress(uint8_t *ibuf, uint8_t *obuf, int isize, int osize)
{
	uint32_t olen;
	uint32_t off;
	uint32_t len;
	uint32_t bits;
	uint32_t val;
	uint32_t sig;
	uint32_t i;
	uint32_t l;
	uint8_t *history;	
	uint8_t *s;
	int histptr = 0;

	uint8_t * hist = new uint8_t[MPPE_HIST_LEN];
	memset(hist, 0, MPPE_HIST_LEN);
	memset(obuf, 0, MPPE_HIST_LEN);

	history = hist + histptr;
	olen = len = i = 0;
	l = 8;
	bits = isize * 8;
	while (bits >= 8) 
	{
		val = getbyte(ibuf, i++, l);
		if (val < 0x80) 
		{	/* literal byte < 0x80 */
			(hist)[(histptr)++] = (uint8_t) val;
			olen++;
			bits -= 8;
			continue;
		}
		sig = val & 0xc0;
		if (sig == 0x80) 
		{	/* literal byte >= 0x80 */
			(hist)[(histptr)++] = (uint8_t)(0x80|((val&0x3f)<<1)|getbits(ibuf, 1 , &i , &l));
			olen++;
			bits -= 9;
			continue;
		}

		/* Not a literal byte so it must be an (offset,length) pair */
		/* decode offset */
		sig = val & 0xf0;
		if (sig == 0xf0) 
		{	/* 10-bit offset; 0 <= offset < 64 */
			off = (((val&0x0f)<<2)|getbits(ibuf, 2 , &i , &l));
			bits -= 10;
		} 
		else 
		{
			if (sig == 0xe0) 
			{	/* 12-bit offset; 64 <= offset < 320 */
				off = ((((val&0x0f)<<4)|getbits(ibuf, 4 , &i , &l))+64);
				bits -= 12;
			} 
			else 
			{
				if ((sig&0xe0) == 0xc0) 
				{	/* 16-bit offset; 320 <= offset < 8192 */
					off = ((((val&0x1f)<<8)|getbyte(ibuf, i++, l))+320);
					bits -= 16;
					if (off > MPPE_HIST_LEN - 1) 
					{
						//g_log->write("%s: too big offset value: %d\n", __FUNCTION__, off);
						delete[] hist;
						return -1;
					}
				} 
			}
		}
		/* decode length of match */
		val = getbyte(ibuf, i, l);
		if ((val & 0x80) == 0x00) 
		{	/* len = 3 */
			len = 3;
			bits--;
			getbits(ibuf, 1 , &i , &l);
		} 
		else if ((val & 0xc0) == 0x80) 
		{	/* 4 <= len < 8 */
			len = 0x04 | ((val>>4) & 0x03);
			bits -= 4;
			getbits(ibuf, 4 , &i , &l);
		} 
		else if ((val & 0xe0) == 0xc0) 
		{	/* 8 <= len < 16 */
			len = 0x08 | ((val>>2) & 0x07);
			bits -= 6;
			getbits(ibuf, 6 , &i , &l);
		} 
		else if ((val & 0xf0) == 0xe0) 
		{	/* 16 <= len < 32 */
			len = 0x10 | (val & 0x0f);
			bits -= 8;
			i++;
		} 
		else 
		{
			bits -= 8;
			val = (val << 8) | getbyte(ibuf, ++i, l);
			if ((val & 0xf800) == 0xf000) 
			{	/* 32 <= len < 64 */
				len = 0x0020 | ((val >> 6) & 0x001f);
				bits -= 2;
				getbits(ibuf, 2 , &i , &l);
			} 
			else if ((val & 0xfc00) == 0xf800) 
			{	/* 64 <= len < 128 */
				len = 0x0040 | ((val >> 4) & 0x003f);
				bits -= 4;
				getbits(ibuf, 4 , &i , &l);
			} 
			else if ((val & 0xfe00) == 0xfc00) 
			{	/* 128 <= len < 256 */
				len = 0x0080 | ((val >> 2) & 0x007f);
				bits -= 6;
				getbits(ibuf, 6 , &i , &l);
			} 
			else if ((val & 0xff00) == 0xfe00) 
			{	/* 256 <= len < 512 */
				len = 0x0100 | (val & 0x00ff);
				bits -= 8;
				i++;
			} 
			else 
			{
				bits -= 8;
				val = (val << 8) | getbyte(ibuf, ++i, l);
				if ((val & 0xff8000) == 0xff0000) 
				{	/* 512 <= len < 1024 */
					len = 0x000200 | ((val >> 6) & 0x0001ff);
					bits -= 2;
					getbits(ibuf, 2 , &i ,&l);
				} 
				else if ((val & 0xffc000) == 0xff8000) 
				{	/* 1024 <= len < 2048 */
					len = 0x000400 | ((val >> 4) & 0x0003ff);
					bits -= 4;
					getbits(ibuf, 4 , &i ,&l);
				} 
				else if ((val & 0xffe000) == 0xffc000) 
				{	/* 2048 <= len < 4096 */
					len = 0x000800 | ((val >> 2) & 0x0007ff);
					bits -= 6;
					getbits(ibuf, 6 , &i ,&l);
				} 
				else if ((val & 0xfff000) == 0xffe000) 
				{	/* 4096 <= len < 8192 */
					len = 0x001000 | (val & 0x000fff);
					bits -= 8;
					i++;
				} 
				else 
				{	/* this shouldn't happen */
					//					g_log->write("%s: wrong length code: 0x%X\n", __FUNCTION__, val);
					delete[] hist;
					return -1;
				}
			}
		}
		s = hist + histptr;
		if (histptr < (int)off)
		{
			return -1;
		}
		histptr += len;
		olen += len;
		lamecopy(s, s - off, len);//
	}
	/* Do PFC decompression */
	len = olen;
	if ((history[0] & 0x01) != 0) 
	{
		obuf[0] = 0;
		obuf++;
		len++;
	}

	if ((int)len <= osize)
	{	/* copy uncompressed packet to the output buffer */
		if (history[0] != 0x00 || history[1] != 0x21)
		{
			delete[] hist;
			return -1;
		}
		memcpy(obuf, history + 2, olen -2);
		delete[] hist;
	} 
	else 
	{
		/* buffer overflow; drop packet */
		//		g_log->write("%s: too big uncompressed packet: %d\n", __FUNCTION__, len + (PPP_HDRLEN / 2));
		delete[] hist;
		return -1;
	}
	return (int) len -2;
}



