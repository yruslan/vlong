/* vlong, multiple-precision integer cross-platform C++ Class
 *
 * Supports all essential numeric theory algorithms to implement public key cryptography procedures. 
 * Implementation is in plain C++ and thus architecture and endian-portable.
 *
 * Anyone can use it freely for any purpose. There is 
 * absolutely no guarantee it works or fits a particular purpose (see below). 
 *
 * This class has been made by Ruslan Yushchenko (yruslan@gmail.com)
 *
 * Inspired by and mostly based on the public domain work of
 *     Tom St Denis, tomstdenis@gmail.com, http://libtom.org (LibTomMath Library)
 *
 * Referance materials:
 *     [BNM] Tom St Denis. BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic, 2006
 *     [HAC] Menezes et al. Handbook of Applied Cryptography, 1997
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 * 
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * For more information, please refer to <http://unlicense.org/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "vlong.h"

// Simulate static asserts (produces "negative subscript" error if fails
// Signed and unsigned digits and words must be the same size
typedef int static_assert_acceptable_dig_size1 [sizeof(sdig_t)==sizeof(udig_t) ? 1 : -1];
typedef int static_assert_acceptable_dig_size2 [sizeof(swrd_t)==sizeof(swrd_t) ? 1 : -1];
// Double digit (word) type must 2 times bigges then single digit type
typedef int static_assert_acceptable_dig_size3 [sizeof(uwrd_t)==sizeof(udig_t)*2 ? 1 : -1];

#ifdef _MSC_VER
#pragma warning( disable : 4996 )
#endif 

#ifndef _min
#define _min(a,b)   (((a)<(b))?(a):(b))
#endif

//Characters per digit, bits per digit
static const char CiD = ((int) sizeof(udig_t));
static const char BiD = (CiD << 3);

// Convert number of bits to number of digits
#define BITS_TO_DIGITS(i)  (((i)+BiD-1)/BiD)

// Convert number of bytes to number of digits
#define CHARS_TO_DIGITS(i) (((i)+CiD-1)/CiD)

// Check return value and fail if error
#define CHECK(f) if( (ret = f) != 0 ) return ret

// Comparison results
#define MP_GT   1
#define MP_LT   -1
#define MP_EQ   0

// Sign of a number
#define MP_NEG  -1
#define MP_ZPOS  1

// Mask to select single digit in double digit data type
static const udig_t MP_MASK_DIG = ~((udig_t)0);

// Characters used to read/write a number in a given radix
static const char  *MP_DIG_CHARS = "0123456789ABCDEF";

// Small primes to chaek before Miller-Rabin primarity test is used
static const sdig_t ltm_prime_tab[] = {
  0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
  0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
  0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
  0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F,
#ifndef MP_8BIT
  0x0083,
  0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
  0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
  0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
  0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

  0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
  0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
  0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
  0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
  0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
  0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
  0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
  0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

  0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
  0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
  0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
  0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
  0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
  0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
  0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
  0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

  0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
  0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
  0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
  0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
  0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
  0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
  0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
  0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653,
#endif
  0
};

// Default pseudo-random generator. Completely insecure and should
// never be used in security-related procedures.
//
// Used in cases in which real randomness is actually not needed.
// For example in Miller-Rabin primarity test.
//
static int _local_prng(void *pPRNG, char *pOutput, size_t nSize)
{
    unsigned int i;
    unsigned char c;
    for (i=0; i<nSize; i++)
    {
        c = rand() % 256;
        pOutput[i] = c;

    }
    return 0;
}

// Init vlong number. (For internal use only)
void vlong::Init()
{
    s = MP_ZPOS;
    d = NULL;
    na = 0;
    nu = 0;
    tmp = NULL;
    ntmp = 0;
}

// Copy vlong object
int vlong::Copy(const vlong &v)
{
    int ret = VLONG_SUCCESS;
    if (na<v.nu)
        CHECK( Grow(v.nu) );
    s  = v.s;
    nu = v.nu;
    memcpy(d, v.d, nu*sizeof(udig_t));
    return ret; 
}

// This function is used ONLY to swap a temporary pointer
// in case result of a function is the same object as 
// one or more of its arguments.
//
// It does NOT transfer the sign and doen't suppose to.
// Do not use the function for any other purposes
int vlong::prvMovePtr(vlong &v)
{
    try
    {
        delete [] d;
    }
    catch (...)
    {
        return VLONG_ERR_MEMORY_FREE;
    }

    d = v.d;
    na = v.na;
    nu = v.nu;
    v.s=MP_ZPOS;
    v.d = NULL;
    v.na=0;
    v.nu=0;
    return VLONG_SUCCESS;
}

// Clears vlong object and frees all buffers
int vlong::Clear()
{
    try
    {
        if (d!=NULL)
            delete [] d;
        if (tmp!=NULL)
            delete [] tmp;
    }
    catch (...)
    {
        return VLONG_ERR_MEMORY_FREE;
    }

    return VLONG_SUCCESS;
}

// Grow a number to a specified number of digits [BNM pp.25 Algorithm 2.6]
int vlong::Grow(size_t n)
{
    //TODO: Optimization: grow to a nearest larger multiple of 2
    //                    shrink if n < 1/4 of that power
	//                    (unimplemented)

    if (na>=n) 
    {
        if (nu<na)  memset(d+nu, 0, (na-nu)*sizeof(udig_t));
        return VLONG_SUCCESS;
    }
#ifdef VLONG_MAX_DIGITS
    if (n>VLONG_MAX_DIGITS) return VLONG_ERR_MEMORY_EXEED;
#endif
    
    //At this point guaranteed to be 0<n<VLONG_MAX_DIGITS
    try
    {
        udig_t *d_new = new udig_t[n];
        if (d_new == NULL) return VLONG_ERR_MEMORY_ALLOC;
        memset(d_new, 0, n*sizeof(udig_t));
        if (nu>0) memcpy(d_new, d, nu*sizeof(udig_t));
        na = n;
        if (d!=NULL) delete [] d;
        d = d_new;
    }
    catch (...)
    {
        return VLONG_ERR_MEMORY_ALLOC;
    }

    return VLONG_SUCCESS;
}

// Remove trailing zeros if any [BNM pp.31 Algorithm 2.9]
int vlong::Clamp()
{
    int i;
    if (nu>0)
    {
        for (i=nu-1; i>=0; i--)
        {
            if (d[i]==0)
                nu--;
            else
                break;
        }
    }
    if (nu==0) s = MP_ZPOS;
    return VLONG_SUCCESS;
}

// Set number equal to zero
void vlong::SetZero()
{
    if (nu>0)
        memset(d,0,sizeof(udig_t)*nu);
    nu=0;
    s=1;
}

// Get least significant digit (unsigned)
udig_t vlong::GetInt()
{
    if (nu==0)
        return 0;
    else
        return d[0];
}

// Set value to a single digit integer
int vlong::SetValue(sdig_t v)
{
    int ret = VLONG_SUCCESS;
    if (v == 0)
    {
        SetZero();
        if (na>0) memset(d, 0, na*sizeof(udig_t));
        return ret;
    }

    if (na>1)
        memset(d, 0, na*sizeof(udig_t));
    else
        CHECK ( Grow(1) );

    nu = 1;
    if (v>0)
    {
        s = MP_ZPOS;
        d[0] = v;
    }
    else
    {
        s = MP_NEG;
        d[0] = -v;
    }
    return ret;
}

// Swap contents of two vlong objects
// Faster then copying because it doesn't require
// memory copy operation. Just swaps pointers
void vlong::swap(vlong &v)
{
    char sn;
    udig_t *p;
    char *pt;
    size_t x;

    sn = s;        s   = v.s;     v.s   = sn;
    x = na;        na  = v.na;    v.na  = x;
    x = nu;        nu  = v.nu;    v.nu  = x;
    p = d;         d   = v.d;     v.d   = p;

    pt = tmp;      tmp = v.tmp;   v.tmp = pt;
    x  = ntmp;     ntmp= v.ntmp;  v.ntmp= x;
}

// Convert from a NUUL-terminated string of 2<=radix<=16
int vlong::FromString(const char *szNumber, int radix/* = 16*/)
{
    if (radix<2 || radix>16) return VLONG_ERR_BAD_ARG_2;
    return FromStringBuf(szNumber, 0, radix, MP_DIG_CHARS);
}

// Convert from arbitrary string of 2<=radix<=16
// or you can supply a custom character alphabet to convert
// from a custom numeric system (2<=radix<=256)
int vlong::FromStringBuf(const char *pBuf, size_t nBufLen /*=0*/, int nRadix /*= 16*/, const char *szCustomChars /*= NULL*/)
{
    int i,j;
    size_t len, cd, cp, nNeeds;
    sdig_t dig;
    char c;
    const char *pos;
    const char *pAlphabet;
    size_t rd = nRadix;
    int ret = VLONG_SUCCESS;

    if (pBuf == NULL) return VLONG_ERR_BAD_ARG_1;
    if (szCustomChars == NULL)
    {
        pAlphabet = MP_DIG_CHARS;
        if (rd<2 || rd>16) return VLONG_ERR_BAD_ARG_3;
    }
    else
    {
        pAlphabet = szCustomChars;
        if (rd == 0) rd = strlen(szCustomChars);
        if (rd<2 || rd>256) return VLONG_ERR_BAD_ARG_3;
    }

    if (nBufLen == 0)
        len = strlen(pBuf);
    else
        len = nBufLen;

    int b = 8;
    if (rd<256) b-=1;
    if (rd<128) b-=1;
    if (rd<64) b-=1;
    if (rd<32) b-=1;
    if (rd<16) b-=1;
    if (rd<8) b-=1;
    if (rd<4) b-=1;

    nNeeds = BITS_TO_DIGITS( b*len );
    nu = 0;
    s = MP_ZPOS;
    CHECK( Grow(nNeeds+1) );

    if (rd == 16)
    {
        for(i=len-1,j=0; i>=0; i--,j++)
        {
            cd = (j / (2*CiD));
            cp = (j % (2*CiD));
            c = pBuf[i];
            if(c=='-')
            {
                s = MP_NEG;
                break;
            }

            if (pAlphabet==MP_DIG_CHARS)
            {
                dig=-1;
                if (c>=48 && c<=57) dig = c - 48;
                if (c>=65 && c<=70) dig = c - 55;
                if (c>=97 && c<=102) dig = c - 87;
                if (dig<0) return VLONG_ERR_INVALID_CHAR;
            }
            else
            {
                pos = strchr(pAlphabet,c);
                if (pos==NULL) return VLONG_ERR_INVALID_CHAR;
                dig = (sdig_t) (pos-pAlphabet);
            }

            d[cd] |= dig << (cp*4);
            if(dig!=0) nu=cd+1;
        }
        if(nu==0) SetZero();
    }
    else
    {
        for(i=0; i<(int)len; i++)
        {
            c = pBuf[i];
            if (i==0 && c=='-')
            {
                s = MP_NEG;
                continue;
            }
            if (pAlphabet==MP_DIG_CHARS && rd<=16)
            {
                dig=-1;
                if (c>=48 && c<=57) dig = c - 48;
                if (c>=65 && c<=70) dig = c - 55;
                if (c>=97 && c<=102) dig = c - 87;
                if (dig<0 || ((size_t)dig)>=rd) return VLONG_ERR_INVALID_CHAR;
            }
            else
            {
                pos = strchr(pAlphabet,c);
                if (pos==NULL) return VLONG_ERR_INVALID_CHAR;
                dig = (sdig_t) (pos-pAlphabet);
            }

            Mul(*this, rd);
            if (s == MP_ZPOS)
                Add(*this, dig);
            else
                Sub(*this, dig);
        }
    }
    return VLONG_SUCCESS;
}

// Convert from unsigned big-endian binary number
int vlong::FromBinary(const char *szNumber, size_t buflen)
{
    s = MP_ZPOS;
    return SetBytes(0, buflen, szNumber);
}

// Convert to temporary readable string (useful in printf) 2<=radix<=16
const char *vlong::ToString(int radix /*= 16*/) const
{
    if (radix<2 || radix>16) return NULL;
    size_t b = BiD;
    if(radix >= 4  ) b>>=1;
    if(radix >= 16 ) b>>=1;

    size_t needs = nu*b + 2;
    if (ntmp<needs)
    {
        delete [] tmp;
        tmp = new char [needs];
        ntmp = needs;
    }

    int ret = ToStringBuf(tmp, ntmp, radix, MP_DIG_CHARS);
    if (ret == VLONG_SUCCESS)
        return tmp;
    else
    {
        strcmp(tmp,"");
        return tmp;
    }
    
    return NULL;
}

static const unsigned char base64_enc[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline int POS(char c)
{
    if (c>='A' && c<='Z') return c - 'A';
    if (c>='a' && c<='z') return c - 'a' + 26;
    if (c>='0' && c<='9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;

    return -2;
}

// Convert from a NUUL-terminated BASE64-encoded string
int vlong::FromBase64(const char *szNumber)
{
    size_t len, dlen;
    int n[4];
    unsigned char *q;
    int ret = VLONG_SUCCESS;

    if (szNumber==NULL) return VLONG_ERR_BAD_ARG_1;
    len = strlen(szNumber);

    if (len==0)
    {
        SetZero();
        return ret;
    }

    if (len % 4) return VLONG_ERR_BAD_ARG_1;

    size_t nNeedBytes = (len/4)*3;
    size_t nNeedDigits = CHARS_TO_DIGITS(nNeedBytes);

    //(Re)allocating memory
    if (ntmp < (size_t)nNeedBytes+1)
    {
        if (tmp!=NULL) delete []tmp;
        tmp = new char[nNeedBytes+1];
        ntmp = nNeedBytes+1;
    }
    q = (unsigned char*) tmp;
    
    for(const char *p = szNumber; *p;)
    {
        n[0] = POS(*p++);
        n[1] = POS(*p++);
        n[2] = POS(*p++);
        n[3] = POS(*p++);

        if (n[0]==-1 || n[1]==-1) return VLONG_ERR_INVALID_CHAR;
        if (n[2]==-1 && n[3]!=-1) return VLONG_ERR_INVALID_CHAR;

        q[0] = (n[0] << 2) + (n[1] >> 4);
        if (n[2] != -1) q[1] = ((n[1] & 15) << 4) + (n[2] >> 2);
        if (n[3] != -1) q[2] = ((n[2] & 3) << 6) + n[3];
        q += 3;
    }

    dlen = ((char *)q - tmp) - (n[2]==-1 ? 1 : 0) - (n[3]==-1 ? 1 : 0);
    assert(dlen<=nNeedBytes);
    
    CHECK( FromBinary(tmp+1, dlen-1) );

    if (tmp[0]==0)
        s = MP_ZPOS;
    else
        s = MP_NEG;

    Clamp();

    return ret;
}

// Convert to BASE64-encoded string and save to user-specified buffer
int vlong::ToBase64Buf(char *pBuf, size_t &nBufLen) const
{
    int nNeedsBin, nNeedsBase64, i;
    unsigned char *pBinB;
    char *p;
    int c;
    int ret = VLONG_SUCCESS;
    
    nNeedsBin = ((GetNumBits()+7)/8)+1;
    nNeedsBase64 = ((nNeedsBin << 3) / 6);

    pBinB = new unsigned char[nNeedsBin];
    if (s == MP_ZPOS)
        pBinB[0] = 0;
    else
        pBinB[0] = 1;

    ret = ToBinary((char *)pBinB+1, nNeedsBin-1);
    if (ret != VLONG_SUCCESS)
    {
        delete [] pBinB;
        return ret;
    }

    switch((nNeedsBin << 3) - (nNeedsBase64*6))
    {
        case  2: nNeedsBase64 += 3; break;
        case  4: nNeedsBase64 += 2; break;
        default: break;
    }
    nNeedsBase64++; //for trailing '\0'

    i=0;
    p = pBuf;
    while(i < nNeedsBin)
    {
        c = pBinB[i++];
        c *= 256;
        if (i < nNeedsBin) c += pBinB[i];
        i++;

        c *= 256;
        if (i < nNeedsBin) c += pBinB[i];
        i++;

        *p++ = base64_enc[(c & 0x00fc0000) >> 18];
        *p++ = base64_enc[(c & 0x0003f000) >> 12];

        if (i > nNeedsBin + 1)
            *p++ = '=';
        else
            *p++ = base64_enc[(c & 0x00000fc0) >> 6];

        if (i > nNeedsBin)
            *p++ = '=';
        else
            *p++ = base64_enc[c & 0x0000003f];
    }
    *p = 0; 

    delete [] pBinB;

    return ret;
}

// Convert to BASE64-encoded string and save to automatically generated internal temporary buffer
const char *vlong::ToBase64()
{
    size_t nNeedsBin, nNeedsBase64;
    int ret = VLONG_SUCCESS;

    nNeedsBin = ((GetNumBits()+7)/8)+1;
    nNeedsBase64 = ((nNeedsBin << 3) / 6);

    switch((nNeedsBin << 3) - (nNeedsBase64*6))
    {
        case  2: nNeedsBase64 += 3; break;
        case  4: nNeedsBase64 += 2; break;
        default: break;
    }
    nNeedsBase64++; //for trailing '\0'

    if (ntmp < nNeedsBase64)
    {
        if (tmp!=NULL) delete [] tmp;
        tmp = new char[nNeedsBase64];
        ntmp = nNeedsBase64;
    }

    ret = ToBase64Buf(tmp, nNeedsBase64);
    if (ret == VLONG_SUCCESS)
        return tmp;
    else
    {
        strcmp(tmp,"");
        return tmp;
    }

    return tmp;
}

// Convert to string of 2<=radix<=16
// or you can supply a custom character alphabet to convert 
// to a custom numeric system (2<=radix<=256)
int vlong::ToStringBuf(char *pBuf, size_t &nBufLen, int nRadix /*= 16*/, const char *szCustomChars /*=NULL*/) const
{
    int c;
    char t;
    size_t i, j, k=0, b;
    size_t nNeeds = 0;
    const char *pAlphabet;
    int ret = VLONG_SUCCESS;

    size_t rd = nRadix;
    if (szCustomChars == NULL)
    {
        pAlphabet = MP_DIG_CHARS;
        if (rd<2 || rd>16) return VLONG_ERR_BAD_ARG_3;
    }
    else
    {
        pAlphabet = szCustomChars;
        if (rd == 0) rd = strlen(szCustomChars);
        if (rd<2 || rd>256) return VLONG_ERR_BAD_ARG_3;
    }
    
    //Calculate size needed to carry the number
    b = BiD;
    if(rd >= 4  ) b>>=1;
    if(rd >= 16 ) b>>=1;
    if(rd == 256) b>>=1;

    nNeeds = nu*b + 2;
    if (nBufLen < nNeeds) 
    {
        nBufLen = nNeeds;
        return VLONG_ERR_BUFFER_SMALL;
    }

    if (nu == 0)
    {
        strcpy(pBuf, "0");
        return ret;
    }

    if (s == MP_NEG) *(pBuf++) = '-';

    if (rd == 16)
    {
        for(i=0; i<nu; i++)
        {
            for(j=0; j<CiD; j++)
            {
                c = (d[nu-i-1] >> ((CiD-j-1) << 3)) & 0xFF;

                if(c == 0 && k == 0 && (nu-i+CiD-j+3) != 0 )
                    continue;

                if (pBuf!=tmp || (c/16)!=0)
                    *(pBuf++) = pAlphabet [c / 16];
                *(pBuf++) = pAlphabet [c % 16];
                k = 1;
            }
        }
        *(pBuf++) = '\0';
    }
    else
    {
        vlong v(*this);
        char *pt = pBuf;
        int  digs = 0;
        sdig_t  r;
        v.s = MP_ZPOS;
        while (v.nu>0)
        {
            ret = v.Div(v, rd, &r);
            if (ret!=VLONG_SUCCESS) break;
            *(pt++) = pAlphabet[r];
            ++digs;
        }
        *pt++ = '\0';
        nBufLen = (size_t) (pt-pBuf);

        //Revers order
        i = 0;
        j = digs - 1;
        while (i < j)
        {
            t = pBuf[i];
            pBuf[i] = pBuf[j];
            pBuf[j] = t;
            ++i;
            --j;
        }
    }

    return ret;
}

// Convert unsigned part of the vlong number to big-endian binary buffer
int vlong::ToBinary(char *buf, size_t buflen) const
{
    size_t nb = ((GetNumBits()+BiD-1)/BiD);
    if (buflen>0) memset(buf, 0, buflen);
    if (nb>buflen) return VLONG_ERR_BUFFER_SMALL;
    return GetBytes(0, buflen, buf);
}

//******************************* Comparisons ******************************************

int vlong::Compare(sdig_t x) const
{
    /* compare with zero */
    if (isZero())
    {
        if (x==0) return MP_EQ;
        return x>0 ? MP_GT : MP_LT;
    }

    /* compare based on sign */
    if (s == MP_NEG && x>=0)
        return MP_LT;
    if (s == MP_ZPOS && x<=0)
        return MP_LT;

    /* compare based on magnitude */
    if (nu > 1)
    {
        if (s == MP_NEG)
            return MP_LT;
        else
            return MP_GT;
    }

    if (x>0)
    {  
        // compare the only digit of a to b
        if ((swrd_t)d[0] > x)
            return MP_GT;
        if ((swrd_t)d[0] < x)
            return MP_LT;
    }
    else
    {
        if ((swrd_t)d[0] > -x)
            return MP_LT;
        if ((swrd_t)d[0] < -x)
            return MP_GT;
    }

    return MP_EQ;
}

int vlong::Compare(const vlong &v) const
{
    if (nu==0 && v.nu==0) return MP_EQ;
    if (s != v.s)
    {
        if (s<0)
            return MP_LT;
        else
            return MP_GT;
    }
    if (s < 0)
        return CompareMag(v, *this);
    else
        return CompareMag(*this, v);

    return VLONG_ERR_UNEXPECTED;
}

// Compare vlong number my magnitude (ignoring sign) [BNM pp.48 Algorithm 3.9]
// Results are usual {-1,0,1} for {|a|<|b|, |a|==|b|, |a|>|b|} results.
int vlong::CompareMag(const vlong &a, const vlong &b)
{
    int i;

    /* compare based on # of non-zero digits */
    if (a.nu > b.nu) 
        return MP_GT;
  
    if (a.nu < b.nu) 
        return MP_LT;

    /* compare based on digits  */
    for (i=a.nu-1; i>=0; i--)
    {
        if (a.d[i] > b.d[i]) 
            return MP_GT;
        if (a.d[i] < b.d[i]) 
            return MP_LT;
    }
    return MP_EQ;
}


//*************************** Bitwise operations ***************************************

size_t vlong::GetNumBits() const
{
    size_t bits=0;

    if (isZero()) return 0;
    if (nu>1) bits = BiD*(nu-1);
    
    udig_t dig = d[nu-1];
    while (dig!=0) {dig>>=1;bits++;}

    return bits;
}

static const int lnz[16] = { 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0 };

//Counts the number of lsbs which are zero before the first one bit
//based on mp_cnt_lsb() of LibTomMath
size_t vlong::GetNumLSB() const
{
    size_t i;
    udig_t q, qq;

    // easy out
    if (isZero()) return 0;

    // scan lower digits until non-zero
    for (i=0; i<nu && d[i]==0; i++);

    assert(i<nu);

    q = d[i];
    i *= BiD;

    // now scan this digit until a 1 is found
    if ((q & 1) == 0)
    {
        do 
        {
            qq  = q & 15;
            i  += lnz[qq];
            q >>= 4;
        } while (qq == 0);
    }
    return i;
}

//based on mp_cnt_msb() of LibTomMath
size_t vlong::GetNumMSB() const
{
    size_t bits = GetNumBits();
    //if (bits>0) bits--;
    return bits;
}

int vlong::prvLeftShiftDigits(size_t digs)
{
    int ret = VLONG_SUCCESS;
    size_t i;

    if (digs==0) return ret;

    // grow to fit the new digits
    if (na < nu + digs) CHECK( Grow(nu+digs) );

    for (i=0; i<nu; i++)
        d[nu+digs-1-i] = d[nu-1-i];

    for (i=0; i<digs; i++)
        d[i] = 0;

    nu+=digs;

    return ret;
}

int vlong::prvRightShiftDigits(size_t digs)
{
    int ret = VLONG_SUCCESS;
    size_t i;

    if (digs==0) return ret;
    if (digs>=nu) {SetZero(); return ret;}
    
    for (i=0; i<nu-digs; i++)
        d[i] = d[i+digs];

    for (i=nu-digs; i<nu; i++)
        d[i] = 0;

    nu-=digs;

    return ret;
}

// shift right by a certain bit count
int vlong::ShiftRight(const vlong &a, int bits)
{
    int ret = VLONG_SUCCESS;
    size_t b2;
    int i;
    udig_t tmp1,tmp2,mask;

    if (bits<0) return ShiftLeft(a, -bits);

    if (&a!=this) SetValue(a);
    if (nu <= (size_t) bits/BiD) {SetZero(); return ret;}
    if (na < (size_t)(nu - bits/BiD)) CHECK( Grow(nu - bits/BiD) );

    // shift by as many digits in the bit count
    if (bits >= (int)BiD) prvRightShiftDigits (bits / BiD);
    if (nu == 0) return ret;
  
    // shift any bit count < BiD
    b2 = (udig_t) (bits % BiD);

    if (b2 > 0)
    {
        // mask
        mask = (((udig_t)1) << b2) - 1;
        tmp1 = 0;
        for (i=nu-1; i>=0; i--)
        {
            // get the lower  bits of this word in a temp
            tmp2 = d[i] & mask;

            // shift the current word and mix in the carry bits from the previous word
            d[i] = (d[i] >> b2) | (tmp1 << (BiD-b2));
            
            // set the carry to the carry bits of the current word found above
            tmp1 = tmp2;
        }
    }

    if (d[nu-1] == 0) nu--;
    if (nu==0) s = MP_ZPOS;

    return ret;
}


// shift left by a certain bit count
int vlong::ShiftLeft(const vlong &a, int bits)
{
    int ret = VLONG_SUCCESS;
    size_t b2,i;
    udig_t u;
    uwrd_t sum;
    if (bits<0) return ShiftRight(a, -bits);

    // copy
    if (&a != this) CHECK( SetValue(a) );

    if (na < (size_t)(nu + bits/BiD + 1)) CHECK( Grow(nu + bits/BiD + 1) );

    // shift by as many digits in the bit count
    if (bits >= BiD) CHECK( prvLeftShiftDigits(bits/BiD) );

    b2 = (size_t) (bits % BiD);
    if (b2 > 0)
    {
        u = 0;
        for (i=0; i<nu; i++)
        {
            /* T[i] = X[i] << b2 */
            sum = ( ((uwrd_t) d[i]) << b2 ) + (uwrd_t) u;
            d[i] = (udig_t)(sum & MP_MASK_DIG);

            /* U = carry bit of T[i] */
            u = (udig_t) (sum >> BiD);
        }

        if (u>0)
        {
            d[nu] = u;
            nu++;
        }       
    }

    return ret;
}

int vlong::SetBit(size_t num, char bit)
{
    int ret = VLONG_SUCCESS;
    size_t dig = num/BiD;
    size_t pos = num%BiD;
    udig_t  val;
    bit&=1;

    if (dig>=nu)
    {
        if (bit>0)
        {
            CHECK(Grow(dig+1));
            nu = dig+1;
        }
        else
            return ret;
    }
    
    val = ( (udig_t)bit << pos );
    d[dig] = (d[dig] & (~(val))) | val;
        
    return ret;
}

char vlong::GetBit(size_t num)
{
    size_t dig = num/BiD;
    size_t pos = num%BiD;
    udig_t  val = 1;


    if (dig>=nu)
        return VLONG_ERR_OUT_OF_RANGE;

    return (char ) ( (d[dig]&(val<<pos))>>pos );
}

int vlong::Xor(const vlong &a, const vlong &b)
{
    int nmin = a.nu<b.nu? a.nu : b.nu;
    int i;
    int ret = VLONG_SUCCESS;

    if (&a==&b) { SetZero(); return ret; }

    const vlong *t1 = a.nu>b.nu ? &a : &b;
    const vlong *t2 = a.nu>b.nu ? &b : &a;

    if (t1!=this && t2!=this)
        CHECK( SetValue( *t1 ) );

    for (i=0; i<nmin; i++)
        d[i] = t1->d[i] ^ t2->d[i];

    return ret;
}

//**************************** Bytewise operations *************************************
int vlong::SetBytes(int start, size_t count, const char *buf)
{
    size_t i,dig,pos;
    udig_t val;
    const unsigned char *p = (const unsigned char *) buf;

    int ret = VLONG_SUCCESS;

    if (start+count > nu*CiD)
    {
        CHECK( Grow(start+count+1) );
        nu = CHARS_TO_DIGITS(start+count);
    }

    for (i=0; i<count; i++)
    {
        dig = (start+count-i-1)/CiD;
        pos = (start+count-i-1)%CiD;

        val = 0xFF << pos*8;
        d[dig] = (d[dig] & (~val)) | (p[i] << pos*8);
    }

    return ret;
}

int vlong::GetBytes(int start, size_t count, char *buf) const
{
    size_t i,dig,pos;
    udig_t val;
    int ret = VLONG_SUCCESS;

    if (start+count > nu*CiD) return VLONG_ERR_OUT_OF_RANGE;

    for (i=0; i<count; i++)
    {
        dig = (start+count-i-1)/CiD;
        pos = (start+count-i-1)%CiD;

        val = 0xFF << pos*8;
        ((unsigned char *)buf)[i] = (unsigned char) ( (d[dig] & val) >> pos*8 );
    }

    return ret;
}

//********************************* Generators *****************************************    

int vlong::GenRandomBytes(size_t bytes, int (*pRNG_f)(void *, char *, size_t) /*= NULL*/, void *pRNG_ctx /*= NULL*/)
{
    //Pointer to a pseudo-random generator
    int (*pRNG_f2)(void *, char *, size_t);
    
    int ret = VLONG_SUCCESS;
    pRNG_f2 = pRNG_f;

    if (bytes<1) return VLONG_ERR_BAD_ARG_1;

    if (pRNG_f==NULL)
    {
        pRNG_f2 = _local_prng;
        ret = VLONG_WRN_INSECURE_RNG;
    }

    CHECK(Grow(CHARS_TO_DIGITS(bytes)+1));

    char *buf = new char[bytes+1];
    memset(buf,0,bytes+1);

    ret = pRNG_f2(pRNG_ctx,buf,bytes);
    if (ret!=0)
    {
        delete [] buf;
        return ret;
    }

    ret = FromBinary(buf, bytes);
    assert(na>=CHARS_TO_DIGITS(bytes));
    nu = CHARS_TO_DIGITS(bytes);

    return ret;
}

int vlong::GenRandomBits(size_t bits, int (*pRNG_f)(void *, char *, size_t) /*= NULL*/, void *pRNG_ctx /*= NULL*/)
{
    size_t bt = (bits+7)/8, d1 = BITS_TO_DIGITS(bits), d2 = bits % BiD;
    int ret = VLONG_SUCCESS;

    if (bt>0)
    {
        CHECK( GenRandomBytes(bt, pRNG_f, pRNG_ctx) );
    }
    
    if (d2>0 && nu>0)
    {
        d[nu-1] &= (MP_MASK_DIG >> (BiD-((int) d2)));
        d[nu-1] |= (1 << ((int)(d2-1)));
    }
    if (d2==0 && nu>0)
        d[nu-1] |= (((udig_t)1) << (BiD-1));
    return ret;
}

int vlong::GenRandomPrime(size_t bytes, int (*pRNG_f)(void *, char *, size_t) /*= NULL*/, void *pRNG_ctx /*= NULL*/)
{
    int ret = VLONG_SUCCESS;
    if ( bytes==0 ) return VLONG_ERR_BAD_ARG_1;

    CHECK( GenRandomBytes(bytes, pRNG_f, pRNG_ctx) );
    return SearchNearestPrime();
}

//********************************** Primarity *****************************************

int vlong::SearchNearestPrime()
{
    int ret;

    if (nu<1) return VLONG_ERR_BAD_ARG_1;

    d[0] |= 3;

    while( !IsPrime() )
    {
        CHECK( Add(*this, 2) );
    }

    return VLONG_SUCCESS;
}

// Miller-Rabin test of "a" to the base of "b" as described in 
// HAC pp. 139 Algorithm 4.24
//
// Sets result to 0 if definitely composite or 1 if probably prime.
// Randomly the chance of error is no more than 1/4 and often 
// very much lower.
//
int vlong::prvIsMillerRabinPrime(const vlong &a, const vlong &b, bool &bPrime)
{
    vlong n1, y, r;
    int lsb, j;
    int ret = VLONG_SUCCESS;

    // default 
    bPrime = false;

    // ensure b > 1
    if (a.Compare(1)!=MP_GT) return VLONG_ERR_BAD_ARG_1;

    // get n1 = a - 1
    CHECK( n1.SetValue(a) );
    CHECK( n1.Sub(n1,1) );

    // set 2**s * r = n1
    CHECK( r.SetValue(n1) );

    // count the number of least significant bits
    // which are zero
    lsb = (int) r.GetNumLSB();

    // now divide n - 1 by 2**s
    CHECK( r.ShiftRight(r,lsb) );

    // compute y = b**r mod a
    y.PowMod(b, r, a);

    // if y != 1 and y != n1 do
    if (y.Compare(1) != MP_EQ && y.Compare(n1) != MP_EQ)
    {
        j = 1;
        // while j <= s-1 and y != n1
        while ((j <= (lsb - 1)) && y.Compare(n1) != MP_EQ)
        {
            CHECK( y.SqrMod(y,a) );

            // if y == 1 then composite
            if (y.Compare(1) == MP_EQ) return false;

            j++;
        }
        
        // if y != n1 then composite
        if (y.Compare(n1) != MP_EQ) return false;
    }

    bPrime = true;

    return false;
}

bool vlong::IsPrime()
{
    bool bPrime = false;
    int i,j,n;
    vlong b;
    int ret = VLONG_SUCCESS;
    vlong r;
    sdig_t r1,r2;

    if (nu==0) return false;

    // Test small factors
    if((d[0]&1) == 0) return false;

    for(i=0; ltm_prime_tab[i]>0; i++ )
    {
        if (Compare(ltm_prime_tab[i]) != MP_GT) return true;
        r2 = (sdig_t) (ltm_prime_tab[i]);
        r1 = ModDig(*this, r2);
        if( r1 == 0 ) return false;
    }

    j = GetNumMSB();

    //Set number of trials (HAC table 4.4)
    n = 27;
    if (j>150)  n=18;
    if (j>250)  n=12;
    if (j>350)  n=8;
    if (j>650)  n=4;
    if (j>850)  n=3;
    if (j>1300) n=1;

    for( i = 0; i < n; i++ )
    {
        // Pick a random base
        ret = b.GenRandomBytes( nu*CiD );

        if (ret!=VLONG_SUCCESS && ret!=VLONG_WRN_INSECURE_RNG) return false;

        if( b.GetNumMSB() >= GetNumMSB() )
        {
            j = b.GetNumMSB() - GetNumMSB();
            ret = b.ShiftRight(b, j+1);
            if (ret!=VLONG_SUCCESS) return false;
        }
        b.d[0] |= 3;

        ret = prvIsMillerRabinPrime(*this, b, bPrime);

        if (!bPrime || ret != VLONG_SUCCESS) return false;
    }

    if (ret!=VLONG_SUCCESS)
        return false;
    else
        return bPrime;
}

//************************** Long-Short Arithmetic *************************************
// single digit addition
int vlong::Add(const vlong &a, sdig_t b)
{
    //vlong ttt = a;
    uwrd_t sum;
    udig_t u;
    size_t i;
    int ret = VLONG_SUCCESS;    

    if (b == 0) return ret;
    if (a.nu == 0) return SetValue(b);
    
    // if signs are different => it is really a substraction
    if ((a.s == MP_NEG && b>0) || (a.s == MP_ZPOS && b<0)) return Sub(a, -b);

    if (na < a.nu+1) CHECK( Grow(a.nu+1) );
    if (&a!=this) CHECK( SetValue(a) );

    // clear msb
    d[nu]=0;
    
    // add digit, after this we're propagating
    // the carry.
    sum = ((uwrd_t) a.d[0]) + ((uwrd_t)b);
    d[0] = (udig_t)(sum & MP_MASK_DIG);

    // U = carry bit of T[i]
    u = (udig_t) (sum >> BiD);

    for (i=1; i<a.nu && u>0; i++)
    {
        /* T[i] = X[i] + U */
        sum = ((uwrd_t) a.d[i]) + (uwrd_t)u;
        d[i] = (udig_t)(sum & MP_MASK_DIG);

        /* U = carry bit of T[i] */
        u = (udig_t) (sum >> BiD);
    }

    if (u>0)
    {
        d[nu] = u;
        nu ++;
    }

    //For testing
    //printf("a.FromString(\"%s\",16);sm=%d;c.FromString(\"%s\",16);s+=sm;\n", ttt.ToString(16), b, ToString(16));
    //printf("TEST(\"%s+%d=%s\", c==s);\n", ttt.ToString(16), b, ToString(16));
    //printf("%s + %d = %s\n", ttt.ToString(16), b, ToString(16));

    return ret;
}

// single digit substraction
int vlong::Sub(const vlong &a, sdig_t b)
{
    swrd_t dif;
    udig_t u;
    udig_t ba;
    size_t i;
    int ret = VLONG_SUCCESS;    

    if (b == 0) return ret;
    if (a.nu == 0) return SetValue(-b);
    
    // if signs are different => it is really an addition
    if ((a.s == MP_NEG && b>0) || (a.s == MP_ZPOS && b<0)) return Add(a, -b);

    // now we know the signs are the same, so substract absolute values
    if (b > 0)
        ba = (udig_t) b;
    else
        ba = (udig_t) -b;

    if (na < a.nu) CHECK( Grow(a.nu) );
    if (&a!=this) CHECK( SetValue(a) ); 

    // if a <= b simply fix the single digit
    if (a.nu == 1 && a.d[0] <= ba)
    {
        d[0] = (udig_t) (ba - d[0]);
        s = a.s==MP_ZPOS ? MP_NEG : MP_ZPOS;
        if (d[0] == 0)
        {
            s = MP_ZPOS;
            nu = 0;
        }
        return ret;
    }

    // T[i] = A[i] - B[i] - U
    dif = ((swrd_t)a.d[0]) - ((swrd_t)ba);
    u = dif<0 ? 1 : 0;
    d[0] = (udig_t)(dif & MP_MASK_DIG);

    // substract from higher magnitude
    for (i = 1; i<a.nu && u>0; i++)
    {
        // T[i] = A[i] - U
        dif = ((swrd_t)a.d[i]) - ((swrd_t)u);
        u = dif<0 ? 1 : 0;

        d[i] = (udig_t)(dif & MP_MASK_DIG);
    }

    //If most signficat digit = 0
    if (d[nu-1]==0) nu--;

    return ret;
}

int vlong::Mul(const vlong &a, sdig_t b)
{
    int ret = VLONG_SUCCESS;

    udig_t b1 = b>0 ? (udig_t) b : (udig_t)(-b);

    CHECK( prvMulDig(a, b1) );

    if ((a.s == MP_ZPOS && b<0) || (a.s == MP_NEG && b>0))
        s = MP_NEG;
    else
        s = MP_ZPOS;
    
    return ret;
}

// multiply by a digit
int vlong::prvMulDig(const vlong &a, udig_t b)
{
    //vlong ttt = a;
    udig_t u;
    uwrd_t w;
    size_t i;
    int ret = VLONG_SUCCESS;
    
    if (nu < a.nu+1) CHECK( Grow(a.nu+1) );
    nu = a.nu;

    // zero carry
    u = 0;
    for (i = 0; i <a.nu; i++)
    {
        // Compute the sum at one digit, T[i] = A[i] + B[i] + U
        w = ((uwrd_t) a.d[i]) * ((uwrd_t) b) + (uwrd_t)u ;
        d[i] = (udig_t)(w & MP_MASK_DIG);

        // U = carry bit of T[i]
        u = (udig_t) (w >> BiD);
    }

    // add carry
    if (u>0)
    {
        d[i] = u;
        nu++;
    }

    //printf("%s * %x = %s\n", ttt.ToString(16), b, ToString(16));
    return ret;
}

// modulus of a number that is a power of 2
int vlong::prvModPow2(const vlong &a, size_t bits)
{
    int ret = VLONG_SUCCESS;
    size_t i;

    if (bits == 0) {SetZero(); return ret;}

    if (&a != this) CHECK(SetValue(a));

    // if the modulus is larger than the value than return
    if (bits >= (size_t) (a.nu*BiD)) return ret;
    
    // zero digits above the last digit of the modulus
    for (i=((bits+BiD-1)/BiD); i<nu; i++)
        d[i] = 0;
  
    // clear the digit that is not completely outside/inside the modulus
    d[bits/BiD] &= (udig_t) ((((udig_t) 1) << (((udig_t) bits) % BiD)) - ((udig_t) 1));
    
    Clamp();
    return ret;
}

// divide by a power of two, place reminder in r
int vlong::prvDivPow2(const vlong &a, size_t bits, vlong *r)
{
    int ret = VLONG_SUCCESS;
    vlong tmp1;
    if (&a==this)
    {
        CHECK( tmp1.ShiftRight(a, bits) );
        if (r!=NULL) CHECK( r->prvModPow2(a, bits) );
        Swap(tmp1);
    }
    else
    {
        CHECK( ShiftRight(a, bits) );
        if (r!=NULL) CHECK( r->prvModPow2(a, bits) );
    }       
    return ret;
}

int vlong::prvIsPow2(udig_t b, size_t *nbits)
{
    if (b==0 || (b & (b-1))) return 0;
    if (nbits == NULL) return 0;

    b >>= 1;
    *nbits=0;
    while (b!=0)
    {
        b >>= 1;
        *nbits = *nbits + 1;
    }   
    return 1;
}

/* single digit division */
// based on LibTomMath
int vlong::prvDivInt(const vlong &a, udig_t b, vlong *q/*=NULL*/, udig_t *r/*=NULL*/)
{
    udig_t t;
    uwrd_t w;
    size_t ix;
    int i;
    int ret = VLONG_SUCCESS;

    if (b == 0) return VLONG_ERR_DIV_BY_ZERO;
    if (a.nu == 0)
    {
        if (q!=NULL) q->SetZero();
        if (r!=NULL) *r = b;
        return ret;
    }

    if (b == 1)
    {
        if (r != NULL) *r = 0;
        if (q != NULL && q!=&a)
        {
            CHECK( q->SetValue(a) );
            return ret;
        }
            
        return ret;
    }

    // power of two?
    if (prvIsPow2(b, &ix) != 0)
    {
        if (r != NULL)
            *r = a.d[0] & ((((udig_t)1)<<ix) - 1);
        if (q != NULL)
            CHECK ( q->prvDivPow2(a, ix, NULL) );
        return ret;
    }

    if (q != NULL) CHECK( q->Grow(a.nu) );

    if (q!=NULL) q->nu = a.nu;
    w = 0;
    for (i=a.nu-1; i>= 0; i--)
    {
        w = (w << ((uwrd_t)BiD)) | ((uwrd_t)a.d[i]);

        if (w >= b)
        {
            t = (udig_t)(w / b);
            w -= ((uwrd_t)t) * ((uwrd_t)b);
        }
        else
            t = 0;
        if (q != NULL) q->d[i] = (udig_t) t;
    }

    if (r != NULL)
        *r = (sdig_t) w;
    return ret;
}

/* single digit division */
int vlong::Div(const vlong &a, sdig_t b, sdig_t *r/*=NULL*/)
{
    vlong *x;
    vlong tmp1;
    udig_t b2,r2;
    char signq = MP_ZPOS;
    int ret = VLONG_SUCCESS;

    if (b < 0 && a.s==MP_ZPOS) signq = MP_NEG;
    if (b > 0 && a.s==MP_NEG)  signq = MP_NEG;

    b2 = b>0 ? (udig_t) b : (udig_t) -b;
    if (b2 == 1)
    {
        if (r != NULL) *r = 0;
        if (&a != this) CHECK( SetValue(a) );
        s = signq;
        return ret;
    }

    if (&a==this)
        x = &tmp1;
    else
        x = this;

    CHECK( prvDivInt(a,b,x,&r2) );

    if (r!=NULL)
    {
        if (a.s==MP_NEG)
            *r = -((sdig_t) r2);
        else
            *r =  ((sdig_t) r2);
    }
    if (&a==this) CHECK( prvMovePtr(tmp1) );
    s = signq;

    Clamp();
    return ret; 
}

int vlong::Mod(const vlong &a, sdig_t b)
{
    sdig_t r=0; 
    vlong tmp;

    int ret = tmp.Div(a,b,&r);
    if (ret == VLONG_SUCCESS)
        return SetValue(r);
    
    return ret;
}
    
sdig_t vlong::ModDig(const vlong &a, sdig_t b) const
{
    if (b==0) return 0;
    vlong tmp;
    sdig_t r=0;
    int ret = tmp.Div(a,b,&r);
    return r;
}

//************************** Long-Long Arithmetic **************************************
// low level addition, based on HAC pp.594, Algorithm 14.7
// based on LibTomMath
int vlong::prvAddMag(const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;
    size_t nmin = a.nu < b.nu ? a.nu : b.nu;
    size_t nmax = a.nu > b.nu ? a.nu : b.nu;
    size_t i;
    const vlong *x = &a;
    vlong *c = this;
    vlong tmp1;
    udig_t u;
    uwrd_t sum;

    if (&a==this || &b==this)
        c = &tmp1;

    if (c->na < nmax+1) CHECK( c->Grow(nmax+1) );
    if (a.nu < b.nu) x = &b;
    
    
    memset(c->d, 0, sizeof(udig_t)*nu);
    c->nu = nmax;

    // zero the carry
    u = 0;
    for (i = 0; i < nmin; i++)
    {
        // Compute the sum at one digit, T[i] = A[i] + B[i] + U
        sum = ((uwrd_t) a.d[i]) + ((uwrd_t)b.d[i]) + (uwrd_t)u;
        c->d[i] = (udig_t)(sum & MP_MASK_DIG);
        
        // U = carry bit of T[i]
        u = (udig_t) (sum >> BiD);
    }

    // now copy higher words if any, that is in A+B 
    // if A or B has more digits add those in 
    if (nmin != nmax)
    {
        for (i=nmin; i<nmax; i++)
        {
            /* T[i] = X[i] + U */
            sum = ((uwrd_t) x->d[i]) + (uwrd_t)u;
            c->d[i] = (udig_t)(sum & MP_MASK_DIG);

            /* U = carry bit of T[i] */
            u = (udig_t) (sum >> BiD);
        }
    }

    // add carry
    if (u>0)
    {
        c->d[i] = u;
        c->nu++;
    }

    if (&a==this || &b==this) prvMovePtr(tmp1);

    //Clamp();
    return ret;
}

// low level subtraction (assumes |a| > |b|), HAC pp.595 Algorithm 14.9
// based on LibTomMath
int vlong::prvSubMag(const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;

    size_t nmin = b.nu;
    size_t nmax = a.nu;
    size_t i;
    vlong *c = this;
    vlong tmp1;
    swrd_t dif;
    udig_t u;

    if (&a==this || &b==this)
        c = &tmp1;

    if (c->na < nmax) CHECK( c->Grow(nmax) );
    memset(c->d, 0, sizeof(udig_t)*nmax);
    c->nu = nmax;

    // zero the carry
    u = 0;

    for (i = 0; i < nmin; i++)
    {
        // T[i] = A[i] - B[i] - U
        dif = ((swrd_t)a.d[i]) - ((swrd_t)b.d[i]) - ((swrd_t)u);
        u = dif<0 ? 1 : 0;
        c->d[i] = (udig_t)(dif & MP_MASK_DIG);
    }

    // now copy higher words if any, e.g. if A has more digits than B
    for (i=nmin; i<nmax; i++)
    {
        // T[i] = A[i] - U
        dif = ((swrd_t)a.d[i]) - ((swrd_t)u);
        u = dif<0 ? 1 : 0;
        c->d[i] = (udig_t)(dif & MP_MASK_DIG);
    }

    if (&a==this || &b==this) prvMovePtr(tmp1);

    Clamp();
    return ret;
}

// high level addition (handles signs)
// based on LibTomMath
int vlong::Add(const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;

    // handle two cases, not four
    if (a.s == b.s)
    {
        // both positive or both negative
        // add their magnitudes, copy the sign
        s = a.s;
        
        ret = prvAddMag (a, b);
    }
    else
    {
        // one positive, the other negative
        // subtract the one with the greater magnitude from
        // the one of the lesser magnitude.  The result gets
        // the sign of the one with the greater magnitude.
        if (CompareMag(a,b) == MP_LT)
        {
            s = b.s;
            ret = prvSubMag (b, a);
        }
        else
        {
            s = a.s;
            ret = prvSubMag (a, b);
        }
    }

    return ret;
}

// high level substratcion (handles signs)
// based on LibTomMath
int vlong::Sub(const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;

    if (a.s != b.s)
    {
        // subtract a negative from a positive, OR
        // subtract a positive from a negative.
        // In either case, ADD their magnitudes,
        // and use the sign of the first number.
        s = a.s;
        ret = prvAddMag (a, b);
    }
    else
    {
        // subtract a positive from a positive, OR
        // subtract a negative from a negative.
        // First, take the difference between their
        // magnitudes, then...
        if (CompareMag(a,b) == MP_GT)
        {
            // Copy the sign from the first
            s = a.s;
            // The first has a larger or equal magnitude
            ret = prvSubMag (a, b);
        }
        else
        {
            // The result has the *opposite* sign from
            // the first number.
            s = (a.s == MP_ZPOS) ? MP_NEG : MP_ZPOS;
            // The second has a larger magnitude
            ret = prvSubMag (b, a);
        }
    }

    return ret;
}

// c = |a| * |b| using Karatsuba Multiplication using 
// three half size multiplications
//
// Let B represent the radix [e.g. 2**DIGIT_BIT] and 
// let n represent half of the number of digits in 
// the min(a,b)
//
// a = a1 * B**n + a0
// b = b1 * B**n + b0
//
// Then, a * b => 
// a1b1 * B**2n + ((a1 + a0)(b1 + b0) - (a0b0 + a1b1)) * B + a0b0
//
// Note that a1b1 and a0b0 are used twice and only need to be 
// computed once.  So in total three half size (half # of 
// digit) multiplications are performed, a0b0, a1b1 and 
// (a1+b1)(a0+b0)
//
// Note that a multiplication of half the digits requires
// 1/4th the number of single precision multiplications so in 
// total after one call 25% of the single precision multiplications 
// are saved.  Note also that the call to mp_mul can end up back 
// in this function if the a0, a1, b0, or b1 are above the threshold.  
// This is known as divide-and-conquer and leads to the famous 
// O(N**lg(3)) or O(N**1.584) work which is asymptopically lower than 
// the standard O(N**2) that the baseline/comba methods use.  
// Generally though the overhead of this method doesn't pay off 
// until a certain size (N ~ 80) is reached.
// based on LibTomMath
int vlong::prvMulKaratsuba(const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;

    vlong x0, x1, y0, y1, t1, x0y0, x1y1;
    int B;

    vlong tmp1;
    vlong *c;
    if (&a==this || &b == this)
        c = &tmp1;
    else
        c = this;

    // min # of digits
    B = a.nu<b.nu ? a.nu : b.nu;

    // now divide in two
    B = B >> 1;

    // init copy all the temps */
    CHECK( x0.Grow(B*2) ); //x0 also is t2, so allocete B*2
    CHECK( x1.Grow(a.nu-B) );
    CHECK( y0.Grow(B) );
    CHECK( y1.Grow(b.nu-B) );

    CHECK( t1.Grow(B*2) );
    CHECK( x0y0.Grow(B*2) );
    CHECK( x1y1.Grow(B*2) );

    // now shift the digits
    x0.nu = y0.nu = B;
    x1.nu = a.nu - B;
    y1.nu = b.nu - B;

    // we copy the digits directly instead of using higher level functions
    // since we also need to shift the digits
    memcpy(x0.d, a.d, B*sizeof(udig_t));
    memcpy(y0.d, b.d, B*sizeof(udig_t));

    memcpy(x1.d, a.d+B, (a.nu-B)*sizeof(udig_t));
    memcpy(y1.d, b.d+B, (b.nu-B)*sizeof(udig_t));
    
    // only need to clamp the lower words since by definition the 
    // upper words x1/y1 must have a known number of digits
    CHECK( x0.Clamp() );
    CHECK( y0.Clamp() );

    // now calc the products x0y0 and x1y1
    // after this x0 is no longer required, free temp [x0==t2]!
    CHECK( x0y0.Mul(x0, y0) );
    CHECK( x1y1.Mul(x1, y1) );

    // now calc x1+x0 and y1+y0
    CHECK( t1.Add( x1, x0 ));
    CHECK( x0.Add( y1, y0 ));
    CHECK( t1.Mul( x0, t1 ));

    // add x0y0
    CHECK( x0.Add( x0y0, x1y1 ));            // t2 = x0y0 + x1y1
    CHECK( t1.Sub( t1,   x0   ));            // t1 = (x1+x0)*(y1+y0) - (x1y1 + x0y0)

    // shift by B
    CHECK( t1.prvLeftShiftDigits  (B    ));  // t1 = (x0y0 + x1y1 - (x1-x0)*(y1-y0))<<B
    CHECK( x1y1.prvLeftShiftDigits(B * 2));  // x1y1 = x1y1 << 2*B

    CHECK( t1.Add( x0y0, t1    ));           // t1 = x0y0 + t1
    CHECK( c->Add( t1,   x1y1  ));           // t1 = x0y0 + t1 + x1y1

    if (&a==this || &b == this) prvMovePtr(tmp1);

    return ret;

}

// multiplies |a| * |b| and only computes upto digs digits of result
// HAC pp. 595, Algorithm 14.12  Modified so you can control how 
// many digits of output are created.
// based on LibTomMath
int vlong::prvMulBaseline(const vlong &a, const vlong &b, size_t ndigs)
{
    int ret = VLONG_SUCCESS;
    size_t i,j;
    uwrd_t r;
    udig_t u,t1;

    size_t digs = a.nu+b.nu < ndigs ? a.nu+b.nu : ndigs;
    if (nu < digs) CHECK( Grow(digs) );
    nu = digs;
    memset(d,0,nu*sizeof(udig_t));

    // limit ourselves to making digs digits of output
    size_t nmin = ndigs<b.nu ? ndigs : b.nu; 
        
    // compute the digits of the product directly
    for (i = 0; i < a.nu; i++)
    {
        // set the carry to zero
        u = 0;
        
        // copy of the digit from a used within the nested loop
        t1 = a.d[i];
    
        // compute the columns of the output and propagate the carry
        for (j = 0; j<nmin; j++)
        {
            // compute the column as a mp_word
            r = ((uwrd_t)d[i+j]) +
                ((uwrd_t)t1) * ((uwrd_t)b.d[j]) +
                ((uwrd_t) u);

            // the new column is the lower part of the result
            d[i+j] = (udig_t) (r & ((uwrd_t) MP_MASK_DIG));

            // get the carry word from the result
            u    = (udig_t) (r >> BiD);
        }
        // set carry if it is placed below digs//
        if (i + j < digs)
            d[i+j] = u;
    }

    Clamp();

    return ret;
}

// high level multiplication
int vlong::Mul(const vlong &a, const vlong &b, size_t maxdigs /*=0*/)
{
    char sign = a.s == b.s ? MP_ZPOS : MP_NEG;
    int ret = VLONG_SUCCESS;
    
    if (a.nu==0 || b.nu==0) {SetZero(); return ret;}
    int nmin = a.nu < b.nu ? a.nu : b.nu;
    int nmax = a.nu > b.nu ? a.nu : b.nu;

    vlong tmp1;
    vlong *x;

    if (&a==this || &b == this)
        x = &tmp1;
    else
        x = this;

    size_t digs = a.nu + b.nu;
    if (x->nu < digs) CHECK( x->Grow(digs) );
    if (maxdigs>0 && maxdigs<digs) digs = maxdigs;
        
    // use Karatsuba?
    if (nmin >= VLONG_KARATSUBA_MUL_CUTOFF)
        ret = x->prvMulKaratsuba(a, b);
    else
        ret = x->prvMulBaseline(a, b, digs);

    if (x->nu>digs)
    {
        memset(&x->d[digs],0,x->nu-digs*sizeof(udig_t));
        x->nu = digs;
    }

    if (&a==this || &b == this) prvMovePtr(tmp1);

    s = sign;

    return ret;
}

//X = a*b mod n
int vlong::MulMod(const vlong &a, const vlong &b, const vlong &n)
{
    int ret = VLONG_SUCCESS;
    CHECK( Mul(a, b) );
    CHECK( Mod(*this, n) );
    return ret;
}

int vlong::Sqr(const vlong &a)
{
    return Mul(a, a);
}

// integer signed division. 
// c*b + d == a [e.g. a/b, c=quotient, d=remainder]
// HAC pp.598 Algorithm 14.20
// based on mp_div() of LibTomMath
//
// Note that the description in HAC is horribly 
// incomplete.  For example, it doesn't consider 
// the case where digits are removed from 'x' in 
// the inner loop.  It also doesn't consider the 
// case that y has fewer than three digits, etc..
//
// The overall algorithm is as described as 
// 14.20 from HAC but fixed to treat these cases.
// q <- a/b, r <- a%b
// based on LibTomMath
int vlong::prvDivBig(const vlong &a, const vlong &b, vlong *q2/*=NULL*/,  vlong *r/*=NULL*/)
{
    int ret = VLONG_SUCCESS;

    vlong q,x,y,t1,t2;
    int i,t,n;
    size_t norm;
    char sign = a.s==b.s ? MP_ZPOS : MP_NEG;

    if (b.nu==0) return VLONG_ERR_DIV_BY_ZERO;

    int cmp = CompareMag(a,b);
    // if a < b then q=0, r = a
    if (cmp == MP_LT)
    {
        if (r!=NULL) CHECK( r->Copy(a) );
        if (q2!=NULL) q2->SetZero();
        return ret;
    }
    if (cmp == MP_EQ)
    {
        if (r!=NULL) r->SetZero();
        if (q2!=NULL) 
        {
            q2->SetValue(a);
            q2->s = sign;
        }
        return ret;
    }

    CHECK( q.Grow(a.nu+2) );
    q.nu = a.nu+2;

    CHECK( t1.Grow(a.nu+2) );
    CHECK( t2.Grow(a.nu+2) );
    CHECK( x.SetValue(a) );
    CHECK( y.SetValue(b) );

    // fix the sign
    x.s = y.s = MP_ZPOS;

    // normalize both x and y, ensure that y >= b/2, [b == 2**BiD]
    norm = y.GetNumBits() % BiD;
    if (norm < BiD-1)
    {
        norm = (BiD-1) - norm;
        CHECK( x.ShiftLeft(x, norm) );
        CHECK( y.ShiftLeft(y, norm) );
    }
    else 
        norm = 0;

    // note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4
    n = x.nu - 1;
    t = y.nu - 1;

    // while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } 
    CHECK( y.prvLeftShiftDigits(n-t) );
    while (CompareMag(x,y) != MP_LT)
    {
        ++(q.d[n - t]);
        CHECK( x.prvSubMag(x,y) );
    }

    // reset y by shifting it back down
    y.prvRightShiftDigits(n - t);

    // step 3. for i from n down to (t + 1)
    for (i=n; i>=(int)(t+1); i--)
    {
        if (i > (int) x.nu)
            continue;

        // step 3.1 if xi == yt then set q{i-t-1} to b-1, 
        // otherwise set q{i-t-1} to (xi*b + x{i-1})/yt
        if (x.d[i] == y.d[t])
            q.d[i - t - 1] = MP_MASK_DIG;
        else
        {
            uwrd_t tmpx;

            tmpx  = ((uwrd_t) x.d[i]) << BiD;
            tmpx |= (uwrd_t) x.d[i - 1];
            tmpx /= (uwrd_t) y.d[t];
            if (tmpx > (uwrd_t) MP_MASK_DIG)
                tmpx = MP_MASK_DIG;
            q.d[i - t - 1] = (udig_t) (tmpx & MP_MASK_DIG);
        }

        // while (q{i-t-1} * (yt * b + y{t-1})) > 
        //       xi * b**2 + xi-1 * b + xi-2      
        // do q{i-t-1} -= 1; 
        q.d[i - t - 1]++;
        do
        {
            q.d[i - t - 1]--;

            // find left hand
            t1.SetZero();
            t1.d[0] = (t < 1) ? 0 : y.d[t - 1];
            t1.d[1] = y.d[t];
            t1.nu = 2;
            CHECK( t1.prvMulDig(t1, q.d[i - t - 1]) );

            // find right hand
            t2.d[0] = (i < 2) ? 0 : x.d[i - 2];
            t2.d[1] = (i < 1) ? 0 : x.d[i - 1];
            t2.d[2] = x.d[i];
            t2.nu = 3;
        } while (CompareMag(t1, t2) == MP_GT);

        // step 3.3 x = x - q{i-t-1} * y * b**{i-t-1}
        CHECK( t1.prvMulDig(y, q.d[i - t - 1]) );
        CHECK( t1.prvLeftShiftDigits(i - t - 1) );
        CHECK( x.Sub(x, t1) );

        // if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; }
        if (x.s == MP_NEG)
        {
            CHECK( t1.SetValue(y) );
            CHECK( t1.prvLeftShiftDigits(i - t - 1) );
            CHECK( x.Add(x, t1) );
            q.d[i - t - 1] = (q.d[i - t - 1] - 1) & MP_MASK_DIG;
        }
    }

    // now q is the quotient and x is the remainder 
    // [which we have to normalize]
    if (q2!=NULL)
    {
        q.Clamp();
        q2->Swap(q);
        q2->s = sign;
    }   
    
    if (r != NULL)
    {
        CHECK( x.ShiftRight(x, norm) );
        r->swap(x);
        r->s = a.s;
    }
    return ret;
}


//X <- a / b
int vlong::Div(const vlong &a, const vlong &b, vlong *r)
{
    return prvDivBig(a, b, this, r);
}

//X <- a % b
int vlong::Mod(const vlong &a, const vlong &b)
{
    if (b.nu==0) {SetZero(); return VLONG_SUCCESS; }
    int ret = prvDivBig(a,b,NULL,this);
    return ret;
}

//X <- a % b (Must hold: 0<a<b*b)
int vlong::ModBarrett(const vlong &a, const vlong &b)
{
    vlong mu;
    int ret = VLONG_SUCCESS;

    CHECK( prvReduceBarrettSetup(b, &mu) );
    if (&a!=this) CHECK( SetValue(a) );
    CHECK( prvReduceBarrett(this, b, mu) );
    return ret;
}

//X <- a % b (Must hold: 0<a<b*b and b is odd)
int vlong::ModMontgomery(const vlong &a, const vlong &b)
{
    udig_t rho;
    int ret = VLONG_SUCCESS;

    CHECK( prvReduceMontgomerySetup(b, &rho) );
    if (&a!=this) CHECK( SetValue(a) );
    CHECK( prvReduceMontgomery(this, b, rho) );
    return ret;
}

//X <- a % b (Must hold: 0<a<b*b, half or more digits of b must me 1 bits)
int vlong::ModDRExt(const vlong &a, const vlong &b)
{
    vlong mu;
    int ret = VLONG_SUCCESS;

    CHECK( prvReduceDRSetup(b, &mu) );
    if (&a!=this) CHECK( SetValue(a) );
    CHECK( prvReduceDR(this, b, mu) );
    return ret;
}

//X <- a ^ e
int vlong::Pow(sdig_t a, sdig_t e)
{
    int ret = VLONG_SUCCESS;
    if (e==0)
    {
        CHECK( SetValue(1) );
        return ret;
    }
    if (e==1)
    {
        CHECK( SetValue(a) );
        return ret;
    }

    vlong sq;
    CHECK( sq.SetValue(a) );
    CHECK(    SetValue(1) );

    while (e>0)
    {
        if ((e & 1)>0) CHECK( Mul(*this, sq) );
        e = e >> 1;
        if (e>0) CHECK( sq.Mul(sq,sq) );
    }

    if (a<0)
    {
        if ((e % 2) == 0)
            s = MP_ZPOS;
        else
            s = MP_NEG;
    }

    return ret;
}

int vlong::Pow(const vlong &a, size_t e)
{
    int ret = VLONG_SUCCESS;
    char sign = MP_ZPOS;
    if (e==0)
    {
        CHECK( SetValue(1) );
        return ret;
    }
    if (e==1)
    {
        CHECK( SetValue(a) );
        return ret;
    }

    if (a.s == MP_NEG)
    {
        if ((e % 2) == 0)
            sign = MP_ZPOS;
        else
            sign = MP_NEG;
    }

    vlong tmp1;
    vlong *c;
    if (&a==this)
        c = &tmp1;
    else
        c = this;

    vlong sq;
    CHECK( sq.SetValue(a) );
    CHECK( c->SetValue(1) );

    while (e>0)
    {
        if ((e & 1)>0) CHECK( c->Mul(*c, sq) );
        e = e >> 1;
        if (e>0) CHECK( sq.Mul(sq,sq) );
    }

    if (&a==this) prvMovePtr(tmp1);
    s = sign;

    return ret;
}

// find the n'th root of an integer
//
// Result found such that (c)**n <= a and (c+1)**n > a 
//
// This algorithm uses Newton's approximation 
// x[i+1] = x[i] - f(x[i])/f'(x[i]) 
// which will find the root in log(N) time where 
// each step involves a fair bit.  This is not meant to 
// find huge roots [square and cube, etc].
//
// based on mp_n_root() of LibTomMath
int vlong::Root(const vlong &a, udig_t n)
{
    vlong t1, t2, t3, t4, t5;
    int ret = VLONG_SUCCESS;

    if (n == 0)
        return VLONG_ERR_DIV_BY_ZERO;

    // input must be positive if b is even
    if ((n & 1) == 0 && a.s == MP_NEG)
        return VLONG_ERR_NEGATIVE_ARG;

    // if a is negative fudge the sign but keep track
    CHECK( t5.SetValue(a) );
    t5.s = 1;

    // t2 = 2
    CHECK( t2.SetValue(2) );

    do
    {
        // t1 = t2
        CHECK( t1.SetValue(t2) );

        // t2 = t1 - ((t1**n - a) / (n * t1**(n-1)))

        // t3 = t1**(n-1)
        CHECK( t3.Pow(t2, n-1) );

        // numerator
        // t2 = t1**n
        CHECK( t2.Mul(t1, t3) );
        
        // t2 = t1**n - a
        CHECK( t2.Sub(t2, t5) );

        // denominator
        // t3 = t1**(n-1) * n
        CHECK( t3.Mul(t3, n) );
        
        // t3 = (t1**n - a)/(n * t1**(n-1))
        CHECK( t3.Div(t2, t3, &t4) );

        CHECK( t2.Sub(t1, t3) );

    } while (t1.Compare(t2) != MP_EQ);

    // result can be off by a few so check
    for (;;) 
    {
        CHECK( t2.Pow(t1, n) );


        if (t2.Compare(t5) == MP_GT) 
        {
            CHECK( t1.Sub(t1, 1) );
        }
        else 
            break;
    }

    // set the result
    swap(t1);

    // set the sign of the result
    s = a.s;

    return ret;
}

//Computes X such as a*X=1 (mod n). Must hold: gcd(a,n)=1 
//HAC 14.61,14.64
int vlong::InvMod(const vlong &a, const vlong &n)
{
    int ret = VLONG_SUCCESS;

    if (a.s == MP_NEG || n.s == MP_NEG) return VLONG_ERR_NEGATIVE_ARG;

    vlong gcd, Y1;

    CHECK( gcd.GCDExtBin (a, n, &Y1, NULL) );

    if (gcd.nu == 1 && gcd.d[0]==1)
    {
        swap(Y1);
    }
    else
        return VLONG_ERR_NO_INVERSE;

    return ret;
}

// computes a = 2**b 
//
// Simple algorithm which zeroes the int, grows it then just sets one bit
// as required.
int vlong::prv2Expt(udig_t b)
{
    int ret = VLONG_SUCCESS;

    // zero a as per default
    SetZero();
    
    //grow a to accomodate the single bit
    CHECK( Grow((b/BiD)+1) );

    // set the used count of where the bit will go
    nu = (b/BiD)+1;

    // put the single bit in its place */
    d[b/BiD] = ((udig_t)1) << (b%BiD);

    return ret;
}

// pre-calculate the value required for Barrett reduction
// For a given modulus "b" it calulates the value required in "a"
int vlong::prvReduceBarrettSetup(const vlong &n, vlong *a)
{
    int ret = VLONG_SUCCESS;

    CHECK( a->prv2Expt(n.nu*2*BiD) );

    return prvDivBig(*a, n, a, NULL);
}

// calc a value a mod 2**b (TESTED)
int vlong::prvMod2d(const vlong &a, int b)
{
    int i, ret = VLONG_SUCCESS;

    // if b is <= 0 then zero the int
    if (b <= 0)
    {
        SetZero();
        return ret;
    }

    // if the modulus is larger than the value than return
    if (b >= (int) (a.nu*BiD)) return Copy(a);

    // copy
    if (&a!=this) CHECK( Copy(a) );

    // zero digits above the last digit of the modulus
    for (i=((b+BiD-1)/BiD); i<(int)nu; i++)
        d[i] = 0;

    // clear the digit that is not completely outside/inside the modulus
    d[b/BiD] &= (udig_t) ((((udig_t) 1) << (b % BiD)) - ((udig_t) 1));
    CHECK( Clamp() );

    return ret;
}

// reduces x mod m, assumes 0 < x < m**2, mu is 
// precomputed via mp_reduce_setup.
// From HAC pp.604 Algorithm 14.42
int vlong::prvReduceBarrett(vlong *x, const vlong &n, const vlong &mu)
{
    vlong q;
    size_t um = n.nu;
    int ret = VLONG_SUCCESS;

    assert(x->nu < (n.nu*2+1));

    // q = x
    CHECK( q.SetValue(*x) );    

    // q1 = x / b**(k-1)
    q.prvRightShiftDigits(um - 1);         

    // q2 = q1 * mu
    CHECK ( q.Mul(q,mu) );

    // q3 = q2 / b**(k+1)
    q.prvRightShiftDigits(um + 1);

    // x = x mod b**(k+1), quick (no division)
    CHECK( x->prvMod2d(*x, BiD*(um+1)) ); //mp_mod_2d

    // q = q * m mod b**(k+1), quick (no division)
    //CHECK( q.prvMulLowDigits(q, n,um+1) ); //s_mp_mul_digs
    CHECK( q.Mul(q, n, um+1) );

    // x = x - q
    CHECK( x->Sub(*x, q) );

    if (x->s==MP_NEG && x->nu>0)
    {
        CHECK( q.SetValue(1) );
        CHECK( q.prvLeftShiftDigits(um+1) );
        CHECK( x->Add(*x, q) );
    }

    while (x->Compare(n) == MP_GT)
    {
        CHECK( x->Sub(*x, n) );
    }

    return ret;
}

// fast inversion mod 2**k
//
// Based on the fact that
//
// XA = 1 (mod 2**n)  =>  (X(2-XA)) A = 1 (mod 2**2n)
//                    =>  2*X*A - X*X*A*A = 1
//                    =>  2*(1) - (1)     = 1
// based on mp_montgomery_setup of LibTomMath
int vlong::prvReduceMontgomerySetup(const vlong &n, udig_t *rho)
{
    int ret = VLONG_SUCCESS;
    udig_t x, b;

    b = n.d[0];

    if ((b & 1) == 0) return VLONG_ERR_BAD_ARG_1;

    x = (((b + 2) & 4) << 1) + b; // here x*a==1 mod 2**4
    x *= 2 - b * x;               // here x*a==1 mod 2**8

    if (BiD >= 16) x *= 2 - b * x; // here x*a==1 mod 2**16
    if (BiD >= 32) x *= 2 - b * x; // here x*a==1 mod 2**32
    if (BiD >= 64) x *= 2 - b * x; // here x*a==1 mod 2**64

    // rho = -1/m mod b
    *rho = ~x + 1;

    return ret;
}

// based on mp_montgomery_calc_normalization of LibTomMath
int vlong::prvMontgomeryNorm(vlong *a, const vlong &b)
{
    int i, bits;
    int ret = VLONG_SUCCESS;

    // how many bits of last digit does b use
    bits = b.GetNumBits() % BiD;

    if (b.nu>1)
    {
        CHECK( a->prv2Expt((b.nu-1)*BiD + bits-1) );
    }
    else
    {
        CHECK( a->SetValue(1) );
        bits=1;
    }

    // now compute C = A * B mod b
    for (i=bits-1; i<(int)BiD; i++)
    {
        CHECK( a->prvMulDig(*a,2) );
        if (CompareMag(*a,b) == MP_GT)
        {
            CHECK( a->Sub(*a,b) );
        }
    }
    return ret;
}

// based on mp_montgomery_reduce of LibTomMath
int vlong::prvReduceMontgomery(vlong *x, const vlong &n, udig_t rho)
{
    int i, j, digs;
    int ret = VLONG_SUCCESS;
    udig_t mu, u;
    uwrd_t r;

    digs = n.nu*2+1;
    // grow the input as required
    
    CHECK( x->Grow(digs) );

    x->nu = digs;

    for (i=0; i<(int)n.nu; i++)
    {
        // mu = ai * rho mod b
        //
        // The value of rho must be precalculated via
        // montgomery_setup() such that
        // it equals -1/n0 mod b this allows the
        // following inner loop to reduce the
        // input one digit at a time
        mu = (udig_t) (((uwrd_t)x->d[i]) * ((uwrd_t)rho) & MP_MASK_DIG);
        
        // a = a + mu * m * b**i

        // set the carry to zero
        u = 0;

        /// Multiply and add in place
        for (j=0; j<(int)n.nu; j++)
        {
            // compute product and sum
            r       = ((uwrd_t)mu) * ((uwrd_t) n.d[j]) +
                      ((uwrd_t) u) + ((uwrd_t) x->d[i+j]);

            // get carry
            u       = (udig_t) (r >> BiD);

            // fix digit
            x->d[i+j] = (udig_t) (r & ((uwrd_t) MP_MASK_DIG));
        }
        // At this point the j'th digit of x should be zero

        // propagate carries upwards as required
        while (u)
        {
            r = ((uwrd_t) x->d[i+j]) + ((uwrd_t) u);
            u = (udig_t) (r >> BiD);
            x->d[i+j] = (udig_t) (r & MP_MASK_DIG);
            j++;
        }
    }

    // at this point the n.used'th least
    // significant digits of x are all zero
    // which means we can shift x to the
    // right by n.used digits and the
    // residue is unchanged.
    
    // x = x/b**n.used
    x->Clamp();
    x->prvRightShiftDigits(n.nu);

    // if x >= n then x = x - n
    if (CompareMag (*x, n) == MP_GT) return x->prvSubMag(*x, n);

    return ret;
}

// determines if reduce_2k_l (prvReduceDR) can be used
bool vlong::prvIsDrModulus() const
{
    size_t i,j;

    if (nu == 0)
        return false;
    else if (nu == 1)
        return true;
    else
    {
        for (j = i = 0; i < nu; i++)
        {
            if (d[i] == MP_MASK_DIG) ++j;
        }
        return (j>=(nu/2)) ? true : false;
    }

    return false;
}

int vlong::prvReduceDRSetup(const vlong &n, vlong *mu)
{
    int ret = VLONG_SUCCESS;

    vlong tmp1;

    CHECK( tmp1.prv2Expt(n.GetNumBits()) );
    CHECK( mu->Sub(tmp1,n) );

    return ret;
}

// reduces a modulo n where n is of the form 2**p - d 
// This differs from reduce_2k since "d" can be larger
// than a single digit.
// based on mp_reduce_2k_l of LibTomMath
int vlong::prvReduceDR(vlong *x, const vlong &n, const vlong &mu)
{
    vlong q,ttt;
    size_t p = n.GetNumBits();
    int ret = VLONG_SUCCESS;
    bool bExit = false;

    while (!bExit)
    {
        // q = x/2**p, x = x mod 2**p
        CHECK( q.prvDivPow2(*x, p, x) );
    
        // q = q * mu
        CHECK( q.Mul(q, mu) );

        // x = x + q
        CHECK( x->prvAddMag(*x, q) );

        if (CompareMag(*x,n) == MP_GT)
        {
            CHECK( x->Sub(*x, n) );
            continue;
        }
        bExit = true;
    }

    return ret;
}



#ifdef MP_LOW_MEM
   #define TAB_SIZE 32
#else
   #define TAB_SIZE 256
#endif

//X = a^e mod n
// based on s_mp_exptmod of LibTomMath
int vlong::prvPowModBarrett(const vlong &a, const vlong &e, const vlong &n, int redmode)
{   
    vlong M[TAB_SIZE], res, mu;
    udig_t buf;
    int bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
    int ret = VLONG_SUCCESS;
    
    // use a pointer to the reduction algorithm.  This allows us to use
    // one of many reduction algorithms without modding the guts of
    // the code with if statements everywhere.
    int (*redux)(vlong *,const vlong &,const vlong &);

    // find window size
    x = e.GetNumBits();
    if (x <= 7) winsize = 2;
    else if (x <= 36) winsize = 3;
    else if (x <= 140) winsize = 4;
    else if (x <= 450) winsize = 5;
    else if (x <= 1303) winsize = 6;
    else if (x <= 3529) winsize = 7;
    else winsize = 8;

#ifdef MP_LOW_MEM
    if (winsize > 5) winsize = 5;
#endif

    // determine and setup reduction code
    if (redmode == 0)
    {
        // now setup Barrett
        CHECK( prvReduceBarrettSetup(n, &mu) ) ;
        redux = prvReduceBarrett;
    }
    else if (redmode == 1)
    {
        // setup extended DR reduction for moduli of the form B**k - b
        CHECK( prvReduceDRSetup(n, &mu) );
        redux = prvReduceDR;
    }
    else
    {
        return VLONG_ERR_BAD_ARG_4;
    }   

    // create M table
    //
    // The M table contains powers of the base, 
    // e.g. M[x] = G**x mod P
    //
    // The first half of the table is not 
    // computed though accept for M[0] and M[1]
    //
    CHECK( M[1].Mod(a, n) );

    //compute the value at M[1<<(winsize-1)] by squaring 
    // M[1] (winsize-1) times 
    CHECK(  M[1 << (winsize - 1)].Copy(M[1]) );
    
    for (x=0; x<(winsize-1); x++)
    {
        // square it
        CHECK( M[1 << (winsize - 1)].Mul(M[1 << (winsize - 1)], M[1 << (winsize - 1)]) );

        // reduce modulo P
        CHECK( redux(&M[1 << (winsize - 1)], n, mu) );
    }

    // create upper table, that is M[x] = M[x-1] * M[1] (mod P)
    // for x = (2**(winsize - 1) + 1) to (2**winsize - 1)
    for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++)
    {
        CHECK( M[x].Mul(M[x - 1], M[1]) );
        CHECK( redux(&M[x], n, mu) );
    }

    CHECK( res.SetValue(1) );

    // set initial mode and bit cnt
    mode   = 0;
    bitcnt = 1;
    buf    = 0;
    digidx = e.nu - 1;
    bitcpy = 0;
    bitbuf = 0;

    for (;;)
    {
        // grab next digit as required
        if (--bitcnt == 0)
        {
            // if digidx == -1 we are out of digits */
            if (digidx == -1)
                break;

            // read next digit and reset the bitcnt
            buf    = e.d[digidx--];
            bitcnt = (int) BiD;
        }

        // grab the next msb from the exponent
        y     = (buf >> (udig_t)(BiD - 1)) & 1;
        buf <<= (udig_t)1;

        // if the bit is zero and mode == 0 then we ignore it
        // These represent the leading zero bits before the first 1 bit
        // in the exponent.  Technically this opt is not required but it
        // does lower the # of trivial squaring/reductions used
        if (mode == 0 && y == 0)
            continue;

        // if the bit is zero and mode == 1 then we square
        if (mode == 1 && y == 0)
        {
            CHECK( res.Mul(res,res) );
            CHECK( redux(&res,n,mu) );
            continue;
        }

        // else we add it to the window
        bitbuf |= (y << (winsize - ++bitcpy));
        mode    = 2;

        if (bitcpy == winsize)
        {
            // ok window is filled so square as required and multiply
            // square first
            for (x = 0; x < winsize; x++)
            {
                CHECK( res.Mul(res,res) );
                CHECK( redux (&res, n, mu) );
            }

            CHECK( res.Mul(M[bitbuf],res) );
            CHECK( redux (&res, n, mu) );
            // empty window and reset
            bitcpy = 0;
            bitbuf = 0;
            mode   = 1;
        }
    }

    // if bits remain then square/multiply
    if (mode == 2 && bitcpy > 0) 
    {
        // square then multiply if the bit is set
        for (x=0; x<bitcpy; x++)
        {
            CHECK( res.Mul(res,res) );
            CHECK( redux (&res, n, mu) );
        
            // get next bit of the window
            bitbuf <<= 1;
            if ((bitbuf & (1 << winsize)) != 0) 
            {
                // then multiply
                CHECK( res.Mul(M[1],res) );
                CHECK( redux (&res, n, mu) );
            }
        }
    }

    swap(res);
    return ret;
}


// computes Y == a**e mod n, HAC pp.616, Algorithm 14.85
// computes Y == G**X mod P, HAC pp.616, Algorithm 14.85
// Uses a left-to-right k-ary sliding window to compute the modular exponentiation.
// The value of k changes based on the size of the exponent.
//
// Uses Montgomery or Diminished Radix reduction [whichever appropriate]
// based on mp_exptmod_fast of LibTomMath
int vlong::prvPowModMontgomery(const vlong &a, const vlong &e, const vlong &n)
{
    int ret = VLONG_SUCCESS;
    vlong M[TAB_SIZE], res;
    udig_t buf, mp;
    int bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;

    // find window size
    x = e.GetNumBits();
    if (x <= 7) winsize = 2;
    else if (x <= 36) winsize = 3;
    else if (x <= 140) winsize = 4;
    else if (x <= 450) winsize = 5;
    else if (x <= 1303) winsize = 6;
    else if (x <= 3529) winsize = 7;
    else winsize = 8;

#ifdef MP_LOW_MEM
    if (winsize > 5) winsize = 5;
#endif

    CHECK( prvReduceMontgomerySetup(n, &mp) );
    // now we need R mod m
    CHECK( prvMontgomeryNorm(&res, n) );

    // create M table
    // The first half of the table is not computed though accept for M[0] and M[1]

    // now set M[1] to G * R mod m
    CHECK( M[1].MulMod(a, res, n) );

    // compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times
    //compute the value at M[1<<(winsize-1)] by squaring 
    // M[1] (winsize-1) times 
    CHECK(  M[1 << (winsize - 1)].Copy(M[1]) );
    
    for (x=0; x<(winsize-1); x++)
    {
        // square it
        CHECK( M[1 << (winsize - 1)].Mul(M[1 << (winsize - 1)], M[1 << (winsize - 1)]) );

        // reduce modulo P
        CHECK( prvReduceMontgomery(&M[1 << (winsize - 1)], n, mp) );
    }

    // create upper table, that is M[x] = M[x-1] * M[1] (mod P)
    // for x = (2**(winsize - 1) + 1) to (2**winsize - 1)
    for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++)
    {
        CHECK( M[x].Mul(M[x - 1], M[1]) );
        CHECK( prvReduceMontgomery(&M[x], n, mp) );
    }

    // set initial mode and bit cnt
    mode   = 0;
    bitcnt = 1;
    buf    = 0;
    digidx = e.nu - 1;
    bitcpy = 0;
    bitbuf = 0;

    for (;;)
    {
        // grab next digit as required
        if (--bitcnt == 0)
        {
            // if digidx == -1 we are out of digits */
            if (digidx == -1)
                break;

            // read next digit and reset the bitcnt
            buf    = e.d[digidx--];
            bitcnt = (int) BiD;
        }

        // grab the next msb from the exponent
        y     = (buf >> (udig_t)(BiD - 1)) & 1;
        buf <<= (udig_t)1;

        // if the bit is zero and mode == 0 then we ignore it
        // These represent the leading zero bits before the first 1 bit
        // in the exponent.  Technically this opt is not required but it
        // does lower the # of trivial squaring/reductions used
        if (mode == 0 && y == 0)
            continue;

        // if the bit is zero and mode == 1 then we square
        if (mode == 1 && y == 0)
        {
            CHECK( res.Mul(res,res) );
            CHECK( prvReduceMontgomery(&res,n,mp) );
            continue;
        }

        // else we add it to the window
        bitbuf |= (y << (winsize - ++bitcpy));
        mode    = 2;

        if (bitcpy == winsize)
        {
            // ok window is filled so square as required and multiply
            // square first
            for (x = 0; x < winsize; x++)
            {
                CHECK( res.Mul(res,res) );
                CHECK( prvReduceMontgomery (&res, n, mp) );
            }

            CHECK( res.Mul(M[bitbuf],res) );
            CHECK( prvReduceMontgomery (&res, n, mp) );
            // empty window and reset
            bitcpy = 0;
            bitbuf = 0;
            mode   = 1;
        }
    }

    // if bits remain then square/multiply
    if (mode == 2 && bitcpy > 0) 
    {
        // square then multiply if the bit is set
        for (x=0; x<bitcpy; x++)
        {
            CHECK( res.Mul(res,res) );
            CHECK( prvReduceMontgomery (&res, n, mp) );
        
            // get next bit of the window
            bitbuf <<= 1;
            if ((bitbuf & (1 << winsize)) != 0) 
            {
                // then multiply
                CHECK( res.Mul(M[1],res) );
                CHECK( prvReduceMontgomery (&res, n, mp) );
            }
        }
    }

    // fixup result if Montgomery reduction is used
    // recall that any value in a Montgomery system is
    // actually multiplied by R mod n.  So we have
    // to reduce one more time to cancel out the factor
    // of R.
    CHECK( prvReduceMontgomery(&res, n, mp) );
    
    Swap(res);

    return ret;
}

// this is a shell function that calls either the normal or Montgomery
// exptmod functions.  Originally the call to the montgomery code was
// embedded in the normal function but that wasted alot of stack space
// for nothing (since 99% of the time the Montgomery code would be called)
// X <- a^e (mod n) (Fast exponentiation modular n)
// based on mp_exptmod of LibTomMath
int vlong::PowMod(const vlong &a, const vlong &e, const vlong &n)
{
    //int mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y)
    // !computes Y == G**X mod P, HAC pp.616, Algorithm 14.85
    int ret = VLONG_SUCCESS;

    if (n.s == MP_NEG) return VLONG_ERR_NEGATIVE_ARG;
    // modulus P must be positive

    // if exponent X is negative we have to recurse
    if (e.s == MP_NEG)
    {
        vlong tmpG, tmpX;

        // first compute 1/G mod P
        CHECK( tmpG.InvMod(a, n) );

        // now get |X|
        CHECK( tmpX.SetValue(e) );

        // and now compute (1/G)**|X| instead of G**X [X < 0]
        CHECK ( PowMod(a, e, n) );
        return ret;
    }

#ifdef VLONG_USE_DR_REDUCE
    if (n.prvIsDrModulus())
        return prvPowModBarrett(a, e, n, 1);
#endif

#ifdef VLONG_USE_MONTGOMRTY
    if ((a.d[0] & 1) == 1)
    {
        // if the modulus is odd or dr != 0 use the montgomery method
        return prvPowModMontgomery(a, e, n);
    }
    else
    {
        // otherwise use the generic Barrett reduction technique
        return prvPowModBarrett(a, e, n, 0);
    }
#else
    return prvPowModBarrett(a, e, n, 0);
#endif

    return ret;
}

int vlong::PowMod(const vlong &a, udig_t e, const vlong &n)
{
    vlong e2;

    e2.na = 1;
    e2.d = &e;
    int ret = PowMod(a, e2, n);
    e2.d = NULL;
    e2.na = 0;

    return ret;
}

//X <- a^e (mod n) (Slow exponentiation modular n, uses full division reduction)
int vlong::PowModSlow(const vlong &a, const vlong &e, const vlong &n)
{
    int ret = VLONG_SUCCESS;
    if (e.nu==0)
    {
        CHECK( SetValue(1) );
        return ret;
    }
    if (e.nu==1 && e.d[0]==1)
    {
        CHECK( SetValue(a) );
        return ret;
    }

    vlong tmp1;
    vlong e1;

    CHECK( e1.SetValue(e) );
    
    vlong *c;
    if (&a==this)
        c = &tmp1;
    else
        c = this;

    vlong sq;
    CHECK( sq.SetValue(a) );
    CHECK( c->SetValue(1) );

    while (e1.nu>0)
    {
        if ((e1.d[0] & 1)>0) 
        {
            CHECK( c->Mul(*c, sq) );
            CHECK( c->Mod(*c, n ) );
        }
        e1.ShiftRight(e1,1);
        if (e1.nu>0)
        {
            CHECK( sq.Mul(sq,sq) );
            CHECK( sq.Mod(sq, n ) );
        }
    }

    if (&a==this) prvMovePtr(tmp1);

    return ret;
}

// Power modular N using Chineese Reminder Theorem (CRT)
// (RSA private key operation)
// HAC pp. 613 Note 14.75
//
// Assume n = p*q, where p and q are prime, private exponent d
// Input:  a  <- Source number (RSA ciphertext)
//         p  <- prime p such as p*q=n
//         q  <- prime q such as p*q=n
//         dp <- d mod p (must be calculated separately)
//         dq <- d mod q (must be calculated separately)
//         qp <- q^-1 mod q (must be calculated separately)
// Output: X  <- a^d (mod n) (RSA plaintext)
int vlong::PowModCRT(const vlong &a, const vlong &p, const vlong &q, const vlong &dp, const vlong &dq, const vlong &qp)
{
    vlong tmp1, t1, t2, *x;
    int ret = VLONG_SUCCESS;

    if (&a==this || &p==this || &q==this || &qp==this || &dp==this || &dq==this)
        x = &tmp1;
    else
        x = this;

    // t1 <- a^dp mod p
    // t2 <- a^dq mod q
    CHECK( t1.PowMod(a, dp, p) );
    CHECK( t2.PowMod(a, dq, q) );

    // x <- (t1-t2)*(qp mod p) mod p
    CHECK( x->Sub(t1, t2) );
    CHECK( t1.Mul(*x, qp) );
    CHECK( x->Mod(t1, p) );

    // X <- t2 + x*q
    CHECK( t1.Mul(*x, q) );
    CHECK( x->Add(t1, t2) );

    if (x!=this) CHECK( prvMovePtr(tmp1) );

    return ret;
}

//*************************** Special algorithms ***************************************

// Counts the number of lsbs which are zero before the first zero bit
// based on LibTomMath
size_t vlong::prvLSB()
{
    size_t i;
    udig_t q, qq;
    
    if (nu==0) return 0;

    // scan lower digits until non-zero
    for (i=0; i<nu && d[i]==0; i++);
    q = d[i];
    i *= BiD;

    // now scan this digit until a 1 is found */
    if ((q & 1) == 0)
    {
        do
        {
            qq  = q & 15;
            i  += lnz[qq];
            q >>= 4;
        } while (qq == 0);
    }
    return i;
}

// X <- gcd(a, b)
// based on mp_gcd() of LibTomMath (HAC 14.54)
int vlong::GCD (const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;
    size_t u_lsb, v_lsb, k;
    vlong u, v;

    CHECK( u.SetValue(a) );
    CHECK( v.SetValue(b) );

    u_lsb = u.prvLSB();
    v_lsb = v.prvLSB();
    
    if (u_lsb < v_lsb)
        k = u_lsb;
    else
        k = v_lsb;

    CHECK( u.ShiftRight(u,k) );
    CHECK( v.ShiftRight(v,k) );

    u.s = v.s = MP_ZPOS;
    
    while(u.Compare(0) != 0)
    {
        CHECK( u.ShiftRight(u,u.prvLSB()) );
        CHECK( v.ShiftRight(v,v.prvLSB()) );

        if( u.Compare(v) >=0 )
        {
            CHECK( u.prvSubMag(u, v) );
            CHECK( u.ShiftRight(u,1) );
        }
        else
        {
            CHECK( v.prvSubMag(v, u) );
            CHECK( v.ShiftRight(v,1) );
        }
    }

    CHECK( v.ShiftLeft(v,k) );
    CHECK ( SetValue(v) );

    return ret;
}

// X <- lcm(a, b) least common multiple
// based on mp_lcm() of LibTomMath
int vlong::LCM (const vlong &a, const vlong &b)
{
    int ret = VLONG_SUCCESS;
    vlong t1, t2, tmp1, *c=this;

    if (&a==this || &b==this) c = &tmp1;

    // t1 = get the GCD of the two inputs
    CHECK( t1.GCD(a,b) );

    // divide the smallest by the GCD
    if (CompareMag(a,b) == MP_LT)
    {
        // store quotient in t2 such that t2 * b is the LCM
        CHECK( t2.Div(a, t1) );
        CHECK( c->Mul(b, t2) );
    }
    else
    {
        // store quotient in t2 such that t2 * a is the LCM
        CHECK( t2.Div(b, t1) );
        CHECK( c->Mul(a, t2) );
    }
    
    // fix the sign to positive
    c->s = MP_ZPOS;

    if (&a==this || &b==this) prvMovePtr(tmp1);

    return ret;
}



//Extended Euclidian Algorithm
//Y1*a + Y2*b = X, where X <- gcd(a,b), output X, Y1, Y2 (HAC 2.107)
int vlong::GCDExt (const vlong &a, const vlong &b, vlong *pY1, vlong *pY2)
{
    int ret = VLONG_SUCCESS;
    int swap=0;

    if (a.nu==0 || b.nu==0)
    {
        if (pY1 != NULL) CHECK( pY1->SetValue(1) );
        if (pY2 != NULL) CHECK( pY2->SetValue(0) );
        CHECK( SetValue(0) );
        return ret;
    }

    vlong x,y,b1,q,r,y1,y2;
    x.SetZero();
    y2.SetZero();
    CHECK( y.SetValue(1) );
    CHECK( y1.SetValue(1) );

    if (CompareMag(a,b) == MP_GT)
    {
        CHECK( Copy(a) );
        CHECK( b1.Copy(b) );
    }
    else
    {
        CHECK( b1.Copy(a) );
        CHECK( Copy(b) );
        swap=1;
    }

    while (b1.nu > 0)
    {
        CHECK( q.Div(*this, b1, &r) );
        CHECK( SetValue(b1) );
        CHECK( b1.SetValue(r) );

        CHECK( r.Mul(q, x) );
        CHECK( r.Sub(y1, r) );
        CHECK( y1.SetValue(x) );
        CHECK( x.SetValue(r) );

        CHECK( r.Mul(q, y) );
        CHECK( r.Sub(y2, r) );
        CHECK( y2.SetValue(y) );
        CHECK( y.SetValue(r) );
    
    }
    if (swap)
    {
        if (pY1 != NULL) pY1->swap(y1);
        if (pY2 != NULL) pY2->swap(y2);
    }
    else
    {
        if (pY1 != NULL) pY1->swap(y2);
        if (pY2 != NULL) pY2->swap(y1);
    }

    return ret;
}

//Binary Extended Euclidian Algorithm (faster)
//Y1*a + Y2*b = X, where X <- gcd(a,b), output X, Y1, Y2 (HAC 14.61 / 14.64)
int vlong::GCDExtBin (const vlong &a, const vlong &b, vlong *pY1, vlong *pY2)
{
    int ret = VLONG_SUCCESS;
    int tg=0;;
    vlong ta, tu, u1, u2, tb, tv, v1, v2;
    
    if (a.nu==0 || b.nu==0)
    {
        if (pY1 != NULL) CHECK( pY1->SetValue(1) );
        if (pY2 != NULL) CHECK( pY2->SetValue(0) );
        CHECK( SetValue(0) );
        return ret;
    }

    CHECK( ta.SetValue(a) );
    CHECK( tb.SetValue(b) );

    while((ta.d[0]&1)==0 && (tb.d[0]&1)==0)
    {
        CHECK( ta.ShiftRight(ta,1) );
        CHECK( tb.ShiftRight(tb,1) );
        tg++;
    }

    CHECK( tu.SetValue(ta) );
    CHECK( tv.SetValue(tb) );

    CHECK( u1.SetValue(1) );
    CHECK( u2.SetValue(0) );
    CHECK( v1.SetValue(0) );
    CHECK( v2.SetValue(1) );

    do
    {
        while((tu.d[0]&1) == 0)
        {
            CHECK( tu.ShiftRight(tu,1) );

            if((u1.d[0]&1)!=0 || (u2.d[0]&1)!=0)
            {
                CHECK( u1.Add(u1, tb) );
                CHECK( u2.Sub(u2, ta) );
            }

            CHECK( u1.ShiftRight(u1, 1) );
            CHECK( u2.ShiftRight(u2, 1) );
        }

        while( ( tv.d[0] & 1 ) == 0 )
        {
            CHECK( tv.ShiftRight(tv, 1) );

            if((v1.d[0]&1)!=0 || (v2.d[0]&1)!=0)
            {
                CHECK( v1.Add(v1, tb) );
                CHECK( v2.Sub(v2, ta) );
            }

            CHECK( v1.ShiftRight(v1, 1) );
            CHECK( v2.ShiftRight(v2, 1) );
        }

        if( CompareMag(tu, tv) >= 0)
        {
            CHECK( tu.Sub(tu, tv) );
            CHECK( u1.Sub(u1, v1) );
            CHECK( u2.Sub(u2, v2) );
        }
        else
        {
            CHECK( tv.Sub(tv, tu) );
            CHECK( v1.Sub(v1, u1) );
            CHECK( v2.Sub(v2, u2) );
        }
    }
    while(tu.nu != 0);

    if (pY1!=NULL) pY1->swap(v1);
    if (pY2!=NULL) pY2->swap(v2);
    CHECK( SetValue(tv) );

    if (tg>0) CHECK( ShiftLeft(*this,tg) );
    
    return ret;
}

