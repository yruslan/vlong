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

#ifndef _VLONG_H_INCLUDED_
#define _VLONG_H_INCLUDED_

#include <algorithm>

//Configuration
//Maximum digits in a number. Comment out if unrestricted.
#define VLONG_MAX_DIGITS           1024

//Cutoff number of digits for Karatsuba multiply
#define VLONG_KARATSUBA_MUL_CUTOFF  80

//Enable diminished radix reduction
#define VLONG_USE_DR_REDUCE

//Enable Montgomery reduction
#define VLONG_USE_MONTGOMRTY

//Setting up the carried digits
//#define VLONG_8BIT
//#define VLONG_16BIT
#define VLONG_32BIT
//#define VLONG_64BIT

#ifdef VLONG_8BIT
typedef   signed char     sdig_t;
typedef unsigned char     udig_t;
typedef   signed short      swrd_t;
typedef unsigned short      uwrd_t;
#endif //VLONG_8BIT

#ifdef VLONG_16BIT
typedef   signed short     sdig_t;
typedef unsigned short     udig_t;
typedef   signed long      swrd_t;
typedef unsigned long      uwrd_t;
#endif //VLONG_16BIT

#ifdef VLONG_32BIT
#if defined(_MSC_VER)
    typedef   signed __int32   sdig_t;
    typedef unsigned __int32   udig_t;
    typedef   signed __int64   swrd_t;
    typedef unsigned __int64   uwrd_t;
#else
    typedef   signed int       sdig_t;
    typedef unsigned int       udig_t;
    typedef   signed long long swrd_t;  
    typedef unsigned long long uwrd_t;
#endif
#endif //VLONG_32BIT

#ifdef VLONG_64BIT
    typedef   signed long   sdig_t;
    typedef unsigned long   udig_t;
    typedef   signed long   swrd_t __attribute__ ((mode(TI)));
    typedef unsigned long   uwrd_t __attribute__ ((mode(TI)));
#endif

//Return values
#define VLONG_SUCCESS              0

#define VLONG_ERR_MEMORY_EXEED     10
#define VLONG_ERR_MEMORY_ALLOC     11
#define VLONG_ERR_MEMORY_FREE      12
#define VLONG_ERR_BUFFER_SMALL     13
#define VLONG_ERR_INVALID_CHAR     14
#define VLONG_ERR_BAD_ARG_1        21
#define VLONG_ERR_BAD_ARG_2        22
#define VLONG_ERR_BAD_ARG_3        23
#define VLONG_ERR_BAD_ARG_4        24
#define VLONG_ERR_OUT_OF_RANGE     25
#define VLONG_ERR_DIV_BY_ZERO      26
#define VLONG_ERR_NEGATIVE_ARG     27
#define VLONG_ERR_NO_INVERSE       28
#define VLONG_ERR_UNEXPECTED       100
#define VLONG_ERR_NOT_IMPLEMENTED  101

#define VLONG_WRN_INSECURE_RNG     200

// The class organized as follows

class vlong
{
public:
    vlong() {Init();}
    vlong(sdig_t v) {Init(); SetValue(v);}
    vlong(const vlong &v) {Init(); Copy(v);}
    vlong(const char *szNumber, int radix) {Init(); FromString(szNumber,radix);}

    virtual ~vlong() {Clear();}
    int Copy(const vlong &v);

	// Set number equal to zero
    void SetZero();
	
	// Check if stored number is zero
    bool isZero() const {return nu==0;}

	// Sets value to the absulute value of a given vlong integer
    int Abs(const vlong &v) {int ret=Copy(v);s=nu==0?0:1;return ret;}

    int GetSign() {return s;}

	// Gets the number of bytes required to store unsigned vlong integer
	// (Does not take into account sign bit)
    int GetSizeBytes() {return nu*sizeof(udig_t);}
    
    // Get least significant digit (unsigned)
    udig_t GetInt();

	// Set value to a single digit integer
    int SetValue(sdig_t v);

	// Set value to be equal to another number
    int SetValue(const vlong &v) {return Copy(v);}

	// Swap contents of two vlong objects
	// Faster then copying because it doesn't require
	// memory copy operation. Just swaps pointers
    void swap(vlong &v);

    //***************** Import a number from various sources *******************************
    // Convert from arbitrary string of 2<=radix<=16
    // or you can supply a custom character alphabet to convert
    // from a custom numeric system (2<=radix<=256)
    int FromStringBuf(const char *pBuf, size_t nBufLen = 0, int nRadix = 16, const char *szCustomChars = NULL);
    
    // Convert from a NUUL-terminated string of 2<=radix<=16
    int FromString(const char *szNumber, int radix = 16);

    // Convert from a NUUL-terminated BASE64-encoded string
    int FromBase64(const char *szNumber);

    // Convert from unsigned big-endian binary number
    int FromBinary(const char *szNumber, size_t buflen);

    //****************** Export a number to various formats ********************************
    // Convert to string of 2<=radix<=16
    // or you can supply a custom character alphabet to convert 
    // to a custom numeric system (2<=radix<=256)
    int ToStringBuf(char *pBuf, size_t &nBufLen, int nRadix = 16, const char *szCustomChars = NULL) const;

    // Convert to temporary readable string (useful in printf) 2<=radix<=16
    const char *ToString(int radix = 16) const;

    // Convert to BASE64-encoded string and save to automatically generated internal temporary buffer
    const char *ToBase64();

    // Convert to BASE64-encoded string and save to user-specified buffer
    int ToBase64Buf(char *pBuf, size_t &nBufLen) const;

    // Convert unsigned part of the vlong number to big-endian binary buffer
    int ToBinary(char *buf, size_t buflen) const;

    //******************************* Comparisons ******************************************
	// Compare this object to either a a small signed number or to a vlong integer. [BNM pp.50 Algorithm 3.10]
	// Results are usual {-1,0,1} for {X<v, X==v, X>v} results.
    int Compare(sdig_t v) const;
    int Compare(const vlong &v) const;

	// Compare vlong numbers my magnitude (ignoring sign) [BNM pp.48 Algorithm 3.9]
	// Results are usual {-1,0,1} for {|a|<|b|, |a|==|b|, |a|>|b|} results.	
	static int CompareMag(const vlong &a, const vlong &b);

    //*************************** Bitwise operations ***************************************
    // Returns count of number of bits in the vlong integer
    size_t GetNumBits() const;

	// Returns the number of least significant zero bits before the first one bit
    size_t GetNumLSB() const;

    // Returns the number of the most significant bit
    size_t GetNumMSB() const;

	// Shift right by a specified number of digits
    int ShiftRight(const vlong &a, int bits);

	// Shift left by a specified number of digits
    int ShiftLeft(const vlong &a, int bits);

	// Set a specified bit to a specified value 0 or 1
    int SetBit(size_t num, char bit);

	// Return value of a specified bit
    char GetBit(size_t num);
    
    //X <- a ^ b  [X refers to caller object]
    int Xor(const vlong &a, const vlong &b);

    //**************************** Bytewise operations *************************************
    int SetBytes(int start, size_t count, const char *buf);
    int GetBytes(int start, size_t count, char *buf) const;

    //********************************* Generators *****************************************
    int GenRandomBytes(size_t bytes, int (*pRNG_f)(void *, char *, size_t) = NULL, void *pRNG_ctx = NULL);
    int GenRandomBits(size_t bits, int (*pRNG_f)(void *, char *, size_t) = NULL, void *pRNG_ctx = NULL);
    int GenRandomPrime(size_t bytes, int (*pRNG_f)(void *, char *, size_t) = NULL, void *pRNG_ctx = NULL);


    //********************************** Primarity *****************************************
    int SearchNearestPrime();
    bool IsPrime();
    
    //************************** Long-Short Arithmetic *************************************
    int Add(const vlong &a, sdig_t b);
    int Sub(const vlong &a, sdig_t b);
    int Mul(const vlong &a, sdig_t b);
    int Div(const vlong &a, sdig_t b, sdig_t *r=NULL);
    int Mod(const vlong &a, sdig_t b);

    //Return reminder of a/b. This function has different name, because
    //it does not affect the value of caller object (as Mod() does).
    sdig_t ModDig(const vlong &a, sdig_t b) const;

    //************************** Long-Long Arithmetic **************************************
	// [BNM pp.64 Algorithm 4.3]
    int Add(const vlong &a, const vlong &b);

	// [BNM pp.67 Algorithm 4.5]
    int Sub(const vlong &a, const vlong &b);
    int Mul(const vlong &a, const vlong &b, size_t maxdigs = 0);
    int Sqr(const vlong &a);
    int Div(const vlong &a, const vlong &b, vlong *r=NULL);

    //X <- a % b  [X refers to caller object]
    int Mod(const vlong &a, const vlong &b);

    //X <- a % b (Must hold: 0<a<b*b)  [X refers to caller object]
    int ModBarrett(const vlong &a, const vlong &b);

    //X <- a % b (Must hold: 0<a<b*b and b is odd) [X refers to caller object]
    int ModMontgomery(const vlong &a, const vlong &b);

    //X <- a % b (Must hold: 0<a<b*b, half or more digits of b must me 1 bits) [X refers to caller object]
    int ModDRExt(const vlong &a, const vlong &b);   

    //X <- a ^ e [X refers to caller object]
    int Pow(sdig_t a, sdig_t e);
    int Pow(const vlong &a, size_t e);

    //Computes X such as X^b <= n < (X+1)^n (integer n'th root of a) [X refers to caller object]
    int Root(const vlong &a, udig_t n);

    //*************************** Modular arithmetic ***************************************
    //X <- a * b mod n  [X refers to caller object]
    int MulMod(const vlong &a, const vlong &b, const vlong &n);
    //X <- a * a mod n  [X refers to caller object]
    int SqrMod(const vlong &a, const vlong &n) { return MulMod(a, a, n); }

    //Computes X such as a*X=1 (mod n). Must hold: gcd(a,n)=1  [X refers to caller object]
    int InvMod(const vlong &a, const vlong &n);

    //X <- a^e (mod n)  [X refers to caller object]
    int PowMod(const vlong &a, const vlong &e, const vlong &n);
    int PowMod(const vlong &a, udig_t e, const vlong &n);
    int PowModSlow(const vlong &a, const vlong &e, const vlong &n);

    // Power modular N using Chineese Reminder Theorem (CRT)
    // (RSA private key operation)
    // Assume n = p*q, where p and q are prime, private exponent d
    // Input:  a  <- Source number (RSA ciphertext)
    //         p  <- prime p such as p*q=n
    //         q  <- prime q such as p*q=n
    //         dp <- d mod p (must be calculated separately)
    //         dq <- d mod q (must be calculated separately)
    //         qp <- q^-1 mod q (must be calculated separately)
    // Output: X  <- a^d (mod n) (RSA plaintext)
    int PowModCRT(const vlong &a, const vlong &p, const vlong &q, const vlong &dp, const vlong &dq, const vlong &qp);

    //X <- gcd(|a|, |b|) Greatest common divisor  [X refers to caller object]
    int GCD (const vlong &a, const vlong &b);

    //Extended Euclidian Algorithm
    //Y1*a + Y2*b = X, where X <- gcd(a,b), output X, Y1, Y2  [X refers to caller object]
    int GCDExt (const vlong &a, const vlong &b, vlong *pY1, vlong *pY2);

    //Binary Extended Euclidian Algorithm (faster)
    //Y1*a + Y2*b = X, where X <- gcd(a,b), output X, Y1, Y2  [X refers to caller object]
    int GCDExtBin (const vlong &a, const vlong &b, vlong *pY1, vlong *pY2);

    //X <- lcm(|a|, |b|) Least common multiple  [X refers to caller object]
    int LCM (const vlong &a, const vlong &b);

    //******************************** Operators *******************************************
	// Commented out as this could be dangerous conversion in various compilers
    //operator const char*() {return ToString(16);}

    vlong& operator = (sdig_t v) {SetValue(v); return *this;}
    vlong& operator = (const vlong &v) {SetValue(v); return *this;}

    //Comparison
    bool operator > (sdig_t x) {return Compare(x)>0;}
    bool operator > (const vlong &x) {return Compare(x)>0;}
    bool operator >= (sdig_t x) {return Compare(x)>=0;}
    bool operator >= (const vlong &x) {return Compare(x)>=0;}
    bool operator < (sdig_t x) {return Compare(x)<0;}
    bool operator < (const vlong &x) {return Compare(x)<0;}
    bool operator <= (sdig_t x) {return Compare(x)<=0;}
    bool operator <= (const vlong &x) {return Compare(x)<=0;}
    bool operator == (sdig_t x) {return Compare(x)==0;}
    bool operator == (const vlong &x) {return Compare(x)==0;}
    bool operator != (sdig_t x) {return Compare(x)!=0;}
    bool operator != (const vlong &x) {return Compare(x)!=0;}

    void operator += (sdig_t v) {Add(*this,v);}
    void operator += (const vlong &v) {Add(*this,v);}   
    void operator -= (sdig_t v) {Sub(*this,v);}
    void operator -= (const vlong &v) {Sub(*this,v);}
    void operator <<= (int c) {ShiftLeft(*this,c);}
    void operator >>= (int c) {ShiftRight(*this,c);}
    void operator %= (sdig_t b) {Mod(*this,b);}
    void operator %= (const vlong &v) {Mod(*this,v);}
    void operator *= (sdig_t v) {Mul(*this,v);}
    void operator *= (const vlong &v) {Mul(*this,v);}
    void operator /= (sdig_t v) {Div(*this,v,NULL);}
    void operator /= (const vlong &v) {Div(*this,v,NULL);}

    const vlong operator + (sdig_t b) const {vlong t;t.Add(*this,b);return t;}
    const vlong operator + (const vlong &b) const {vlong t;t.Add(*this,b); return t;}
    const vlong operator - (sdig_t b) const {vlong t;t.Sub(*this,b);return t;}
    const vlong operator - (const vlong &b) const {vlong t;t.Sub(*this,b);return t;}
    const vlong operator << (int c) const {vlong t;t.ShiftLeft(*this,c);return t;}
    const vlong operator >> (int c) const {vlong t;t.ShiftRight(*this,c);return t;}
    const sdig_t operator % (sdig_t b) const {return ModDig(*this,b);}
    const vlong operator % (const vlong &b) const {vlong t;t.Mod(*this,b); return t;}
    const vlong operator * (sdig_t b) const {vlong t;t.Mul(*this,b);return t;}
    const vlong operator * (const vlong &b) const {vlong t;t.Mul(*this,b); return t;}
    const vlong operator / (sdig_t b) const {vlong t;t.Div(*this,b,NULL);return t;}
    const vlong operator / (const vlong &b) const {vlong t;t.Div(*this,b,NULL); return t;}

private:
    //Memory Management
    void Init();
    int Clear();
    int Grow(size_t n);
    int Clamp();
    int prvMovePtr(vlong &v);

    //Tool arithmetic
	
	//Low-level addition (adds only magnitudes) [BNM pp.55 Algorithm 4.1]
    int prvAddMag(const vlong &a, const vlong &b);
	
	// Low-level substraction (substract only magnitudes) [BNM pp.60 Algorithm 4.2]
	// Assumes |a|>=|b|
    int prvSubMag(const vlong &a, const vlong &b);

	// Shift by specified number of digits [BNM pp.76 Algorithm 4.9, pp.79 Algorithm 4.11]
    int prvLeftShiftDigits(size_t digs);
    int prvRightShiftDigits(size_t digs);

    //Fast Karatsuba multiplication O(N^1.584) (used for long numbers only)
    int prvMulKaratsuba(const vlong &a, const vlong &b);

    //Baseline O(N^2) multiplication
    int prvMulBaseline(const vlong &a, const vlong &b, size_t ndigs);

    static int prvDivInt(const vlong &a,       udig_t b, vlong *q=NULL, udig_t *r=NULL);
    static int prvDivBig(const vlong &a, const vlong &b, vlong *q=NULL,  vlong *r=NULL);

    //Multiply by a digit
    int prvMulDig(const vlong &a, udig_t b);

    static int prvIsPow2(udig_t b, size_t *nbits);
    int prvModPow2(const vlong &a, size_t bits);
    int prvDivPow2(const vlong &a, size_t bits, vlong *r);

    //X <- a^e (mod n)
    int prvPowModBarrett(const vlong &a, const vlong &e, const vlong &n, int redmode);
    int prvPowModMontgomery(const vlong &a, const vlong &e, const vlong &n);

    //Reduction
    // computes a = 2**b
    int prv2Expt(udig_t b);
    int prvMod2d(const vlong &a, int b);

    // Barett reduction
    static int prvReduceBarrettSetup(const vlong &n, vlong *mu);
    static int prvReduceBarrett(vlong *x, const vlong &n, const vlong &mu);
    // Diminished radix reduction
    //determines if DR reduce could be used
    bool prvIsDrModulus() const;
    static int prvReduceDRSetup(const vlong &n, vlong *mu);
    static int prvReduceDR(vlong *x, const vlong &n, const vlong &mu);
    //Montgomery reduction reduction
    static int prvReduceMontgomerySetup(const vlong &n, udig_t *rho);
    static int prvReduceMontgomery(vlong *x, const vlong &n, udig_t rho);
    int prvMontgomeryNorm(vlong *a, const vlong &b);

    //Primarity tests
    static int prvIsMillerRabinPrime(const vlong &a, const vlong &b, bool &bPrime);

    size_t prvLSB();
    
    //Polynomial arithmetic

    //The very long number
    char s;       //Sign
    udig_t *d;    //Digits
    size_t na;    //Number of allocated digits
    size_t nu;    //Number of used digits

    //Temporary attributes
    mutable char *tmp;    //For string output
    mutable size_t ntmp;  //Chars in the tmp string
};

namespace std
{
	template<>
	inline void swap(vlong &a, vlong &b)
	{
		a.swap(b);
	}
}

#endif //_VLONG_H_INCLUDED_

