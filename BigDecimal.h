/* BigDecimal, a C++ class for multiple-precision fixed-point numbers
*
* Supports from string and to string conversions and arithmetic operations.
* Implementation is in plain C++ and thus architecture and endian-portable.
*
* Anyone can use it freely for any purpose. There is
* absolutely no guarantee it works or fits a particular purpose (see below).
*
* This class has been made by Ruslan Yushchenko (yruslan@gmail.com)
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
#ifndef _BIG_DECIMAL_H_INCLUDED_
#define _BIG_DECIMAL_H_INCLUDED_

#include <string>
#include "vlong.h"

class BigDecimal
{
public:
	explicit BigDecimal(int scale);
	explicit BigDecimal(const char *szNumber);
	BigDecimal(double d, int scale);

	void fromString(const char *szNumber);
	void fromDouble(double d);
	void fromDouble(double d, int scale);

	std::string toString() const;
	int getScale() const { return scale_; }
	void setScale(int scale);

	int compare(double rhs) const { return compare(BigDecimal(rhs, scale_)); }
	int compare(const BigDecimal &rhs) const;

	//Comparison
	bool operator > (double x) const { return compare(x) > 0; }
	bool operator > (const BigDecimal &x) const { return compare(x) > 0; }
	bool operator >= (double x) const { return compare(x) >= 0; }
	bool operator >= (const BigDecimal &x) const { return compare(x) >= 0; }
	bool operator < (double x) const { return compare(x) < 0; }
	bool operator < (const BigDecimal &x) const { return compare(x) < 0; }
	bool operator <= (double x) const { return compare(x) <= 0; }
	bool operator <= (const BigDecimal &x) const { return compare(x) <= 0; }
	bool operator == (double x) const { return compare(x) == 0; }
	bool operator == (const BigDecimal &x) const { return compare(x) == 0; }
	bool operator != (double x) const { return compare(x) != 0; }
	bool operator != (const BigDecimal &x) const { return compare(x) != 0; }

	void operator += (double rhs) { add(BigDecimal(rhs, scale_)); }
	void operator += (const BigDecimal &rhs) { add(rhs); }
	void operator -= (double rhs) { sub(BigDecimal(rhs, scale_)); }
	void operator -= (const BigDecimal &rhs) { sub(rhs); }
	void operator *= (double rhs) { mul(BigDecimal(rhs, scale_)); }
	void operator *= (const BigDecimal &rhs) { mul(rhs); }
	void operator /= (double rhs) { div(BigDecimal(rhs, scale_)); }
	void operator /= (const BigDecimal &rhs) { div(rhs); }

	BigDecimal operator + (double rhs) const { BigDecimal t(*this); t.add(BigDecimal(rhs, scale_)); return t; }
	BigDecimal operator + (const BigDecimal &rhs) const { BigDecimal t(*this); t.add(rhs); return t; }
	BigDecimal operator - (double rhs) const { BigDecimal t(*this); t.sub(BigDecimal(rhs, scale_)); return t; }
	BigDecimal operator - (const BigDecimal &rhs) const { BigDecimal t(*this); t.sub(rhs); return t; }
	BigDecimal operator * (double rhs) const { BigDecimal t(*this); t.mul(BigDecimal(rhs, scale_)); return t; }
	BigDecimal operator * (const BigDecimal &rhs) const { BigDecimal t(*this); t.mul(rhs); return t; }
	BigDecimal operator / (double ths) const { BigDecimal t(*this); t.div(BigDecimal(ths, scale_)); return t; }
	BigDecimal operator / (const BigDecimal &rhs) const { BigDecimal t(*this); t.div(rhs); return t; }

private:
	void add(const BigDecimal &rhs);
	void sub(const BigDecimal &rhs);
	void mul(const BigDecimal &rhs);
	void div(const BigDecimal &rhs);

	int scale_;
	vlong m_;
};


#endif // _BIG_DECIMAL_H_INCLUDED_
