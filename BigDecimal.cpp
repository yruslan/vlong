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
#include "BigDecimal.h"
#include <sstream>

static const char *szFormatError = "Numeric Format Error";

BigDecimal::BigDecimal(int scale)
	: scale_ (scale)
{

}

BigDecimal::BigDecimal(const char *szNumber)
	: scale_(0)
{
	fromString(szNumber);
}

BigDecimal::BigDecimal(double d, int scale)
	: scale_(scale)
{
	fromDouble(d, scale);
}

void BigDecimal::fromString(const char *szNumber)
{
	int scale = 0, state = 0, expSign=1;
	size_t len = strlen(szNumber), pos = 0;
	int exp=0;
	std::string s;
	s.resize(len + 2);
	for (size_t i = 0; i < len; i++)
	{
		char c = szNumber[i];
		if (state==0 && c == '-')
		{
			state = 1;
			s[pos] = c;
			pos++;
			continue;
		}
		if (state == 0 && c >= 48 && c <= 57)
		{
			s[pos] = c;
			pos++;
			state = 2;
			continue;
		}
		if (state <= 2 && c =='.')
		{
			state = 10;
			continue;
		}

		// First digit
		if (state == 1 && (c < 48 || c > 57))
		{
			throw std::logic_error(szFormatError);
		}
		if (state == 1 && c >= 48 && c <= 57)
		{
			s[pos] = c;
			pos++;
			state = 2;
			continue;
		}

		// Integral part
		if (state == 2)
		{
			if (c >= 48 && c <= 57)
			{
				s[pos] = c;
				pos++;
				continue;
			}
			if (c == 'e' || c == 'E')
			{
				state = 3;
				continue;
			}
			if (c == 'e' || c == 'E')
			{
				state = 3;
				exp = 0;
				continue;
			}
			throw std::logic_error(szFormatError);
		}

		// Exponent sign
		if (state == 3)
		{
			if (c == '-')
			{
				expSign = -1;
				state = 4;
				continue;
			}
			if (c == '+')
			{
				expSign = 1;
				state = 4;
				continue;
			}
			if (c >= 48 && c <= 57)
			{
				exp = exp * 10 + c - 48;
				state = 4;
				continue;
			}
			throw std::logic_error(szFormatError);
		}

		// Exponent sign
		if (state == 4)
		{
			if (c >= 48 && c <= 57)
			{
				if (exp >= 100000000)
					throw std::logic_error(szFormatError);
				exp = exp * 10 + c - 48;
				state = 4;
				continue;
			}
		}

		// Fracture part
		if (state == 10 && c >= 48 && c <= 57)
		{
			scale += 1;
			s[pos] = c;
			pos++;
			continue;
		}
		break;
	}
	scale_ = scale <= 0 ? 0 : scale;
	m_.FromString(s.c_str(), 10);
	if (exp!=0)
	{
		if (expSign<0)
			scale_ = exp;
		else
		{
			vlong p10(10);
			p10.Pow(10, exp);
			vlong m(m_);
			m_.Mul(m_, p10);
		}
	}
}

void BigDecimal::fromDouble(double d)
{
	char str[30];
	sprintf(str, "%g", d);
	fromString(str);
}

void BigDecimal::fromDouble(double d, int scale)
{
	fromDouble(d);
	setScale(scale);
}

std::string BigDecimal::toString() const
{
	std::ostringstream oss;
	int sign = m_.GetSign();
	const char * str = m_.ToString(10);
	if (sign < 0) str++;
	size_t len = strlen(str);
	int scaleLeft = scale_;
	bool haveNonZero = false;

	if (len>0 && str[0] == '-')
	{
		oss << str[len - 1];
		len--;
	}

	while (scaleLeft>0 && len>0)
	{
		if (haveNonZero || str[len - 1]!='0')
		{
			oss << str[len - 1];
			haveNonZero = true;
		}
		scaleLeft--;
		len--;
	}
	while (scaleLeft > 0)
	{
		oss << "0";
		scaleLeft--;
	}

	if (haveNonZero)
		oss << ".";
	if (len == 0)
	{
		oss << "0";
	}
	else
	{
		while (len>0)
		{
			oss << str[len - 1];
			len--;
		}
	}
	if (sign < 0)
		oss << '-';
	std::string result = oss.str();
	std::reverse(result.begin(), result.end());
	return result;
}

void BigDecimal::setScale(int scale)
{
	if (scale < 0) scale = 0;
	if (scale > scale_)
	{
		vlong p10;
		p10.Pow(10, scale - scale_);
		vlong m(m_);
		m_.Mul(m, p10);
	}
	if (scale < scale_)
	{
		vlong p10;
		p10.Pow(10, scale_ - scale);
		vlong m(m_);
		vlong r;
		int sign = m_.GetSign()>0 ? 1 : -1;
		m_.Div(m, p10, &r);
		r.Mul(r, 2*sign);
		if (r >= p10)
			m_.Add(m_, sign);
	}
	scale_ = scale;
}

int BigDecimal::compare(const BigDecimal &rhs) const
{
	if (scale_ == rhs.scale_)
		return m_.Compare(rhs.m_);
	if (scale_>rhs.scale_)
	{
		BigDecimal tmp(rhs);
		tmp.setScale(scale_);
		return m_.Compare(tmp.m_);
	}
	BigDecimal tmp(*this);
	tmp.setScale(rhs.scale_);
	return tmp.m_.Compare(rhs.scale_);
}

void BigDecimal::add(const BigDecimal &rhs)
{
	if (scale_ == rhs.scale_)
	{
		m_.Add(m_, rhs.m_);
		return;
	}
	if (scale_ > rhs.scale_)
	{
		BigDecimal tmp(rhs);
		tmp.setScale(scale_);
		m_.Add(m_, tmp.m_);
		return;
	}

	BigDecimal tmp(*this);
	tmp.setScale(rhs.scale_);
	tmp.m_.Add(tmp.m_, rhs.m_);
	tmp.setScale(scale_);
	m_ = tmp.m_;
}

void BigDecimal::sub(const BigDecimal &rhs)
{
	if (scale_ == rhs.scale_)
	{
		m_.Sub(m_, rhs.m_);
		return;
	}
	if (scale_ > rhs.scale_)
	{
		BigDecimal tmp(rhs);
		tmp.setScale(scale_);
		m_.Sub(m_, tmp.m_);
		return;
	}

	BigDecimal tmp(*this);
	tmp.setScale(rhs.scale_);
	tmp.m_.Sub(tmp.m_, rhs.m_);
	tmp.setScale(scale_);
	m_ = tmp.m_;
}

void BigDecimal::mul(const BigDecimal &rhs)
{
	int scale = scale_;
	m_.Mul(m_, rhs.m_);
	scale_ = scale_ + rhs.scale_;
	setScale(scale);
}

void BigDecimal::div(const BigDecimal &rhs)
{
	BigDecimal tr(rhs);
	vlong r;
	int scale = scale_;
	setScale(scale + rhs.scale_);
	m_.Div(m_, tr.m_, &r);
	tr.m_.SetSign(1);
	r.Mul(r, 2);
	if (r >= tr.m_)
		m_.Add(m_, 1);
	scale_ -= rhs.scale_;
	setScale(scale);
}
