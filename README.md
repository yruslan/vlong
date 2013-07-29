vlong
=====

vlong, multiple-precision integer cross-platform C++ Class

Supports all essential numeric theory algorithms to implement public key cryptography procedures. 
Implementation is in plain C++ and thus architecture and endian-portable.

This code has no copyright whatsoever. Anyone can use it freely for any purpose. There is 
absolutely no guarantee it works or fits a particular purpose. 

This class has been made by Ruslan Yushchenko (yruslan@gmail.com)

Inspired by and mostly based on the work of
    Tom St Denis, tomstdenis@gmail.com, http://libtom.org (LibTomMath Library)

Referance materials:
   [BNM] Tom St Denis. BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic, 2006
   [HAC] Menezes et al. Handbook of Applied Cryptography, 1997
   
   
   Tested in 
     Windows
	    Visual C++ 6
		Visual C++ 2005
     Linux
	    GNU C++ (g++) 3.4.6


=======
BUILD
=======

Windows
    Use projects (.dsw, .sln) to build using Visual Studio

Linux
    Use the following command line to build the tests:
    g++ -O3 *.cpp -o example
	
=======
SOURCE
=======

   vlong,h, vlong.cpp - C++ class for multiple precision arithmetic
   vlong_selftest.h, vlong_selftest.h.cpp - self tests
   main.cpp - example
   
