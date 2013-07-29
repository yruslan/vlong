/* 
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vlong.h"
#include "vlong_selftest.h"

//------------------------------------------------------------------------------------------------------

#ifdef WIN32
#define _WIN32_WINNT    0x0500
#include <windows.h>
#include <winnt.h>
#include <winbase.h>

#else

#include <sys/time.h>
#include <unistd.h>

void getcurtime(struct timeval *t)
{
    gettimeofday (t, (struct timezone *) 0);
}
#endif


double GetTime()
{
#ifdef WIN32
    LARGE_INTEGER t, freq;
    QueryPerformanceCounter(&t);
    QueryPerformanceFrequency(&freq);

    return ((double)t.QuadPart)/((double)freq.QuadPart);
#else
    struct timeval t;
    getcurtime(&t);

    return ((double)t.tv_sec)+((double)t.tv_usec)/1.e+6;
#endif
}

//------------------------------------------------------------------------------------------------------


int vlong_timing()
{
    vlong a,b,c,n,e,d,p,q,dp,dq,qp;

    const char *szModulus = "BED310CB2BBFE6BBEE0B3168CD47711AEC9CDACFAA560748C76FA5A6A9381782A1D71D866E7A52F01926BBDB6610A6449BA65E9611D55F1CC0C2F72E157F174ACA26B6AE36560B84E7E325970D52A2591FBD2578D454D22E52F8CC52B7E644198FC4FCD3928E2924FBC64F3F5F586E4542A73948F02FA04DCE0FF9DF1141E2C5";
    n.FromString(szModulus,16);
    //Public exponent
    e.FromString("65537",10);
    //Private exponent
    d.FromString("04f4aa4cfc77e16024107a5a046ac48f3471e664da419db2d02b201c31ecd8ff758086adc514bc2eac188b6c693c297542ad916b484f484710e27f54dd0e0de6c1c4b58e54064e9483e9957c9a66f5fa8a58fec97758e2778a3dc453093475f8a3dffdd1bb68ede240643a3d5a8fd71eff09bcbb362dd8f8ed9d8688067b5d89",16);

    // Div timing (11 s)
    double fTime1 = GetTime();
    int i;
    for (i=0; i<1000000; i++)
    {
        c.Div(n, d);
    }
    double fTime2 = GetTime();
    printf("Divide(1e+6 times): %g seconds\n",fTime2-fTime1);

    // Mod timing (11 s)
    fTime1 = GetTime();
    for (i=0; i<1000000; i++)
    {
        c.Mod(n, d);
    }
    //printf("c=%s\n",c.ToString(10));
    fTime2 = GetTime();
    printf("Mod (1e+6 times): %g seconds\n",fTime2-fTime1);

    // Multiply timing (16 s)
    fTime1 = GetTime();
    for (i=0; i<1000000; i++)
    {
        c.Mul(n, d);
    }
    //printf("c=%s\n",c.ToString(10));
    fTime2 = GetTime();
    printf("Multiply(1e+6 times): %g seconds\n",fTime2-fTime1);
    
    p.FromString("f9805c758fce4a9502a6090b1d355869e3e8571a747429d3c5ca12347fa3f0b803a002960df03aa264728af0f2baff0ed4d479186069020cfead8210baf20b63");
    q.FromString("c3cb7489a2862898e2372f7866b43e94090fe5c36e43a7fd30a228662fe967f8e262b12e97c525150ce074f3c19172ff5ac2d782d99e6f824d0f6b3d3032f5b7");
    dp.FromString("09616a18816fa01e3a1b43fbc6fd5a75a0bbfb8a63167afc1b539d9b9bb0ee3bfce6e731fd142b202fe69e92b08d97495777259665098daa2f69169aca6c8f41");
    dq.FromString("77fc5ca463e6d746298b2c1a1ac6667b0dbaa2514b6746b150766f4f801907506c5b92bd3ce0e1c2aeab76c052653215eea6ecaf117198603f9d2d58c80ad2ad");
    qp.FromString("21e7230c187496bc72ea56e6516e45f0ed0ba434ca6a763caa75d6939ffb98cd326fd9be3267565d29f817a8535a39f2fed84de66e2551f0384f8fd3f628345f");

	a.SetValue(99999);
	printf("Plaintext  = %s\n", a.ToString(10));

    // RSA timing (21 s)
    fTime1 = GetTime();
    for (i=0; i<100; i++)
    {
        a.SetValue(99999);
        b.PowMod(a, e, n);
        
        //FULL power modular N
        //c.PowMod(b, d, n);

        //CRT (fast) power modular N    
        c.PowModCRT(b, p, q, dp, dq, qp);
    }
	fTime2 = GetTime();
    printf("\n");
    printf("Ciphertext = %s\n",b.ToString(10));  
	printf("Deciphered = %s\n", c.ToString(10));    
    printf("RSA-1024(100 times): %g seconds\n",fTime2-fTime1);
    
    return 0;
}

int main ()
{

	printf("Performing selftest...\n");
    vlong_selftest(1); // 1 - verbose
	printf("Performing timing...\n");
    vlong_timing();

    return 0;
}
