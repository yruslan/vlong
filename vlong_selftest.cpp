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

#define TEST(s,x) if( !(x) ) { bError=true;printf("%s:\tFAIL!\n", (s)); nFailed++;} else {nSucceed++; bError=false;}

int vlong_selftest(int verbose/*=0*/)
{
    bool bError=false;
    int nSucceed = 0;
    int nFailed = 0;
    char str[255];

    vlong a, c, b,s,x,y;

    TEST("Carrier Digits Size", sizeof(uwrd_t)==2*sizeof(udig_t));
    if (bError)
        printf("sizeof(udig_t)=%d, sizeof(uwrd_t)=%d (uwrd_t must me twice as big!)\n", (int)sizeof(udig_t), (int)sizeof(uwrd_t));
    
    a.FromString("AaaBbBCccDddd012345fff");

    TEST("Conversion",strcmp(a.ToString(16), "AAABBBCCCDDDD012345FFF")==0);
    if (bError && verbose)
        printf("a=%s\n", a.ToString(16));

    s = 0;
    s.SetBit(77,1);
    TEST("bit77==1", s.GetBit(77)==1);
    TEST("bit76==0", s.GetBit(76)==0);
    TEST("bit78==0", s.GetBit(78)==0);
    //printf("s=%s\n", s.ToString());
    a = 1;
    s.Xor(s,a);
    TEST("bit0==1", s.GetBit(0)==1);

    a.FromString("5A4653CA673768565B41F775D6947D55CF3813D1");
    b.FromString("1E17714377BD22C773C0A7D1F2317F1C9A68069B");
    s.FromString("785DC50DDEF48B1DCF029F47C8C5FC7269A01A6C");
    c = a + b;
    TEST("a+b(1)", c==s);
    if (bError && verbose)
    {
        printf("OUT=%s\n", c.ToString());
        printf("EXP=%s\n", s.ToString());
    }

    TEST("a>b", a>b);
    TEST("a>=b", a>=b);
    TEST("a!=b", a!=b);
    TEST("a!=0", a!=0);
    TEST("nbits==159", a.GetNumBits()==159);
    //if (a>b)
    //  printf("A>B\n");
    //else
    //  printf("A<=B\n");

    a = 0;
    a.SetBytes(0,16,"1234567890123456");
    a.GetBytes(1,14, str);
    str[14]='\0';
    TEST("SetBytes/GetBytes", strcmp(str,"23456789012345")==0);
    //printf("a=%s (%d) %s\n", a.ToString(), a.GetNumBits(), str);

    a=2;
    b=2;
    s.Add(a,b);
    //printf("s=%s\n", s.ToString());

    a=2;
    b=2;
    s.Add(a,b);
    //printf("s=%s\n", s.ToString());

    a = 0;
    b = 3;
    a.SetBit(32,1);
    a.SetBit(0,1);
    a-=b;
    //printf("a=%s\n", a.ToString());
    TEST("SubLong", strcmp(a.ToString(),"FFFFFFFE")==0);

    a = 0;
    b = 3;
    a.SetBit(64,1);
    a.SetBit(0,1);
    a-=b;
    //printf("a=%s\n", a.ToString());
    TEST("SubLong", strcmp(a.ToString(),"FFFFFFFFFFFFFFFE")==0);

    a+=3;
    //printf("a=%s\n", a.ToString());
    TEST("AddShort", strcmp(a.ToString(),"10000000000000001")==0);

    a-=3;
    //printf("a=%s\n", a.ToString());
    TEST("SubShort", strcmp(a.ToString(),"FFFFFFFFFFFFFFFE")==0);

    a=1;
    a = a<<31;
    //printf("a=%s\n", a.ToString());
    TEST("1<<31", strcmp(a.ToString(),"80000000")==0);
    a = a>>30;
    //printf("a=%s\n", a.ToString());
    TEST("1<<31 >>30", strcmp(a.ToString(),"2")==0);

    //a<<=1023;
    //printf("a=%s\n", a.ToString());
    //a>>=1024;
    //printf("a=%s\n", a.ToString());
    //TEST("1<<31 >>30", strcmp(a.ToString(),"2")==0);

    a = 100;
    a<<=100;
    a.Div(a,7);
    TEST("Div/Sm1", strcmp(a.ToString(),"E4924924924924924924924924")==0);
    a.Div(a,1073741824);
    //printf("a=%s\n", a.ToString());
    TEST("Div/Sm2", strcmp(a.ToString(),"3924924924924924924")==0); 

    //printf("a=%s\n", a.ToString(16));
    //printf("a=%s\n", a.ToString(8));
    //printf("a=%s\n", a.ToString(10));
    //printf("a=%s\n", a.ToCustom("abcdEFGH+"));
    //printf("a=%s\n", a.ToCustom("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"));

    //a.FromString("1000", 10);
    //printf("a=%s\n", a.ToString(10));

    a.FromString("1099511627776", 10); //2^40
    TEST("Con10", strcmp(a.ToString(16), "10000000000")==0);
    //printf("a=%s\n", a.ToString(16));

    //a.FromString("11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568", 10);
    //printf("a=%s\n", a.ToString(10));

    a.FromString("-1AABBCCF", 16);
    //printf("a=%s\n", a.ToString(16));
    //printf("a=%s\n", a.ToBase64());
    TEST("ToB64", strcmp(a.ToBase64(),"ARqrvM8=")==0);
    b.FromBase64(a.ToBase64());
    TEST("FrB64", strcmp(b.ToString(16),"-1AABBCCF")==0);
    //printf("b=%s\n", b.ToString(16));
    //printf("c=-1AABBCCF\n");

    a.FromString("1234567900002", 10);
    b.FromString("4500001", 10);
    c.Mul(a,b);
    TEST("MulMsu", strcmp(c.ToString(10),"5555556784576900002")==0);
    //printf("%s*%s=%s\n", a.ToString(10), b.ToString(10), c.ToString(10));


    a.Pow(3,300);
    //printf("%s\n", a.ToString(16));
    //printf("B39CFFF485A5DBF4D6AAE030B91BFB0EC6BBA389CD8D7F85BBA3985C19C5E24E40C543A123C6E028A873E9E3874E1B4623A44BE39B34E67DC5C2671\n");
    TEST("3^300", strcmp(a.ToString(16),"B39CFFF485A5DBF4D6AAE030B91BFB0EC6BBA389CD8D7F85BBA3985C19C5E24E40C543A123C6E028A873E9E3874E1B4623A44BE39B34E67DC5C2671")==0);
    if (bError)
        printf("3^300?=%s\n", a.ToString(16));

    b.FromBase64("AAs5z/9IWl2/TWquAwuRv7Dsa7o4nNjX+Fu6OYXBnF4k5AxUOhI8bgKKhz6eOHThtGI6RL45s05n3FwmcQ==");
    TEST("Base64", a==b);
    

    //TEST Karatsuba (need to lower KARATSUBA_MUL_CUTOFF
    //a.FromString("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 10);
    //b.FromString("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 10);
    //c.Mul(a,b);
    //TEST("MulMsu", strcmp(c.ToString(10),"5555556784576900002")==0);
    //printf("%s*%s=%s\n", a.ToString(16), b.ToString(16), c.ToString(10));

    /*a=1;
    int i;
    for (i=2; i<=100; i++)
    {
        a*=i;
        printf("%d! = %s\n", i, a.ToString(10));
    }*/

    //a = 50;
    //b = 250;
    //a.Pow(3,300);
    //b.Pow(2,300);
    //c.GCD(a,b);
    //printf("GCD(%s,%s)=%s\n", a.ToString(10), b.ToString(10), c.ToString(10));

    a = 1239;
    b = 735;
    c.GCDExtBin(a,b,&x,&y); 
    TEST("GCD_Ext_Bin", (x==89) && (y==-150));
    if (bError)
    {
        printf("(%s)*%s + (%s)*%s = %s", x.ToString(10),a.ToString(10),y.ToString(10),b.ToString(10),c.ToString(10));
        c = a*x+b*y;
        printf("(expected %s)\n", c.ToString(10));
    }

    //c=a;
    //c*=x;
    //printf("(%s)*(%s) = %s\n", a.ToString(10),x.ToString(10),c.ToString(10));
    //s=b;
    //s*=y;
    //printf("(%s)*(%s) = %s\n", b.ToString(10),y.ToString(10),s.ToString(10));
    //c+=s;
    //printf("(%s) + (%s) = %s\n", b.ToString(10),y.ToString(10),c.ToString(10));

    a.FromString("12381723981720398712098376423748296873610000009999999988888888889999999999",10);
    b.FromString("234678087908071823794444444412222222222",10);
    c.Div(a,b,&x);
    TEST("Div/Long", strcmp(c.ToString(10),"52760460476269823791333933038493411")==0);
    //s=c;
    //s*=b;
    //printf("%s / %s = %s , %s (%s) \n", a.ToString(10), b.ToString(10), c.ToString(10), x.ToString(10), s.ToString(10));

    vlong n,e,d,g,gab1,gab2,p,q,dp,dq,qp;


    /*n.FromString("FFFFFFFFFFFFFFFFFF002B", 16);
    e.FromString("65537",10);
    a.FromString("99889988",10);
    d.FromString("CF305352C15A57B1CACE4FD52F3232AE1DCDB5860C79",16);
    c.Mod(d,n);
    printf("c=%s\n", c.ToString(16));
    c.ModDRExt(d,n);
    printf("c=%s\n", c.ToString(16));*/

    //c.PowMod(a, e, n);
    //printf("c=%s\n", c.ToString(10)); 

    a.FromString("16342093704794905017200815921831331498602310292448679875661939076",10);
    b.Root(a,2);
    TEST("Root", strcmp(b.ToString(10), "127836198726318927639187263981726")==0);
    //printf("b=%s\n", b.ToString(10));

    a.GenRandomBits(1023);
    TEST("GetBits", a.GetNumBits()==1023);  


    n.FromString("10000000000000000000000000000000",16);
    n.SearchNearestPrime();
    TEST("SearchPrime", strcmp(n.ToString(16), "10000000000000000000000000000043")==0);
    if (bError)
        printf("Supposed prime: %s\n", n.ToString(16));

    n.FromString("10000000000001110000000000000000",16);
    n.SearchNearestPrime();
    TEST("SearchPrime", strcmp(n.ToString(16), "100000000000011100000000000000CF")==0);
    if (bError)
        printf("Supposed prime: %s\n", n.ToString(16));

    //RFC5114 1024-bit prime and generator for DH
    n.FromString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    g.FromString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);
    a.GenRandomBits(1023);    
    b.GenRandomBits(1023);

    TEST("DHIsPrime", n.IsPrime());
    
    c.PowMod(g,a,n);
    d.PowMod(g,b,n);
    gab1.PowMod(c,b,n);
    gab2.PowMod(d,a,n);
    TEST("DH", gab1==gab2);
    if (bError)
    {
        printf("Must be equal:\n");
        printf("(g^a)^b = %s\n", gab1.ToString(16));
        printf("(g^b)^a = %s\n", gab1.ToString(16));
    }
    
    /*printf("n=%s\n", n.ToString(16));
    if (n.IsPrime())
        printf("Prime\n");
    else
    {
        n.SearchNearestPrime();
        printf("Not prime\n");
        printf("n=%s\n", n.ToString(16));
    }*/
    

    const char *szModulus = "BED310CB2BBFE6BBEE0B3168CD47711AEC9CDACFAA560748C76FA5A6A9381782A1D71D866E7A52F01926BBDB6610A6449BA65E9611D55F1CC0C2F72E157F174ACA26B6AE36560B84E7E325970D52A2591FBD2578D454D22E52F8CC52B7E644198FC4FCD3928E2924FBC64F3F5F586E4542A73948F02FA04DCE0FF9DF1141E2C5";
    n.FromString(szModulus,16);
    TEST("FromHEX", strcmp(szModulus, n.ToString(16))==0);
    if (bError)
    {
        printf("N=%s\n", szModulus);
        printf("n=%s\n", n.ToString(16));
    }
    //Public exponent
    e.FromString("65537",10);
    //Private exponent
    d.FromString("04f4aa4cfc77e16024107a5a046ac48f3471e664da419db2d02b201c31ecd8ff758086adc514bc2eac188b6c693c297542ad916b484f484710e27f54dd0e0de6c1c4b58e54064e9483e9957c9a66f5fa8a58fec97758e2778a3dc453093475f8a3dffdd1bb68ede240643a3d5a8fd71eff09bcbb362dd8f8ed9d8688067b5d89",16);

    TEST("RSA_N_Prime", !n.IsPrime());


    a.SetValue(9999);
    b.PowMod(a, e, n);
    c.PowMod(b, d, n);

    TEST("RSA_encrypt", b!=9999);
    TEST("RSA_decrypt", c==9999);

    p.FromString("f9805c758fce4a9502a6090b1d355869e3e8571a747429d3c5ca12347fa3f0b803a002960df03aa264728af0f2baff0ed4d479186069020cfead8210baf20b63");
    q.FromString("c3cb7489a2862898e2372f7866b43e94090fe5c36e43a7fd30a228662fe967f8e262b12e97c525150ce074f3c19172ff5ac2d782d99e6f824d0f6b3d3032f5b7");
    dp.FromString("09616a18816fa01e3a1b43fbc6fd5a75a0bbfb8a63167afc1b539d9b9bb0ee3bfce6e731fd142b202fe69e92b08d97495777259665098daa2f69169aca6c8f41");
    dq.FromString("77fc5ca463e6d746298b2c1a1ac6667b0dbaa2514b6746b150766f4f801907506c5b92bd3ce0e1c2aeab76c052653215eea6ecaf117198603f9d2d58c80ad2ad");
    qp.FromString("21e7230c187496bc72ea56e6516e45f0ed0ba434ca6a763caa75d6939ffb98cd326fd9be3267565d29f817a8535a39f2fed84de66e2551f0384f8fd3f628345f");

    c.PowModCRT(b, p, q, dp, dq, qp);
    TEST("RSA_decrypt", c==9999);

    a.Pow(2, 8000);
    b.Pow(3, 7000);
    c.Mul(a,b);
    e.FromString("1000000000000",10);
    d.Mod(c,e);
    TEST("BigMulHi", strncmp(c.ToString(10), "12267282015427807746869624803940836185908536859923312606641454087554", 68)==0);   
    if (bError)
        printf("c=%s\n", c.ToString(10));
        
    TEST("BigMulLo", strcmp(d.ToString(10), "699033829376")==0);    
    if (bError)
        printf("d=%s\n", d.ToString(10));

    if (verbose)
        printf("SUCCEEDED: %d\tFAILED: %d\n", nSucceed, nFailed);

    return nFailed;
}
