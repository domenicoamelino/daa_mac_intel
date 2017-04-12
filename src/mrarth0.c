
/***************************************************************************
                                                                           *
Copyright 2013 CertiVox UK Ltd.                                           *
                                                                           *
This file is part of CertiVox MIRACL Crypto SDK.                           *
                                                                           *
The CertiVox MIRACL Crypto SDK provides developers with an                 *
extensive and efficient set of cryptographic functions.                    *
For further information about its features and functionalities please      *
refer to http://www.certivox.com                                           *
                                                                           *
* The CertiVox MIRACL Crypto SDK is free software: you can                 *
  redistribute it and/or modify it under the terms of the                  *
  GNU Affero General Public License as published by the                    *
  Free Software Foundation, either version 3 of the License,               *
  or (at your option) any later version.                                   *
                                                                           *
* The CertiVox MIRACL Crypto SDK is distributed in the hope                *
  that it will be useful, but WITHOUT ANY WARRANTY; without even the       *
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. *
  See the GNU Affero General Public License for more details.              *
                                                                           *
* You should have received a copy of the GNU Affero General Public         *
  License along with CertiVox MIRACL Crypto SDK.                           *
  If not, see <http://www.gnu.org/licenses/>.                              *
                                                                           *
You can be released from the requirements of the license by purchasing     *
a commercial license. Buying such a license is mandatory as soon as you    *
develop commercial activities involving the CertiVox MIRACL Crypto SDK     *
without disclosing the source code of your own applications, or shipping   *
the CertiVox MIRACL Crypto SDK with a closed source product.               *
                                                                           *
***************************************************************************/
/*
 *   MIRACL arithmetic routines 0 - Add and subtract routines 
 *   mrarth0.c
 *
 */
#include "miracl.h"
#include <sys/time.h>

#include <mach/clock.h>
#include <mach/mach.h>


void mr_padd(_MIPD_ big x,big y,big z)
{ /*  add two  big numbers, z=x+y where *
   *  x and y are positive              */

	//struct timeval t1;
	//struct timeval t2;
	int buffer_1;
	int buffer_2;
	int buffer_3;
	buffer_1 = x->len;
	buffer_2 = y->len;

	if(buffer_1 > mr_padd_op_1_len) mr_padd_op_1_len = buffer_1;
	if(buffer_2 > mr_padd_op_2_len) mr_padd_op_2_len = buffer_2;


    double istante1 = mach_absolute_time( ) ;


    int i,lx,ly,lz,la;
    mr_small carry,psum;
    mr_small *gx,*gy,*gz; 
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    lx = (int)x->len;
    ly = (int)y->len;
    
    if (ly>lx)
    {
        lz=ly;
        la=lx;
        if (x!=z) copy(y,z); 
        else la=ly;  
    }
    else
    {
        lz=lx;
        la=ly;
        if (y!=z) copy(x,z);
        else la=lx;
    }
    carry=0;
    z->len=lz;

    //printf("MR_MIP->nib = %d \n",mr_mip->nib);
    gx=x->w; gy=y->w; gz=z->w;
    if (lz<mr_mip->nib || !mr_mip->check) z->len++;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0) 
    {
#endif
        for (i=0;i<la;i++)
        { /* add by columns to length of the smaller number */
            psum=gx[i]+gy[i]+carry;
            if (psum>gx[i]) carry=0;
            else if (psum<gx[i]) carry=1;
            gz[i]=psum;
        }
        for (;i<lz && carry>0;i++ )
        { /* add by columns to the length of larger number (if there is a carry) */
            psum=gx[i]+gy[i]+carry;
            if (psum>gx[i]) carry=0;
            else if (psum<gx[i]) carry=1;
            gz[i]=psum;
        }
        if (carry)
        { /* carry left over - possible overflow */
            if (mr_mip->check && i>=mr_mip->nib)
            {
                mr_berror(_MIPP_ MR_ERR_OVERFLOW);
                return;
            }
            gz[i]=carry;
        }
#ifndef MR_SIMPLE_BASE
    }
    else
    {
        for (i=0;i<la;i++)
        { /* add by columns */
            psum=gx[i]+gy[i]+carry;
            carry=0;
            if (psum>=mr_mip->base)
            { /* set carry */
                carry=1;
                psum-=mr_mip->base;
            }
            gz[i]=psum;
        }
        for (;i<lz && carry>0;i++)
        {
            psum=gx[i]+gy[i]+carry;
            carry=0;
            if (psum>=mr_mip->base)
            { /* set carry */
                carry=1;
                psum-=mr_mip->base;
            }
            gz[i]=psum;
        }
        if (carry)
        { /* carry left over - possible overflow */
            if (mr_mip->check && i>=mr_mip->nib)
            {
                mr_berror(_MIPP_ MR_ERR_OVERFLOW);
                return;
            }
            gz[i]=carry;
        }
    }
#endif
    if (gz[z->len-1]==0) z->len--;

    mrpadd_count++;
    double istante2 = mach_absolute_time( ) ;
        double buff = istante2-istante1;
        if(buff > mrpadd_time) mrpadd_time = buff;
    //printf("ex_time = %d \n",t2.tv_usec-t1.tv_usec);

     buffer_3 = z->len;
     if(buffer_3 > mr_padd_op_3_len) mr_padd_op_3_len = buffer_3;


}

void mr_psub(_MIPD_ big x,big y,big z)
{  /*  subtract two big numbers z=x-y      *
    *  where x and y are positive and x>y  */

	double istante1 = mach_absolute_time( ) ;

	int buffer_1;
	int buffer_2;
	int buffer_3;
	buffer_1 = x->len;
	buffer_2 = y->len;

	if(buffer_1 > mr_psub_op_1_len) mr_psub_op_1_len = buffer_1;
	if(buffer_2 > mr_psub_op_2_len) mr_psub_op_2_len = buffer_2;


    int i,lx,ly;
    mr_small borrow,pdiff;
    mr_small *gx,*gy,*gz;
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    lx = (int)x->len;
    ly = (int)y->len;
    if (ly>lx)
    {
        mr_berror(_MIPP_ MR_ERR_NEG_RESULT);
        return;
    }
    if (y!=z) copy(x,z);
    else ly=lx;
    z->len=lx;
    gx=x->w; gy=y->w; gz=z->w;
    borrow=0;
#ifndef MR_SIMPLE_BASE
    if (mr_mip->base==0)
    {
#endif    
        for (i=0;i<ly || borrow>0;i++)
        { /* subtract by columns */
            if (i>lx)
            {
                mr_berror(_MIPP_ MR_ERR_NEG_RESULT);
                return;
            }
            pdiff=gx[i]-gy[i]-borrow;
            if (pdiff<gx[i]) borrow=0;
            else if (pdiff>gx[i]) borrow=1;
            gz[i]=pdiff;
        }
#ifndef MR_SIMPLE_BASE
    }
    else for (i=0;i<ly || borrow>0;i++)
    { /* subtract by columns */
        if (i>lx)
        {
            mr_berror(_MIPP_ MR_ERR_NEG_RESULT);
            return;
        }
        pdiff=gy[i]+borrow;
        borrow=0;
        if (gx[i]>=pdiff) pdiff=gx[i]-pdiff;
        else
        { /* set borrow */
            pdiff=mr_mip->base+gx[i]-pdiff;
            borrow=1;
        }
        gz[i]=pdiff;
    }
#endif
    mr_lzero(z);

    double istante2 = mach_absolute_time( ) ;
        double buff = istante2-istante1;
        if(buff > mrpsub_time) mrpsub_time = buff;

    mrpsub_count++;

    buffer_3 = z->len;
    if(buffer_3 > mr_psub_op_3_len) mr_psub_op_3_len = buffer_3;
}

static void mr_select(_MIPD_ big x,int d,big y,big z)
{ /* perform required add or subtract operation */
    int sx,sy,sz,jf,xgty;
#ifdef MR_FLASH
    if (mr_notint(x) || mr_notint(y))
    {
        mr_berror(_MIPP_ MR_ERR_INT_OP);
        return;
    }
#endif
    sx=exsign(x);
    sy=exsign(y);
    sz=0;
    x->len&=MR_OBITS;  /* force operands to be positive */
    y->len&=MR_OBITS;
    xgty=mr_compare(x,y);
    jf=(1+sx)+(1+d*sy)/2;
    switch (jf)
    { /* branch according to signs of operands */
    case 0:
        if (xgty>=0)
            mr_padd(_MIPP_ x,y,z);
        else
            mr_padd(_MIPP_ y,x,z);
        sz=MINUS;
        break;
    case 1:
        if (xgty<=0)
        {
            mr_psub(_MIPP_ y,x,z);
            sz=PLUS;
        }
        else
        {
            mr_psub(_MIPP_ x,y,z);
            sz=MINUS;
        }
        break;
    case 2:
        if (xgty>=0)
        {
            mr_psub(_MIPP_ x,y,z);
            sz=PLUS;
        }
        else
        {
            mr_psub(_MIPP_ y,x,z);
            sz=MINUS;
        }
        break;
    case 3:
        if (xgty>=0)
            mr_padd(_MIPP_ x,y,z);
        else
            mr_padd(_MIPP_ y,x,z);
        sz=PLUS;
        break;
    }
    if (sz<0) z->len^=MR_MSBIT;         /* set sign of result         */
    if (x!=z && sx<0) x->len^=MR_MSBIT; /* restore signs to operands  */
    if (y!=z && y!=x && sy<0) y->len^=MR_MSBIT;
}

void add(_MIPD_ big x,big y,big z)
{  /* add two signed big numbers together z=x+y */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(27)

    mr_select(_MIPP_ x,PLUS,y,z);

    MR_OUT
}

void subtract(_MIPD_ big x,big y,big z)
{ /* subtract two big signed numbers z=x-y */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(28)

    mr_select(_MIPP_ x,MINUS,y,z);

    MR_OUT
}

void incr(_MIPD_ big x,int n,big z)
{  /* add int to big number: z=x+n */
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(7)

    convert(_MIPP_ n,mr_mip->w0);
    mr_select(_MIPP_ x,PLUS,mr_mip->w0,z);

    MR_OUT
}

void decr(_MIPD_ big x,int n,big z)
{  /* subtract int from big number: z=x-n */   
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    if (mr_mip->ERNUM) return;

    MR_IN(8)

    convert(_MIPP_ n,mr_mip->w0);
    mr_select(_MIPP_ x,MINUS,mr_mip->w0,z);

    MR_OUT
}

