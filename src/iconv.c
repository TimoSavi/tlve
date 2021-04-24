/* 
   tlve - A program to parse tag-length-value structures and print them in different formats

   Copyright (C) 2009 Timo Savinen

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  
*/ 

#include "tlve.h"
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif

/* conversion handle */
#ifdef HAVE_ICONV_T
static iconv_t *cd = (iconv_t) -1;
#endif

/* previous used from/to pair 
   these are saved assuming that the next conversion will use the same pair

   if the same pair id not used, a new handle must be open
 */
static char *prev_from = "--UNKNOWN--";
static char *prev_to = "--UNKNOWN--";

/* buffer for conversion */
static char *outb = NULL;
static size_t outb_size = 0;

/* make conversion return to pointer to converted value */
char *
make_iconv(char *data,char *from,char *to)
{
#if defined(HAVE_ICONV_OPEN) && defined(HAVE_ICONV_T)
    size_t data_size = strlen(data);
    size_t out_size = data_size * 4;   // make 4 times larger for wide characters
    char *optr;
    size_t left;

    if(outb == NULL)
    {
        outb_size = out_size;
        outb = xmalloc(outb_size);
    } else if(out_size > outb_size)
    {
        outb_size = out_size;             
        outb = xrealloc(outb,outb_size);
    }

    if(cd == (iconv_t) -1 || strcmp(from,prev_from) != 0 || strcmp(to,prev_to) != 0)
    {
        if(cd != (iconv_t) -1) iconv_close(cd);
        cd = iconv_open(to,from);
        if(cd == (iconv_t) -1) 
        {
            char msg[100];
            sprintf(msg,"%s -> %s",from,to);
            panic("Character Set Conversion not possible",strerror(errno),msg);
        }
    }

    left = outb_size;
    optr = outb;

    iconv(cd,NULL,NULL,&optr,&left);

    if(iconv(cd,&data,&data_size,&optr,&left) == (size_t) -1)
    {
        char msg[100];
        sprintf(msg,"%s -> %s",from,to);
        panic("Character Set Conversion not possible",strerror(errno),msg);
    }

    outb[optr - outb] = 0;

    prev_from = from;
    prev_to = to;

    return outb;
#else
    return data;
#endif
}
