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


#define B_UNIVERSAL 0x00
#define B_UNIVERSAL_S "U-"
#define B_APPLICATION 0x40
#define B_APPLICATION_S "A-"
#define B_CONTENT 0x80
#define B_CONTENT_S "C-"
#define B_PRIVATE 0xc0
#define B_PRIVATE_S "P-"
#define B_CLASS_MASK 0xc0

#define B_CONSTRUCTED 0x20

#define B_LONG_TAG 0x1f
#define B_LONG_TAG_MASK 0x7f

#define B_LAST_TAG 0x80

#define B_LENGTH_LONG_MASK 0x80
#define B_LENGTH_MASK 0x7f
#define B_LENGTH_INDEFINITE 0x80

/* read a BER tag, format tag as X-nnn, where X is the tag class (U,A,C or P) and nnn is the tag number
   as decimal integer

   returns the count of octets consumed, 0 in case of error

   writes constructor type (T_CONSTRUCTED or T_PRIMITIVE) to type
   and constructed block type to constructor_type (T_DEFINITE or T_INDEFINITE)

   writes tag to 'tag'.
 */
size_t 
read_ber_tag(char *tag,TYPE *type,TYPE *constructor_type)
{
    unsigned long long tag_value = (unsigned long long) 0;
    register BUFFER *p;
    BUFFER loctet;
    
    p = buffer_data();

    if(!buffer_address_safe(p)) return (size_t) 0;             
    
    loctet = *p;

    tag[0] = 0;

    switch(loctet & B_CLASS_MASK)
    {
        case B_UNIVERSAL:
            strcpy(tag,B_UNIVERSAL_S);
            break;
        case B_APPLICATION:
            strcpy(tag,B_APPLICATION_S);
            break;
        case B_CONTENT:
            strcpy(tag,B_CONTENT_S);
            break;
        case B_PRIVATE:
            strcpy(tag,B_PRIVATE_S);
            break;
    }


    if((loctet & B_LONG_TAG) == B_LONG_TAG)
    {
        do
        {
            p++;
            if(!buffer_address_safe(p)) return (size_t) 0;
            tag_value = (tag_value << 7) | ((BUFFER) *p & B_LONG_TAG_MASK);
        } while(*p & B_LAST_TAG);
    } else
    {
        tag_value = loctet & B_LONG_TAG;
    }

    if(!buffer_address_safe(p + (size_t) 1)) return (size_t) 0;  // there should be the length

    if(loctet & B_CONSTRUCTED)
    {
        *type = T_CONSTRUCTED;
    } else
    {
        if(loctet == (BUFFER) 0)   // in BER enf of content is marked with tag value zero
        {
            if(*(buffer_data() + (size_t) 1) == (BUFFER) 0)
            {
                *type = T_EOC;
            } else
            {
                return (size_t) 0;        // non BER tag+length
            }
        } else
        {
            *type = T_PRIMITIVE;
        }
    }
    
    /* Note! if the style (X-) of ber tag is changed, this must also be changed (the length of the prefix) */
    sprintf(&tag[2],"%llu",tag_value);

    /* peek the first byte of the length */
    if(p[1] == B_LENGTH_INDEFINITE)
    {
        *constructor_type = T_INDEFINITE;
    } else
    {
        *constructor_type = T_DEFINITE;
    }

    return p - buffer_data() + (size_t) 1; 
}

/* read BER length 

   return number of octets consumed from the buffer_data()

   write length to 'length'
   'tag_consumed' is the number of octets to skip in buffer before reading
 */
size_t 
read_ber_length(FILE_OFFSET *length,size_t tag_consumed)
{
    register BUFFER *p;
    unsigned long long l = (unsigned long long) 0;
    size_t len_bytes;

    p = buffer_data() + tag_consumed;

    if(!buffer_address_safe(p)) return (size_t) 0;

    if(*p != B_LENGTH_INDEFINITE)
    {
        if(*p & B_LENGTH_LONG_MASK)         // long form
        {
            len_bytes = (BUFFER) *p & B_LENGTH_MASK;

            if(!buffer_address_safe(p + len_bytes)) return (size_t) 0;

            while(len_bytes--)
            {
                p++;
                l = (l << 8) | (BUFFER) *p;
            }
        } else
        {
            l = (BUFFER) *p & B_LENGTH_MASK;
        }
    }

    *length = (FILE_OFFSET) l;

    return p - buffer_data() + (size_t) 1;
}

/* format a ber bit string
 */
void
format_ber_bit_string(char *target,BUFFER *source, size_t length)
{
    BUFFER mask;
    int use_last;
    register int i;
    int j;

    j = 0;

    if(length > (size_t) 1)
    {
        i = 1;
        use_last = 8 - (int) *source;

        while(i < length - (size_t) 1)
        {
            mask=0x80;
            do
            {
                target[j++] = source[i] & mask ? '1' : '0';
                mask = mask >> 1;
            } while(mask);
            target[j++] = ' ';
            i++;
        }

        if(use_last >= 1 && use_last <= 8)
        {
            mask=0x80;
            do
            {
                target[j++] = source[i] & mask ? '1' : '0';
                mask = mask >> 1;
            } while(mask && --use_last);
        }
    }

    target[j] = 0;
}


/* format BER Oid value as a string
 */
void
format_oid(char *target,BUFFER *source, size_t length)
{
    unsigned int x,y;
    unsigned long int value;
    int i;

    target[0] = 0;

    if(!length) return;

    if(*source < 40)
    {
        x = (unsigned int) 0;
        y = (unsigned int) *source;
    } else if(*source >= 40 && *source < 80)
    {
        x = (unsigned int) 1;
        y = (unsigned int) *source - 40;
    } else
    {
        x = (unsigned int) 2;
        y = (unsigned int) *source - 80;
    }

    sprintf(target,"%u %u",x,y);

    i = 1;
    value = (unsigned long int) 0;

    while(i < length)
    {
        value = (value << 7) | ((BUFFER) source[i] & 0x7f);
        if(!(source[i] & 0x80))
        {
            sprintf(target+strlen(target)," %lu",value);
            value = (unsigned long int) 0;
        }
        i++;
    }
} 






