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

#ifdef TM_IN_SYS_TIME
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#define TLV_HASH_SIZE 1024

struct tlvlist *tlvhash[TLV_HASH_SIZE];

/* level array */
static struct level levels[MAX_LEVEL + FIRST_LEVEL];

/* current level index for levels array, starts from 1 to be the same as human count */
static int current_level;


/* static item, which will be populated and returned by functions in this file */
static struct tlvitem new;

/* for printing hex dump */
static char hex_to_ascii_low[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static char hex_to_ascii_cap[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
static char *hex_to_ascii;

/* calculate hash for a string 
   hash is between 0...TLV_HASH_SIZE - 1
 */
static size_t
hash(char *str)
{
    register unsigned long h = 5381;
    int c;

    while ((c = *str++) != 0)
    {
        h = ((h << 5) + h) + c;
    }

    return (size_t) (h % TLV_HASH_SIZE);
}


/* return current level */
int
get_current_level()
{
    return current_level;
}

static TYPE
get_level_form()
{ 
    return levels[current_level].form;
}

/* Initializes the current level, before reading any data */
static void 
init_level()
{
    current_level = FIRST_LEVEL;
    levels[current_level].size = (FILE_OFFSET) 0;
    levels[current_level].content_tl = structure.content_tl;
    levels[current_level].form = T_UNKNOWN;
}

/* update active levels */
static void
update_levels(size_t size)
{
    register int i = FIRST_LEVEL;

    while(i <= current_level)
    {
        levels[i].size -= (FILE_OFFSET) size;
        i++;
    }
}

/* checks is there is size lefth for definite element
 */
static int
enough_size(size_t size)
{
    if(levels[current_level].form == T_DEFINITE)
    {
        return (levels[current_level].size >= size);
    }
    return 1;
}

/* a  constructor has been found make go deeper one level 
 */
static void
level_down(FILE_OFFSET size,struct tlvdef *tlv,TYPE form)
{
    if(!enough_size(size)) buffer_error("Constructed element is larger than space left in parent element",&new);
    current_level++;
    if(current_level == MAX_LEVEL + FIRST_LEVEL) panic("Maximun number of levels reached",NULL,NULL);
    levels[current_level].size = size;
    levels[current_level].form = form;
    if(tlv != NULL && (tlv->content_tl != NULL))              // use tl from tlv if defined
    {
        levels[current_level].content_tl = tlv->content_tl;
    } else                                                    // else inherit from previous level
    {
        levels[current_level].content_tl = levels[current_level - 1].content_tl;
    }
}


/* a  end of level has been found make go up one level 
 */
static void
level_up()
{
    if(current_level > FIRST_LEVEL) current_level--;
}

/* return the remaining bytes of current level */
static FILE_OFFSET
level_current_size()
{
    return levels[current_level].size;
}

/* return the tl info for current level, in first level
   use tl from structure, and in following levels, use the
   info from constructor from previous level if defined, else structure level info
*/
static struct tldef *
current_tl()
{
    return levels[current_level].content_tl;
}

/* return the bytes from the start of the buffer consumed by the object, return 0 if not enough data,
   or the terminator is not found

   bytes contains also the terminator in case of terminated data

   Do not use offset in bo, use the parameter instead
*/
static size_t
consumed_bo(struct bo *bo, size_t offset)
{
    size_t consumed;
    int term_pos;

    if(bo->use_terminator)
    {
        term_pos = search_buffer_c(bo->terminator,offset);   // try to find the terminator in buffer
        if(term_pos == -1) return 0;
        consumed = (size_t) term_pos + (size_t) 1;           // term_pos contains the offset also
    } else
    {
        consumed = offset + bo->length;
        if(!buffer_address_safe(buffer_data() + consumed - (size_t) 1)) return 0; 
    }
    return consumed;
}


/* read signed big endian int from input data
   assuming that negative numbers are presented in two's complement
 */
static long long int 
read_int_be(size_t offset,size_t length,unsigned long int mask,int shift)
{
    long long int result = 0;
    int is_negative;
    register BUFFER c,*p;
    size_t i = 0;

    p = buffer_data() + offset;

    is_negative = *p & 0x80;         // check the first bit

    if(is_negative)                        // invert all bits and  add 1 to get absolute value 
    {
        while(i < length)
        {
            c = *p;
            c = ~c;
            result = (result << 8) | c;   
            i++;
            p++;
        }
        result++;                                               // add one,  
        result = -result;                                       // make it negative
    } else
    {
        while(i < length)
        {
            c = *p;
            result = (result << 8) | c;
            i++;
            p++;
        }
    }

    if(mask) result = result & mask;
    result = shift > 0 ? result << shift : result >> -shift;

    return result;
}

/* read unsigned big endian int from input data
 */
static unsigned long long int 
read_uint_be(size_t offset,size_t length,unsigned long int mask,int shift)
{
    unsigned long long int result = 0;
    register BUFFER c,*p;
    size_t i = 0;

    p = buffer_data() + offset;

    while(i < length)
    {
        c = *p;
        result = (result << 8) | c;
        i++;
        p++;
    }

    if(mask) result = result & mask;
    result = shift > 0 ? result << shift : result >> -shift;

    return result;
}


/* read signed little endian int from input data
   assuming that negative numbers are presented in two's complement
 */
static long long int 
read_int_le(size_t offset,size_t length,unsigned long int mask,int shift)
{
    long long int result = 0;
    int is_negative;
    register BUFFER c,*p;
    size_t i = length;

    p = buffer_data() + offset + length - (size_t) 1;

    is_negative = *p & 0x80;         // check the MS bit

    if(is_negative)                        // invert all bits and  add 1 to get absolute value 
    {
        while(i)
        {
            c = *p;
            c = ~c;
            result = (result << 8) | c;   
            i--;
            p--;
        }
        result++;                                               // add one,  
        result = -result;                                       // make it negative
    } else
    {
        while(i)
        {
            c = *p;
            result = (result << 8) | c;
            i--;
            p--;
        }
    }

    if(mask) result = result & mask;
    result = shift > 0 ? result << shift : result >> -shift;

    return result;
}


/* read unsigned little endian int from input data
 */
static unsigned long long int 
read_uint_le(size_t offset,size_t length,unsigned long int mask,int shift)
{
    unsigned long long int result = 0;
    register BUFFER c,*p;
    size_t i = length;

    p = buffer_data() + offset + length - (size_t) 1;

    while(i)
    {
        c = *p;
        result = (result << 8) | c;
        i--;
        p--;
    }

    if(mask) result = result & mask;
    result = shift > 0 ? result << shift : result >> -shift;

    return result;
}



/* Format a HEX string, format will be nnnn..., where nn is the
   hex value of octet
 */
static void
format_hex_string(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        *p++ = hex_to_ascii[(source[i] >> 4) & 0x0f];
        *p++ = hex_to_ascii[source[i] & 0x0f];
        i++;
    }
    *p = 0;
}

/* Format a HEX string with nibbles reversed, format will be nnnn..., where nn is the
   hex value of octet
*/
static void
format_hexs_string(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        *p++ = hex_to_ascii[source[i] & 0x0f];
        *p++ = hex_to_ascii[(source[i] >> 4) & 0x0f];
        i++;
    }
    *p = 0;
}

/* Format a DEC string, format will be n n n where n is the
   decimal value of octet
 */
static void
format_dec_string(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        sprintf(p,i < length - 1 ? "%d " : "%d",(int) source[i]);
        while(*p) p++;
        i++;
    }
}


/* Format escaped, non printabled characters are printed as \xnn
 */
static void
format_escaped(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        if(isprint(source[i]))
        {
            *p++ = source[i];
        } else
        {
            *p++ = '\\';
            *p++ = 'x';
            *p++ = hex_to_ascii[(source[i] >> 4) & 0x0f];
            *p++ = hex_to_ascii[source[i] & 0x0f];
        }
        i++;
    }
    *p = 0;
}

/* Format a BCD string, format will be nnnn..., where nn is the
   hex value of the octet
   
   value 'f' terminates the string
 */
static void
format_bcd_string(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        *p = hex_to_ascii[(source[i] >> 4) & 0x0f];
        if(*p == hex_to_ascii[0x0f]) 
        {
            *p = 0;
            return;
        }
        p++;
        *p = hex_to_ascii[source[i] & 0x0f];
        if(*p == hex_to_ascii[0x0f]) 
        {
            *p = 0;
            return;
        }
        p++;
        i++;
    }
    *p = 0;
}

/* Format a swapped BCD string, format will be nnnn..., where nn is the
   hex value of the octet
   
   value 'f' terminates the string
 */
static void
format_bcds_string(char *target,BUFFER *source, size_t length)
{
    size_t i = 0;
    register char *p = target;

    while(i < length)
    {
        *p = hex_to_ascii[source[i] & 0x0f];
        if(*p == hex_to_ascii[0x0f]) 
        {
            *p = 0;
            return;
        }
        p++;
        *p = hex_to_ascii[(source[i] >> 4) & 0x0f];
        if(*p == hex_to_ascii[0x0f]) 
        {
            *p = 0;
            return;
        }
        p++;
        i++;
    }
    *p = 0;
}
/* read the tag, return the total octets consumed from the beginning of the current read point.
   Format 'tag' as decimal number in case of binary data
   
   if tlv type (constructed, primitive or end of content) can be identified, write it to 'type'. This applies BER only
   if constructor type (definitive or indefinite) can be identified, write it to 'constructortype'. This applies BER only
 */
size_t
read_tag(struct bo *bo,char *tag,TYPE *type,TYPE *form)
{
    size_t consumed;
    size_t length;
    
    if(bo->type != T_BER)
    {
        consumed = consumed_bo(bo,bo->offset);
        if(!consumed) return consumed;

        /* data length without the possible terminator */
        length = consumed - bo->offset - (size_t) (bo->use_terminator ? 1 : 0);
    }
     
    /* now it is sure that we have enough data in buffer for the tag */

    switch(bo->type)
    {
        case T_INTBE:
            sprintf(tag,"%lli",read_int_be(bo->offset,length,bo->mask,bo->shift));
            break;
        case T_UINTBE:
            sprintf(tag,"%llu",read_uint_be(bo->offset,length,bo->mask,bo->shift));
            break;
        case T_INTLE:
            sprintf(tag,"%lli",read_int_le(bo->offset,length,bo->mask,bo->shift));
            break;
        case T_UINTLE:
            sprintf(tag,"%llu",read_uint_le(bo->offset,length,bo->mask,bo->shift));
            break;
        case T_STRING:
            memcpy(tag,buffer_data() + bo->offset,length);
            tag[length] = 0;
            break;
        case T_HEX:
            format_hex_string(tag,buffer_data() + bo->offset,length);
            break;
        case T_BER:
            consumed = read_ber_tag(tag,type,form);
            break;
    }

    return consumed;
}

/* read the type, return the total octets consumed from the beginning of the current read point.
   Format type as decimal number in case of binary data
*/
size_t
read_type(struct bo *bo,char *type,size_t tag_consumed)
{
    size_t consumed;
    size_t length;
    size_t offset;

    if(bo == NULL) return 0;          // No type
    
    /* default is to read type after the tag, unless length offset is specified */
    offset = bo->use_offset ? bo->offset : tag_consumed;

    consumed = consumed_bo(bo,offset);
    
    if(!consumed && bo->type != T_BER) return consumed;

    /* data length without the possible terminator */
    length = consumed - offset - (size_t) (bo->use_terminator ? 1 : 0);
    
    /* now it is sure that we have enough data in buffer for the tag */

    type[0] = 0;

    switch(bo->type)
    {
        case T_INTBE:
            sprintf(type,"%lli",read_int_be(offset,length,bo->mask,bo->shift));
            break;
        case T_UINTBE:
            sprintf(type,"%llu",read_uint_be(offset,length,bo->mask,bo->shift));
            break;
        case T_INTLE:
            sprintf(type,"%lli",read_int_le(offset,length,bo->mask,bo->shift));
            break;
        case T_UINTLE:
            sprintf(type,"%llu",read_uint_le(offset,length,bo->mask,bo->shift));
            break;
        case T_STRING:
            memcpy(type,buffer_data() + offset,length);
            type[length] = 0;
            break;
        case T_HEX:
            format_hex_string(type,buffer_data() + offset,length);
            break;
    }

    return consumed;
}
/* read the length, return the total octets consumed from the beginning of the current read point.
   write length to parameter vlength

   Read the length after the tag (use tag_consumed), unless offset is specified in bo-data. Offset is relative to
   the start of the whole tlv-data
   
 */
size_t
read_length(struct bo *bo,FILE_OFFSET *vlength,size_t tag_consumed)
{
    size_t consumed;
    size_t length;
    size_t offset;
    char ascii_len[128];

    if(bo == NULL) return 0;        // length is not even defined....

    /* default is to read length after the tag, unless length offset is specified */
    offset = bo->use_offset ? bo->offset : tag_consumed;

    consumed = consumed_bo(bo,offset);
    
    if(!consumed && bo->type != T_BER) return consumed;

    /* data length without the possible terminator */
    length = consumed - offset - (size_t) (bo->use_terminator ? 1 : 0);
     
    /* now it is sure that we have enough data in buffer for the length */

    switch(bo->type)
    {
        case T_INTBE:
        case T_UINTBE:
            *vlength = (FILE_OFFSET) read_uint_be(offset,length,bo->mask,bo->shift);
            break;
        case T_INTLE:
        case T_UINTLE:
            *vlength = (FILE_OFFSET) read_uint_le(offset,length,bo->mask,bo->shift);
            break;
        case T_STRING:
        case T_HEX:
            memcpy(ascii_len,buffer_data() + offset,length);
            ascii_len[length] = 0;
            *vlength = (FILE_OFFSET) atoll(ascii_len);
            break;
        case T_BER:
            consumed = read_ber_length(vlength,tag_consumed);
            break;
    }

    return consumed;
}

/* read buffer forward and update the levels */
void
tl_buffer_read(size_t size)
{
    buffer_read(size);
    update_levels(size);
}

/* skip filler strings in buffer*/
/* returns true if skipped, if not skipped returns false */
static int
skip_fillers()
{
    int done = 0;
    int ret = 0;

    if(structure.filler_length)
    {
        do
        {
            if(buffer(B_NEEDED,structure.filler_length))
            {
                if(memcmp(structure.filler_string,buffer_data(),structure.filler_length) == 0)
                {
                    tl_buffer_read(structure.filler_length);
                    ret = 1;
                } else
                {
                    done = 1;
                }
            } else
            {
                done = 1;
            }
        } while(!done);
    }
    return ret;
}

/* add item to hash list 
 */
static void 
add_hash_list(size_t h, struct tlvdef *item)
{
    struct tlvlist *list = tlvhash[h];

    if(list == NULL)
    {
        list = xmalloc(sizeof(struct tlvlist));
        list->next = NULL;
        tlvhash[h] = list;
    } else
    {
        if(list->tlv == item) return;       // do not add doubles
        while(list->next != NULL) 
        {
            list = list->next;
            if(list->tlv == item) return;   // do not add doubles
        } 
        list->next = xmalloc(sizeof(struct tlvlist));
        list = list->next;
        list->next = NULL;
    }
    list->tlv = item;
}

/* searches a tlvlist for a tag
   returns pointer tlvdef if found, if not found returns NULL

 */
static struct tlvdef *
search_tlvlist(struct tlvlist *list,char *tag,TYPE tag_type)
{
    long long int int_tag = 0;
    unsigned long long int uint_tag = 0;
    register struct tlvdef *retval = NULL,*p;

    if(list == NULL) return NULL;

    switch(tag_type)
    {
        case T_INTBE:
        case T_INTLE:
            int_tag = (long long int) strtoll(tag,NULL,10);
            break;
        case T_UINTBE:
        case T_UINTLE:
            uint_tag = (unsigned long long int) strtoull(tag,NULL,10);
            break;
    }


    while(list != NULL && retval == NULL)
    {
        p = list->tlv;
        if(p->stag == p->etag)  // not range search
        {
            switch(tag_type)
            {
                case T_INTBE:
                case T_INTLE:
                    if(int_tag == (long long int) strtoll(p->stag,NULL,10)) retval = p;
                    break;
                case T_UINTBE:
                case T_UINTLE:
                    if(uint_tag == (unsigned long long int) strtoull(p->stag,NULL,10)) retval = p;
                    break;
                case T_STRING:
                case T_HEX:
                case T_BER:
                    if(strcmp(tag,p->stag) == 0) retval = p;
                    break;
            }
        } else                 // range search
        {
            switch(tag_type)
            {
                case T_INTBE:
                case T_INTLE:
                    if(int_tag >= (long long int) strtoll(p->stag,NULL,10) && 
                       int_tag <= (long long int) strtoll(p->etag,NULL,10)) retval = p;
                    break;
                case T_UINTBE:
                case T_UINTLE:
                    if(uint_tag >= (unsigned long long int) strtoull(p->stag,NULL,10) && 
                       uint_tag <= (unsigned long long int) strtoull(p->etag,NULL,10)) retval = p;
                    break;
                case T_STRING:
                case T_HEX:
                case T_BER:
                    if(strcmp(tag,p->stag) >= 0 && strcmp(tag,p->etag) <= 0) retval = p;
                    break;
            }
        }

        /* check if the path is defined and compare to the current path */
        if(retval != NULL && retval->path != NULL) 
        {
            /* add all path-cases to hash to be sure that all are scanned in next run */
            add_hash_list(hash(tag),retval);

            if(retval->path[0] == '*')    // Compare only trailer of the path
            {
                register int position;

                position = strlen(print_list_path()) - strlen(retval->path) + 1;
                if(position >= 0)
                {
                    if(STRCMP(&retval->path[1],&print_list_path()[position]) != 0) retval = NULL;
                } else
                {
                    retval = NULL;
                }
            } else
            {
                if(STRCMP(retval->path,print_list_path()) != 0) retval = NULL;
            }
        }
        list = list->next;
    }
    return retval;
}


static struct tlvdef *
find_tlvdef(char *tag,TYPE tag_type)
{
    size_t tlv_hash;
    register struct tlvdef *retval = NULL;

    tlv_hash = hash(tag);

    retval = search_tlvlist(tlvhash[tlv_hash],tag,tag_type);

    if(retval == NULL)
    {
        if((retval = search_tlvlist(structure.tlv,tag,tag_type)) != NULL)
        {
            add_hash_list(tlv_hash,retval);
        }
    }
    
    return retval;
}



/* format unix epoch time using strftime */
/* strftime format is recognized when the format string starts with + (local time) or
   ++ (utc)

   make string length zero if not formatted
 */
static void
format_epoch(time_t t, char *format,char *buffer, size_t buffer_size)
{
#ifdef HAVE_STRFTIME
    struct tm *ts;
    char *f;

    if(format[0] == '+' && format[1] == '+')
    {
        ts = gmtime(&t);
        f = format + 2;
    } else if(format[0] == '+')
    {
        ts = localtime(&t);
        f = format + 1;
    } else
    {
        buffer[0] = 0;
        return;
    }

    strftime(buffer,buffer_size,f,ts);
#else
    buffer[0] = 0;
#endif
}

/* format a bit string, in case of ber, use ber related formatter
 */
static void
format_bit_string(char *target,BUFFER *source, size_t length,TYPE tag_type)
{
    BUFFER mask;
    register int i,j;

    if(tag_type == T_BER)
    {
        format_ber_bit_string(target,source,length);
    } else
    {
        i = 0;
        j = 0;
        while(i < length)
        {
            mask=0x80;
            do
            {
                target[j++] = source[i] & mask ? '1' : '0';
                mask = mask >> 1;
            } while(mask);
            i++;
            if(i < length) target[j++] = ' ';
        }
        target[j] = 0;
    }
}



static TYPE
search_type_mapping(char *type,struct type_mappings *types)
{
    register struct type_map *m = types->mappings;

    while(m != NULL)
    {
        if(strcmp(type,m->source_type) == 0) return m->valuetype;
        m = m->next;
    }
    return T_UNKNOWN;
}

/* read the value part of the tlv triplet, write it to tlvitem->converted_value
   return the consumed bytes for the value
 */
static size_t
read_value(struct tlvitem *tlvi)
{
   int term_pos = -1;
   size_t consumed;
   size_t length,length_needed;
   TYPE type;
   char *format;

   if(tlvi->form == T_INDEFINITE)
   {
       term_pos = search_buffer_s(tlvi->tl->value_terminator,tlvi->tl->value_terminator_len,(size_t) 0);
       if(term_pos == -1) buffer_error("Terminating string was not found for a terminated value",tlvi);
       length = term_pos;
       consumed = term_pos + tlvi->tl->value_terminator_len;
   } else
   {
       consumed = tlvi->length;
       length = tlvi->length;
   }

   if(!buffer(B_NEEDED,consumed))
   {
       buffer_error("File does not contain enough data to read a value",tlvi);
   }


   if(tlvi->tlv == NULL)
   {
       type = T_UNKNOWN;               // this is the default value type
   } else
   {
       type = tlvi->tlv->valuetype;

       if(tlvi->tlv->length_adjust > 0)
       {
           length += tlvi->tlv->length_adjust;  // adjust the length 
       } else if(tlvi->tlv->length_adjust < 0)
       {
           if((size_t) abs(tlvi->tlv->length_adjust) <= length)
           {
               length += tlvi->tlv->length_adjust;
           }
       }
   }

   if(type == T_UNKNOWN && tlvi->tl->types != NULL)
   {
       type = search_type_mapping(tlvi->type,tlvi->tl->types);
   }

   /* check the integer length, if length is > the length of long long int then print as hex string */
   switch(type)
   {
       case T_INTBE:
       case T_INTLE:
           if (length > sizeof(long long int)) type=T_HEX;
           break;
       case T_UINTBE:
       case T_UINTLE:
           if (length > sizeof(unsigned long long int)) type=T_HEX;
           break;

   }

   /* check how must data should be reserved for converted value */
   switch(type)
   {
       case T_INTBE:
       case T_INTLE:
           format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%lli";
           length_needed = 32;     // 32 enough for integer in ascii ???
            break;
        case T_UINTBE:
        case T_UINTLE:
            format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%llu";
            length_needed = 126;   // 126 to format possible epoch time
            break;
        case T_STRING:
            format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%s";
            length_needed = length + 1;     
            break;
        case T_HEX:
        case T_HEXS:
            format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%s";
            length_needed = (2 * length) + 1;     
            break;
        case T_ESCAPED:
        case T_UNKNOWN:
        case T_DEC:
            format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%s";
            length_needed = (4 * length) + 1;
            break;
        case T_BCD:
        case T_BCDS:
            format = (tlvi->tlv != NULL && (tlvi->tlv->format != NULL)) ? tlvi->tlv->format : "%s";
            length_needed = (2 * length) + 1;     
            break;
        case T_BITSTRING:
            length_needed = (9 * length) + 1;   // 9 because one space
            break;
        case T_OID:
            length_needed = (8 * length) + 1;
            break;
    }

    

    if(tlvi->converted_value == NULL)
    {
        tlvi->converted_value_len = length_needed;
        tlvi->converted_value = xmalloc(tlvi->converted_value_len);
    } else
    {
        if(length_needed > tlvi->converted_value_len)
        {
            tlvi->converted_value_len = length_needed;
            tlvi->converted_value = xrealloc(tlvi->converted_value,tlvi->converted_value_len);
        }
    }

    switch(type)
    {
        case T_INTBE:
            sprintf(tlvi->converted_value,format,read_int_be(0,length,0,0));
            break;
        case T_INTLE:
            sprintf(tlvi->converted_value,format,read_int_le(0,length,0,0));
            break;
        case T_UINTBE:
            format_epoch((time_t) read_uint_be(0,length,0,0),format,tlvi->converted_value,tlvi->converted_value_len);
            if(!*tlvi->converted_value) sprintf(tlvi->converted_value,format,read_uint_be(0,length,0,0));
            break;
        case T_UINTLE:
            format_epoch((time_t) read_uint_be(0,length,0,0),format,tlvi->converted_value,tlvi->converted_value_len);
            if(!*tlvi->converted_value) sprintf(tlvi->converted_value,format,read_uint_be(0,length,0,0));
            break;
        case T_STRING:
            memcpy(tlvi->converted_value,buffer_data(),length);
            tlvi->converted_value[length] = 0;
            break;
        case T_HEX:
            format_hex_string(tlvi->converted_value,buffer_data(),length);
            break;
        case T_HEXS:
            format_hexs_string(tlvi->converted_value,buffer_data(),length);
            break;
        case T_DEC:
            format_dec_string(tlvi->converted_value,buffer_data(),length);
            break;
        case T_ESCAPED:
        case T_UNKNOWN:
            format_escaped(tlvi->converted_value,buffer_data(),length);
            break;
        case T_BCD:
            format_bcd_string(tlvi->converted_value,buffer_data(),length);
            break;
        case T_BCDS:
            format_bcds_string(tlvi->converted_value,buffer_data(),length);
            break;
        case T_BITSTRING:
            format_bit_string(tlvi->converted_value,buffer_data(),length,tlvi->tl->tag->type);
            break;
        case T_OID:
            format_oid(tlvi->converted_value,buffer_data(),length);
            break;
        default:
            tlvi->converted_value[0] = 0;
            break;
    }

    return consumed;
}

/* read tag-length pair, return the bytes consumed for the pair
   if tag cannot be read return 0

   write information to *i
 */
static size_t
read_tl(struct tlvitem *i)
{
    size_t tag_consumed;
    size_t type_consumed;
    size_t len_consumed;
    size_t consumed_now;

    tag_consumed = read_tag(i->tl->tag,i->tag,&i->tlv_type,&i->form);

    if(!tag_consumed) return (size_t) 0;
    consumed_now = tag_consumed;

    type_consumed = read_type(i->tl->type,i->type,consumed_now);

    if(i->tl->type != NULL && !type_consumed) return (size_t) 0;

    if(type_consumed > consumed_now) consumed_now = type_consumed;

    len_consumed = read_length(i->tl->len,&i->length,consumed_now);

    if(i->tl->len != NULL && !len_consumed) return (size_t) 0;

    i->raw_tl_length = consumed_now > len_consumed ? consumed_now : len_consumed;  // init length which ever is longer tag,type length;

    if(i->tl->tl_included) i->length -= i->raw_tl_length;                // if tl-part is included in length, remove it from value length

    return i->raw_tl_length;
}

/* checks if the current content is actually a constructed item
   this is chekked by read tag and length from the begining 

   if tag and length are found AND the length + bytes consumed for tag/length
   are the same as the content size then we may have a constructed item
*/
static int
maybe_constructed(TYPE tag_type,char *tag,FILE_OFFSET *length)
{
    struct tlvitem dummy;
    int result;

    if(!*length) return 0;

    dummy.level = current_level;
    dummy.tlv_type = T_UNKNOWN;                    
    dummy.file_offset = file_offset();
    dummy.total_offset = total_offset();
    dummy.tl = current_tl();
    dummy.form = dummy.tl->form;
    dummy.raw_tl = buffer_data();

    /* A hack for BER BIT STRING tag (U-3), this is stupid thing in ASN.1 (IMHO) */

    if(tag_type == T_BER && strcmp(tag,"U-3") == 0)
    {
        buffer_ahead();             // skip first BIT STRING byte
        result = read_tl(&dummy);
        buffer_back();
        if(result && (FILE_OFFSET) (dummy.raw_tl_length + dummy.length + 1) == *length)
        {
            tl_buffer_read(1);             //  move one byte to forward to read constructed element
            (*length)--;                     //  and remove the byte from the elements length, argh...
            return 1;
        }
    } else if(read_tl(&dummy))
    {
        if((FILE_OFFSET) (dummy.raw_tl_length + dummy.length) == *length) return 1;
    }

    return 0;
}


/* parse one tlv triplet, return pointer the tlvitem if parse ok, NULL if end of file
   write tag, length and actual value to tlvitem structure 'new'
*/
struct tlvitem *
parse_tlv()
{
    buffer(B_FLUSH,0);              // try to make sure that there is at least something to read in buffer and this ensures that
                                    // the end of file can be recogniced with buffer_eof, in following steps
    
    if(buffer_eof()) return NULL;   // check end of file

    if (skip_fillers()) if(buffer_eof()) return NULL;  // check again end of file if fillers were skipped

    new.level = current_level;
    new.tlv_type = T_UNKNOWN;                    
    new.tag[0] = 0;
    new.type[0] = 0;
    new.length = 0;
    new.file_offset = file_offset();
    new.total_offset = total_offset();
    new.tl = current_tl();
    new.form = new.tl->form;
    new.raw_tl = buffer_data();

    if(!read_tl(&new)) buffer_error("Not a valid tag/length",&new);    // read tl pair 

    tl_buffer_read(new.raw_tl_length);                         // tl is now read, move pointer to beginning of value part, this is safe

    new.raw_value = buffer_data();                 

    new.tlv = find_tlvdef(new.tag,new.tl->tag->type);          // search possible tlv definition

    /* Check if the content is really a constructed item, user must give a hint of this in new.tlv->maybe_constructor */
    if(new.tlv != NULL && new.tlv->maybe_constructor && new.tlv_type != T_CONSTRUCTED)
    {
        if(maybe_constructed(new.tl->tag->type,new.tag,&new.length))
        {
            new.tlv_type = T_CONSTRUCTED;
        }
    }

    if(new.tlv_type == T_UNKNOWN)                              // check if user has defined a new tlv type
    {
        new.tlv_type = new.tlv != NULL && new.tlv->type != T_UNKNOWN ? new.tlv->type : T_PRIMITIVE;
    }

    if(new.tlv != NULL &&                                      // check if user has defined the form for this
      (new.tlv->form != T_UNKNOWN)) new.form = new.tlv->form;  // get the form if tlv was found

    if(new.tlv_type != T_CONSTRUCTED)                          // if type is not constructed, read the value
    {
        new.raw_value_length = read_value(&new);
        if(!enough_size(new.raw_value_length)) buffer_error("Element is larger than space left in parent element",&new);
        tl_buffer_read(new.raw_value_length);                  // move ahead in buffer
    } 
    {
        new.raw_value_length = new.length;                     // constructed data size, do not tl_buffer_read, because this
    }                                                          // contains individual tlv triplets

    return &new;
}

/* checks if there end of file was premature
 */
static void
check_premature_eof()
{
    int i;
    int wait_bytes = 0;
    int wait_eoc = 0;
    char msg[100];

    i = FIRST_LEVEL + 1;
    while(i <= get_current_level())
    {
        if(levels[i].form == T_DEFINITE && levels[i].size > (size_t) 0 && !wait_bytes)
        {
            wait_bytes = (int) levels[i].size;
        } else if(levels[i].form == T_INDEFINITE)
        {
            wait_eoc++;
        }
        i++;
    }

    if(wait_bytes || wait_eoc)
    {
        strcpy(msg,"Unexpected end of file:");
        if(wait_bytes) sprintf(msg + strlen(msg)," expecting the file to be %d bytes larger", wait_bytes);
        if(wait_eoc) sprintf(msg + strlen(msg)," expecting the file to have %d end-of-content elements", wait_eoc);
        buffer_error(msg,NULL);
    }
}



/* main execution loop */
void
execute()
{
    struct tlvitem *i;
    int pl_up,j;

    for(j = 0;j < TLV_HASH_SIZE;j++) tlvhash[j] = NULL;

    print_init_path();
     
    hex_to_ascii = (structure.hex_caps ? hex_to_ascii_cap : hex_to_ascii_low);

    while(open_next_input_file())
    {
        print_list_clear_hold();
        init_level();
        buffer(B_INIT,0);
        print_file_header();
        while((i = parse_tlv()) != NULL)
        {
            pl_up = 0;

            if(i->tlv_type == T_CONSTRUCTED) print_list_down(i);

            if(i->tlv_type != T_EOC) print_list_add_item(i);

            switch(i->tlv_type)
            {
                case T_CONSTRUCTED:
                    level_down(i->length,i->tlv,i->form);
                    break;
                case T_EOC:
                    if(get_level_form() == T_INDEFINITE)
                    {
                        level_up();
                        pl_up = 1;
                    }
                    break;
                default:
                    break;
            }

            while(level_current_size() <= 0 && get_level_form() == T_DEFINITE) 
            {
                level_up();
                pl_up++;
            }

            print_list_print();

            while(pl_up--) print_list_up();
        }
        check_premature_eof();
        print_file_trailer();
    }
}
