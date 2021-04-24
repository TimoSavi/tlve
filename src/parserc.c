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

/* max number of parameter=value pairs per line */
#define MAX_PARAMETER 20

#define COMMENT '#'


/* Keyword codes */
#define K_TL 0
#define K_TLV 1
#define K_STRUCTURE 2
#define K_STRUCTURE_END 3
#define K_PRINT 4
#define K_TYPE_MAPPING 5
#define K_TYPE_MAPPING_END 6
#define K_MAP 7
#define K_MAX K_MAP

/* Parameter codes */
#define P_NAME 0
#define P_TYPE 1
#define P_TL 2
#define P_TAG 3
#define P_LENGTH 4
#define P_PRINT 5
#define P_TAGTERM 6
#define P_LENTERM 7
#define P_DATATERM 8
#define P_ENCODING 9
#define P_VALUE 10
#define P_MASK 11
#define P_SHIFT 12
#define P_STRING 13
#define P_LEVEL_START 14
#define P_LEVEL_END 15
#define P_FILE_START 16
#define P_FILE_END 17
#define P_CONTENT_TL 18
#define P_FILLER 19
#define P_ETAG 20
#define P_DATATYPE 21
#define P_CONTENT 22
#define P_UCONTENT 23
#define P_INDENT 24
#define P_SEPARATOR 25
#define P_FORMAT 26
#define P_FORM 27
#define P_VALUE_LEN_ADJUST 28
#define P_TL_INCLUDED 29
#define P_MAY_CONSTRUCTOR 30
#define P_PATH 31
#define P_BLOCK_START 32
#define P_BLOCK_END 33
#define P_HOLD 34
#define P_HEX_CAPS 35
#define P_TYPEMAP 36
#define P_MAX P_TYPEMAP

/* error value for unknown data */
#define E_UNKNOWN 99999
/* Keywords */
static char *keywords[K_MAX + 1];

/* Parameters */
static char *parameters[P_MAX + 1];

/* Types */
static char *types[T_MAX + 1];

/* One paramter/value pair found in config line */
struct rcconfig
{
    TYPE parameter;
    size_t value_len; // some strings can contain \0 so we have to use length also
    char value[1024];
};

/* Paramter/value pairs for current line */
static struct rcconfig pvpairs[MAX_PARAMETER];
static int parameter_count;

/* Current lineno */
static int lineno = 0;

/* Found keyword in current line */
static int keyword;

/* Current line, starting whitespaces and comments trimmed */
static unsigned char *line = NULL;
static size_t line_length;

/* rcfile handle */
static FILE *rcfp;

/* ber content terminator string for indefinite elements */
static BUFFER ber_content_terminator[] = {'\000','\000'};

static void
verify_rc_data();

/* Initialize keyword array  */
static void
init_keywords()
{
    keywords[K_TL] = "tl";
    keywords[K_TLV] = "tlv";
    keywords[K_STRUCTURE] = "structure";
    keywords[K_STRUCTURE_END] = "structure-end";
    keywords[K_PRINT] = "print";
    keywords[K_TYPE_MAPPING] = "typemap";
    keywords[K_TYPE_MAPPING_END] = "typemap-end";
    keywords[K_MAP] = "map";

    parameters[P_NAME] = "name";
    parameters[P_TYPE] = "type";
    parameters[P_TL] = "tl";
    parameters[P_TAG] = "tag";
    parameters[P_LENGTH] = "length";
    parameters[P_PRINT] = "print";
    parameters[P_TAGTERM] = "tag-term";
    parameters[P_LENTERM] = "length-term";
    parameters[P_DATATERM] = "value-term";
    parameters[P_ENCODING] = "encoding";
    parameters[P_VALUE] = "-- reserved --";
    parameters[P_MASK] = "mask";
    parameters[P_SHIFT] = "shift";
    parameters[P_STRING] = "string";
    parameters[P_LEVEL_START] = "constructor";
    parameters[P_LEVEL_END] = "constructor-end";
    parameters[P_FILE_START] = "file-start";
    parameters[P_FILE_END] = "file-end";
    parameters[P_CONTENT_TL] = "content-tl";
    parameters[P_FILLER] = "filler";
    parameters[P_ETAG] = "end-tag";
    parameters[P_DATATYPE] = "value-type";
    parameters[P_CONTENT] = "value";
    parameters[P_UCONTENT] = "uvalue";
    parameters[P_INDENT] = "indent";
    parameters[P_SEPARATOR] = "separator";
    parameters[P_FORMAT] = "format";
    parameters[P_FORM] = "form";
    parameters[P_VALUE_LEN_ADJUST] = "value-length-adjust";
    parameters[P_TL_INCLUDED] = "tl-included";
    parameters[P_MAY_CONSTRUCTOR] = "maybe-constructed";
    parameters[P_PATH] = "path";
    parameters[P_BLOCK_START] = "block-start";
    parameters[P_BLOCK_END] = "block-end";
    parameters[P_HOLD] = "hold";
    parameters[P_HEX_CAPS] = "hex-caps";
    parameters[P_TYPEMAP] = "type-map";

    types[T_UNKNOWN] = "--unkown--";
    types[T_INTBE] = "int-be";
    types[T_INTLE] = "int-le";
    types[T_STRING] = "string";
    types[T_CONSTRUCTED] = "constructed";
    types[T_PRIMITIVE] = "primitive";
    types[T_EOC] = "end-of-content";
    types[T_BER] = "ber";
    types[T_INT] = "int";
    types[T_HEX] = "hex";
    types[T_BCD] = "bcd";
    types[T_BCDS] = "bcds";
    types[T_UINTBE] = "uint-be";
    types[T_UINTLE] = "uint-le";
    types[T_UINT] = "uint";
    types[T_DEFINITE] = "definite";
    types[T_INDEFINITE] = "indefinite";
    types[T_OID] = "oid";
    types[T_BITSTRING] = "bit-string";
    types[T_ESCAPED] = "escaped";
    types[T_DEC] = "dec";
    types[T_HEXS] = "hexs";
}

/* print line number and error message */
static void
config_panic(char *e1,char *e2,char *e3)
{
    fprintf(stderr,"%s: error in configuration file, line %d\n",program_name,lineno);
    panic(e1,e2,e3);
}

/* search keyword table for a keyword, search is not case-sensitive */
/* in not found return E_UNKNOWN */
static int
search_config_item(char **table,int count,char *keyword)
{
    int i = 0;

    if(keyword == NULL) return E_UNKNOWN;

    while(i <= count)
    {
        if(STRCMP(table[i],keyword) == 0) return i;
        i++;
    }

    return E_UNKNOWN;
}


/* read a single character from config file */
static inline
int read_char()
{
    register int c;
    c = getc(rcfp);
    if(c == '\n') lineno++;
    return c;
}


/* reads one logical line, lines in file can be terminated with \
   meaning line continues in next line. Line is saved in line[]

   empty and comment lines are skipped

   return values
   > 0 - line read
   0   - end of file
*/
int
read_logical_line()
{
    int c,prev;
    int i = 0;
    int quoted = 0;

    /* skip comment and empty lines */
    do
    {
        do
        {
            c = read_char();
        } while(isspace(c));

        if(c == COMMENT)
        {
            do
            {
                c = read_char();
            } while(c != '\n' && c != EOF);
        }

    } while(c == '\n');

    if(c == EOF) return 0;

    prev = 0;

    do
    {
        line[i] = (unsigned char) c;
        switch(c)
        {
            case COMMENT:
                if(!quoted)
                {
                    do
                    {
                        c = read_char();           // skip the rest of the line
                    } while(c != '\n' && c != EOF);
                    line[i] = 0;
                    return i;
                }
                break;
            case '"':
                if(prev != '\\') quoted = !quoted;
                break;
            case '\n':
                if(i && line[i-1] == '\\') // does line continue on next physical line
                {
                    line[i-1] = ' ';       // replace with space
                    i--;
                } else
                {
                    line[i] = 0;
                    return i;
                }
                break;
            case EOF:
                line[i] = 0;
                return i;
                break;
        }

        i++;

        if(i == line_length) 
        {
            line_length = 2 * line_length;
            line = xrealloc(line,line_length);
        }

        prev = c;
        c = read_char();
    } while(1);
}


/* parse a single logical line 
   write keyword to keyword and parameter=value pairs to pvpairs
 */

int 
parse_line()
{
    int i = 0;
    int quoted;
    int p_start;
    char value[1024];
    char num[5];
    int value_len;
    int value_done;
    int h;
    int line_done = 0;

    parameter_count = 0;
    num[0] = '0';
    num[1] = 'x';
    num[4] = 0;

    if(!read_logical_line()) return 0;
    
    /* check keyword */

    while(!isspace(line[i]) && line[i]) i++;

    if(!line[i])
    {
        if((keyword = search_config_item(keywords,K_MAX,line)) == E_UNKNOWN) config_panic("Unknown keyword",line,NULL);
        return 1;
    }

    line[i] = 0;

    if((keyword = search_config_item(keywords,K_MAX,line)) == E_UNKNOWN) config_panic("Unknown keyword",line,NULL);
      
    i++;
        
    do
    {
        while(isspace(line[i]) && line[i]) i++;
        if(!line[i]) return 1;
        p_start = i;
        while(line[i] != '=' && line[i]) i++;
        if(line[i] == '=')
        {
            /* check the parameter */
            line[i] = 0;
            pvpairs[parameter_count].parameter = search_config_item(parameters,P_MAX,&line[p_start]);
            if(pvpairs[parameter_count].parameter == E_UNKNOWN) config_panic("Unknown parameter",&line[p_start],NULL);
            i++;
            quoted = 0;
            value_len = 0;
            value_done = 0;
            /* check the value */
            do
            {
                switch(line[i])
                {
                    case '\\':
                        i++; 
                        if(!line[i]) config_panic("Invalid configuration line",NULL,NULL);
                        switch(line[i])
                        {
                            case 'a':
                                value[value_len] = '\a';
                                break;
                            case 'b':
                                value[value_len] = '\b';
                                break;
                            case 't':
                                value[value_len] = '\t';
                                break;
                            case 'n':
                                value[value_len] = '\n';
                                break;
                            case 'v':
                                value[value_len] = '\v';
                                break;
                            case 'f':
                                value[value_len] = '\f';
                                break;
                            case 'r':
                                value[value_len] = '\r';
                                break;
                            case '\\':
                                value[value_len] = '\\';
                                break;
                            case '"':
                                value[value_len] = '"';
                                break;
                            case 'x':
                                if(isxdigit(line[i+1]) && isxdigit(line[i+2]))
                                {
                                    num[2] = line[i+1];
                                    num[3] = line[i+2];
                                    sscanf(num,"%i",&h);
                                    value[value_len] = (unsigned char) h;
                                    i += 2;
                                } 
                                break;
                            default:
                                value[value_len] = line[i];
                                break;
                        }
                        value_len++;
                        break;
                    case '"':
                        quoted = !quoted;
                        break;
                    case ' ':
                        if(quoted) 
                        {
                            value[value_len++] = line[i];
                        } else
                        {
                            value_done = 1;
                        }
                        break;
                    case 0:
                        value_done = 1;
                        line_done = 1;
                        break;
                    default:
                        value[value_len++] = line[i];
                        break;
                }
                i++;
            } while(!value_done);
            value[value_len] = 0; // for visible strings
            memcpy(pvpairs[parameter_count].value,value,(size_t) (value_len + 1));
            pvpairs[parameter_count].value_len = value_len;
        } else
        {
            config_panic("Invalid parameter, missing \'=\'",NULL,NULL);
        }
        parameter_count++;
        if(parameter_count == MAX_PARAMETER) config_panic("Too many parameters",NULL,NULL);
    } while(!line_done);
    return 1;
}

/* parse one tag or length defintion, these are in form:
   type,length,mask,shift,offset

   type is "int", "intbe", "intle", "string" or "ber"
   length is a number, or terminating char in enclosed in /c/
   mask is a hexnumber (0xnnnn)
   shift is signed integer
   offset is unsigned integer

   minimun required is type and length (ber does not need the length)
*/

#define BO_LS ','

static struct bo *
parse_bo(char *bo_string)
{
    struct bo *ret;
    int done = 0;
    char *s;
    char *p;
    unsigned long int uli;

    ret = xmalloc(sizeof(struct bo));

    ret->length = 0;
    ret->mask = (unsigned long int) 0;
    ret->shift = 0;
    ret->offset = 0;
    ret->use_terminator = 0;
    ret->use_offset = 0;
    
    s = bo_string;
    p = bo_string;

    /* check the type */

    while(*p != BO_LS && *p) p++;
    done = !*p;
    *p = 0;
    
    ret->type = search_config_item(types,T_MAX,s);

    if(ret->type == E_UNKNOWN) config_panic("Invalid tag/length definition, unknown type",bo_string,NULL);
    if(ret->type == T_INT) ret->type = T_INTBE;              // int is same as int-be
    if(ret->type == T_UINT) ret->type = T_UINTBE;            // int is same as uint-be

    if(done) goto end;

    p++; s = p;

    /* check the length/terminator */
    if(*p == '/' && p[2] == '/')
    {
        p++;
        ret->terminator = *p;
        p += 2;
        done = !*p;
        ret -> use_terminator = 1;
    } else
    {
        /* length */
        while(*p != BO_LS && *p) p++;
        done = !*p;
        *p = 0;
        ret->length = (size_t) atol(s);
        if(!ret->length) config_panic("Invalid tag/length definition, unknown length or terminator definition",bo_string,NULL);
    }

    if(done) goto end;

    /* now check mask */
    p++; s = p;
    while(*p != BO_LS && *p) p++;
    done = !*p;
    *p = 0;
    if(p > s)
    {
        sscanf(s,"%li",&ret->mask);
    }

    if(done) goto end;

    /* shift */

    p++; s = p;
    while(*p != BO_LS && *p) p++;
    done = !*p;
    *p = 0;
    if(p > s)
    {
        sscanf(s,"%i",&ret->shift);
    }

    if(done) goto end;

    /* offset */

    p++; s = p;
    while(*p != BO_LS && *p) p++;
    done = !*p;
    *p = 0;
    if(p > s)
    {
        sscanf(s,"%lu",&uli);
        ret->offset = uli;
        ret->use_offset = 1;
    }

end:
    switch(ret->type)
    {
        case T_UINTBE:
        case T_INTBE:
        case T_UINTLE:
        case T_INTLE:
        case T_STRING:
        case T_BER:
            break;
        default:
            config_panic("Unknown type for tag or length",bo_string,NULL);
    }
    return ret;
}


/* check if paramters contain the name of the sructure */
static int
check_structure_name(char *name)
{
    int i = 0;

    while(i < parameter_count) 
    {
        if(STRCMP(pvpairs[i].value,name) == 0 && pvpairs[i].parameter == P_NAME) return 1;
        i++;
    }
    return 0;
}

/* Add new item to hold list */
static struct hold *
add_hold_list(void)
{
    struct hold *new;

    if(hold != NULL)
    {
        new = hold;
        while(new->next != NULL) new = new->next;
        new->next = xmalloc(sizeof(struct hold));
        new = new->next;
    } else
    {
        hold = xmalloc(sizeof(struct hold));
        new = hold;
    }
    new->next = NULL;
    new->name = NULL;
    new->buffer = NULL;

    return new;
}

/* Add or find a item to hold list, item is searched according the name */
static struct hold *
add_or_find_hold_list(char *name)
{
    struct hold *new;

    if(name == NULL || name[0] == 0) return NULL;

    new = hold;

    while(new != NULL) {
        if(new->name != NULL && STRCMP(new->name,name) == 0) return new;
        new = new->next;
    }

    new = add_hold_list();
    new->name = xstrdup(name);
    new->name_len = strlen(new->name);
    return new;
}



#define READING 0
#define STRUCTURE_NOT_READ 1
#define STRUCTURE_READING 2
#define STRUCTURE_READ 3
#define TYPEMAP_READING 4
#define TYPEMAP_READ 5


/* parse rc-file, read all definitions and
   recuired structure definitions

   put tl's to global list and structure to global variable
*/
void
parse_rc(char *rcfile, char *required_structure,char *printing)
{
    int state = READING;
    int i;
    struct tldef *ctl = NULL;
    struct type_map *ctm = NULL;
    struct type_mappings *ctms = NULL;
    struct tlvdef *ctlv = NULL;
    struct tlvlist *ctlvl = NULL;
    struct print *cprint = NULL;

    rcfp = xfopen(rcfile,"r",'a');

    line_length = 1024;

    line = xmalloc(line_length);

    init_keywords();

    while(parse_line())
    {
        switch(keyword)
        {
            case K_STRUCTURE:
                if(state == STRUCTURE_READING) config_panic("Structure keyword in structure definition",NULL,NULL);
                if(state != READING) config_panic("Structure keyword found",NULL,NULL);
                if(check_structure_name(required_structure) && structure.name == NULL)
                {
                    structure.print_name = printing != NULL ? printing : "default";
                    structure.content_tl = NULL;
                    structure.tlv = NULL;
                    structure.filler_string = NULL;
                    structure.filler_length = 0;
                    structure.name = NULL;
                    structure.tl_name = NULL;
                    structure.hex_caps = 0;

                    i = 0;
                    while(i < parameter_count)
                    {
                        switch(pvpairs[i].parameter)
                        {
                            case P_PRINT:
                                structure.print_name = xstrdup(pvpairs[i].value);
                                break;
                            case P_CONTENT_TL: 
                                structure.tl_name = xstrdup(pvpairs[i].value);
                                break;
                            case P_FILLER:
                                structure.filler_length = pvpairs[i].value_len;
                                structure.filler_string = xmalloc(structure.filler_length);
                                memcpy(structure.filler_string,pvpairs[i].value,pvpairs[i].value_len);
                                break;
                            case P_NAME: 
                                structure.name =  xstrdup(pvpairs[i].value);
                                break;
                            case P_HEX_CAPS:
                                if(STRCMP(pvpairs[i].value,"yes") == 0)
                                {
                                    structure.hex_caps = 1;
                                }
                                break;
                            default:
                                config_panic("Unknown parameter for structure",parameters[pvpairs[i].parameter],NULL);
                                break;
                        }

                        i++;
                    }
                    if(structure.tl_name == NULL) config_panic("Structure must have a tag-length definition name",NULL,NULL);
                    state = STRUCTURE_READING;
                }
                break;
            case K_STRUCTURE_END:
                if(state == STRUCTURE_READING) state = READING;
                break;
            case K_TYPE_MAPPING:
                if(state != READING) config_panic("Typemap keyword found",NULL,NULL);
                if(ctms != NULL)
                {
                    ctms->next = xmalloc(sizeof(struct type_mappings));
                    ctms = ctms->next;
                } else
                {
                    ctms = xmalloc(sizeof(struct type_mappings));
                    type_maps = ctms;
                }

                ctms->name = NULL;
                ctms->mappings = NULL;
                ctms->next = NULL;
                ctm = NULL;

                i = 0;
                while(i < parameter_count)
                {
                    switch(pvpairs[i].parameter)
                    {
                        case P_NAME: 
                            ctms->name =  xstrdup(pvpairs[i].value);
                            break;
                        default:
                            config_panic("Unknown parameter for typemap",parameters[pvpairs[i].parameter],NULL);
                            break;
                    }

                    i++;
                }
                state = TYPEMAP_READING;
                break;
            case K_TYPE_MAPPING_END:
                if(state == TYPEMAP_READING) 
                {
                    state = READING;
                } else
                {
                    config_panic("Typemap-end keyword found",NULL,NULL);
                }
                break;
            case K_MAP:
                if(state == TYPEMAP_READING)
                {
                    if(ctm != NULL)
                    {
                        ctm->next = xmalloc(sizeof(struct type_map));
                        ctm = ctm->next;
                    } else
                    {
                        ctm = xmalloc(sizeof(struct type_map));
                        ctms->mappings = ctm;
                    }

                    ctm->source_type = NULL;
                    ctm->valuetype = T_UNKNOWN;
                    ctm->next = NULL;


                    i = 0;
                    while(i < parameter_count)
                    {
                        switch(pvpairs[i].parameter)
                        {
                            case P_CONTENT: 
                                ctm->source_type  = xstrdup(pvpairs[i].value);
                                break;
                            case P_DATATYPE:
                                ctm->valuetype = search_config_item(types,T_MAX,pvpairs[i].value);
                                switch(ctm->valuetype)
                                {
                                    case T_INT:                     // int defaults to bigendian int
                                    case T_UINT:                    // uint defaults to bigendian int
                                    case T_UINTBE:
                                    case T_INTBE:
                                    case T_UINTLE:
                                    case T_INTLE:
                                    case T_STRING:
                                    case T_HEX:
                                    case T_HEXS:
                                    case T_OID:
                                    case T_BITSTRING:
                                    case T_BCD:
                                    case T_BCDS:
                                    case T_ESCAPED:
                                    case T_DEC:        
                                        if(ctm->valuetype == T_INT) ctm->valuetype = T_INTBE;
                                        if(ctm->valuetype == T_UINT) ctm->valuetype = T_UINTBE;
                                        break;
                                    default:
                                        config_panic("mapping: Unknown value-type",pvpairs[i].value,NULL);
                                        break;
                                }
                                break;
                            default:
                                config_panic("Unknown parameter for mapping",parameters[pvpairs[i].parameter],NULL);
                                break;
                        }

                        i++;
                    }
                } else
                {
                    config_panic("Unknown parameter for typemap",parameters[pvpairs[i].parameter],NULL);
                }
                break;
            case K_TL:
                if(state == READING)
                {
                    if(ctl != NULL)
                    {
                        ctl->next = xmalloc(sizeof(struct tldef));
                        ctl = ctl->next;
                    } else
                    {
                        ctl = xmalloc(sizeof(struct tldef));
                        tl = ctl;
                    }
                    ctl->name = NULL;
                    ctl->tag = NULL;
                    ctl->type = NULL;
                    ctl->len = NULL;
                    ctl->value_terminator = NULL;
                    ctl->value_terminator_len = 0;
                    ctl->print_name = NULL;
                    ctl->p = NULL;
                    ctl->type_mapping = NULL;
                    ctl->next = NULL;
                    ctl->tl_included = 0;   // default FALSE
                    i = 0;
                    while(i < parameter_count)
                    {
                        switch(pvpairs[i].parameter)
                        {
                            case P_NAME:
                                ctl->name = xstrdup(pvpairs[i].value);
                                break;
                            case P_TAG:
                                ctl->tag = parse_bo(pvpairs[i].value);
                                break;
                            case P_TYPE:
                                ctl->type= parse_bo(pvpairs[i].value);
                                if(ctl->type->type == T_BER) config_panic("Type cannot be used with BER",parameters[pvpairs[i].parameter],NULL);
                                break;
                            case P_LENGTH:
                                ctl->len = parse_bo(pvpairs[i].value);
                                break;
                            case P_PRINT:
                                if(printing == NULL) ctl->print_name = xstrdup(pvpairs[i].value);
                                break;
                            case P_DATATERM:
                                ctl->value_terminator_len = pvpairs[i].value_len;
                                ctl->value_terminator = xmalloc(ctl->value_terminator_len);
                                memcpy(ctl->value_terminator,pvpairs[i].value,ctl->value_terminator_len);
                                break;
                            case P_TL_INCLUDED:
                                if(STRCMP(pvpairs[i].value,"yes") == 0)
                                {
                                    ctl->tl_included = 1;
                                } else if(STRCMP(pvpairs[i].value,"no") == 0)
                                {
                                    ctl->tl_included = 0;
                                } else config_panic("tl: Invalid value for tl-included",parameters[i],NULL);
                                break;
                            case P_TYPEMAP:
                                ctl->type_mapping = xstrdup(pvpairs[i].value);
                                break;
                            default:
                                config_panic("tl: Unknown parameter",parameters[pvpairs[i].parameter],NULL);
                                break;
                        }
                        i++;
                    }
                    if(ctl->name == NULL) config_panic("tl: A definition must have a name",NULL,NULL);
                    if(ctl->tag == NULL) config_panic("tl: A definition must have tag definition",NULL,NULL);
                    if(ctl->len == NULL && !ctl->value_terminator_len) config_panic("tl: length or value-terminator must be defined",NULL,NULL);
                    if(ctl->value_terminator_len && ctl->len != NULL) config_panic("tl: length and value-terminator are mutually exclusive",NULL,NULL);
                    if(printing != NULL) ctl->print_name = printing;

                    if(ctl->value_terminator_len)
                    {
                        ctl->form = T_INDEFINITE;
                    } else
                    {
                        ctl->form = T_DEFINITE;
                    }

                    if(ctl->tag->type == T_BER)  // special for BER
                    {
                        ctl->value_terminator = ber_content_terminator;
                        ctl->value_terminator_len = sizeof(ber_content_terminator);
                    }
                } else
                {
                    config_panic("tl must not be defined here",NULL,NULL);
                }
                break;
            case K_TLV:
                if(state == STRUCTURE_READING)
                {
                    if(ctlvl != NULL)
                    {
                        ctlvl->next = xmalloc(sizeof(struct tlvlist));
                        ctlvl = ctlvl->next;
                    } else
                    {
                        ctlvl = xmalloc(sizeof(struct tlvlist));
                        structure.tlv = ctlvl;
                    }
                    ctlvl->next = NULL;

                    ctlv = xmalloc(sizeof(struct tlvdef));

                    ctlvl->tlv = ctlv;

                    ctlv->path = NULL;
                    ctlv->name = NULL;
                    ctlv->stag = NULL;
                    ctlv->etag = NULL;
                    ctlv->type = T_UNKNOWN;
                    ctlv->valuetype = T_UNKNOWN;
                    ctlv->content_tl_name = NULL;
                    ctlv->content_tl = NULL;
                    ctlv->print_name = NULL;
                    ctlv->encoding = NULL;
                    ctlv->format = NULL;
                    ctlv->p = NULL;
                    ctlv->form = T_UNKNOWN;
                    ctlv->length_adjust = 0;
                    ctlv->maybe_constructor = 0;
                    ctlv->hold_buffer = NULL;

                    i = 0;
                    while(i < parameter_count)
                    {
                        switch(pvpairs[i].parameter)
                        {
                            case P_PATH:
                                ctlv->path = xstrdup(pvpairs[i].value);
                                break;
                            case P_NAME:
                                ctlv->name = xstrdup(pvpairs[i].value);
                                break;
                            case P_TAG:
                                ctlv->stag = xstrdup(pvpairs[i].value);
                                break;
                            case P_ETAG:
                                ctlv->etag = xstrdup(pvpairs[i].value);
                                break;
                            case P_FORM:
                                ctlv->form = search_config_item(types,T_MAX,pvpairs[i].value);
                                switch(ctlv->form)
                                {
                                    case T_DEFINITE:
                                    case T_INDEFINITE:
                                        break;
                                    default:
                                        config_panic("tlv: Unknown form",pvpairs[i].value,NULL);
                                }
                                break;
                            case P_TYPE:
                                ctlv->type = search_config_item(types,T_MAX,pvpairs[i].value);
                                switch(ctlv->type)
                                {
                                    case T_CONSTRUCTED:
                                    case T_PRIMITIVE:
                                    case T_EOC:
                                        break;
                                    default:
                                        config_panic("tlv: Unknown type",pvpairs[i].value,NULL);
                                }
                                break;
                            case P_DATATYPE:
                                ctlv->valuetype = search_config_item(types,T_MAX,pvpairs[i].value);
                                switch(ctlv->valuetype)
                                {
                                    case T_INT:                     // int defaults to bigendian int
                                    case T_UINT:                    // uint defaults to bigendian int
                                    case T_UINTBE:
                                    case T_INTBE:
                                    case T_UINTLE:
                                    case T_INTLE:
                                    case T_STRING:
                                    case T_HEX:
                                    case T_HEXS:
                                    case T_OID:
                                    case T_BITSTRING:
                                    case T_BCD:
                                    case T_BCDS:
                                    case T_ESCAPED:
                                    case T_DEC:        
                                        if(ctlv->valuetype == T_INT) ctlv->valuetype = T_INTBE;
                                        if(ctlv->valuetype == T_UINT) ctlv->valuetype = T_UINTBE;
                                        break;
                                    default:
                                        config_panic("tlv: Unkown value-type",pvpairs[i].value,NULL);
                                        break;
                                }
                                break;
                            case P_CONTENT_TL:
                                ctlv->content_tl_name = xstrdup(pvpairs[i].value);
                                break;
                            case P_PRINT:
                                if(printing == NULL) ctlv->print_name = xstrdup(pvpairs[i].value);
                                break;
                            case P_ENCODING:
                                ctlv->encoding = xstrdup(pvpairs[i].value);
                                break;
                            case P_VALUE_LEN_ADJUST:
                                ctlv->length_adjust = atoi(pvpairs[i].value);
                                break;
                            case P_FORMAT:
                                ctlv->format = xstrdup(pvpairs[i].value);
                                break;
                            case P_MAY_CONSTRUCTOR:
                                if(STRCMP(pvpairs[i].value,"yes") == 0)
                                {
                                    ctlv->maybe_constructor = 1;
                                } else if(STRCMP(pvpairs[i].value,"no") == 0)
                                {
                                    ctlv->maybe_constructor = 0;
                                } else config_panic("tlv: Invalid value for maybe-constructor",parameters[i],NULL);
                                break;
                            case P_HOLD:
                                if(STRCMP(pvpairs[i].value,"yes") == 0)
                                {
                                    ctlv->hold_buffer = add_hold_list();
                                } else if(STRCMP(pvpairs[i].value,"no") == 0) 
                                {
                                } else
                                {
                                    ctlv->hold_buffer = add_or_find_hold_list(pvpairs[i].value);
                                }
                                break;
                            default:
                                config_panic("tlv: Unknown parameter",parameters[pvpairs[i].parameter],NULL);
                                break;
                        }
                        i++;
                    }
                    if(ctlv->hold_buffer != NULL && ctlv->name != NULL && ctlv->hold_buffer->name == NULL) 
                    {
                        ctlv->hold_buffer->name = ctlv->name;
                        ctlv->hold_buffer->name_len = strlen(ctlv->name);
                    }
                    if(ctlv->stag == NULL) config_panic("tlv: tag missing",NULL,NULL);
                    if(ctlv->etag == NULL) ctlv->etag = ctlv->stag;
                    if(printing != NULL) ctlv->print_name = printing;
                }
                break;
            case K_PRINT:
                if(state == READING)
                {
                    if(cprint != NULL)
                    {
                        cprint->next = xmalloc(sizeof(struct print));
                        cprint = cprint->next;
                    } else
                    {
                        cprint = xmalloc(sizeof(struct print));
                        print = cprint;
                    }

                    cprint->name = NULL;
                    cprint->file_head = NULL;
                    cprint->file_trailer = NULL;
                    cprint->block_start = NULL;
                    cprint->block_end = NULL;
                    cprint->level_head = NULL;
                    cprint->level_trailer = NULL;
                    cprint->content = "%v";
                    cprint->ucontent = NULL;
                    cprint->indent = NULL;
                    cprint->encoding = NULL;
                    cprint->separator = 0;
                    cprint->next = NULL;

                    i = 0;
                    while(i < parameter_count)
                    {
                        switch(pvpairs[i].parameter)
                        {
                            case P_NAME:
                                cprint->name = xstrdup(pvpairs[i].value);
                                break;
                            case P_FILE_START:
                                cprint->file_head = xstrdup(pvpairs[i].value);
                                break;
                            case P_FILE_END:
                                cprint->file_trailer = xstrdup(pvpairs[i].value);
                                break;
                            case P_LEVEL_START:
                                cprint->level_head = xstrdup(pvpairs[i].value);
                                break;
                            case P_LEVEL_END:
                                cprint->level_trailer = xstrdup(pvpairs[i].value);
                                break;
                            case P_CONTENT:
                                cprint->content = xstrdup(pvpairs[i].value);
                                break;
                            case P_UCONTENT:
                                cprint->ucontent = xstrdup(pvpairs[i].value);
                                break;
                            case P_INDENT:
                                cprint->indent = xstrdup(pvpairs[i].value);
                                break;
                            case P_ENCODING:
                                cprint->encoding = xstrdup(pvpairs[i].value);
                                break;
                            case P_SEPARATOR:
                                cprint->separator = pvpairs[i].value[0];
                                break;
                            case P_BLOCK_START:
                                cprint->block_start = xstrdup(pvpairs[i].value);;
                                break;
                            case P_BLOCK_END:
                                cprint->block_end = xstrdup(pvpairs[i].value);;
                                break;
                            default:
                                config_panic("print: Unknown parameter",parameters[pvpairs[i].parameter],NULL);
                                break;
                        }
                        i++;
                    }
                    if(cprint->name == NULL) config_panic("print: Printing definition must have a name",NULL,NULL);
                    if(cprint->ucontent == NULL) cprint->ucontent = cprint->content;
                } else
                {
                    config_panic("Printing definition found",NULL,NULL);
                }
                break;

        }
    }
    fclose(rcfp);
    free(line);
    if(state == STRUCTURE_READING) config_panic("Structure definition has no end keyword",NULL,NULL);
    if(state == TYPEMAP_READING) config_panic("Typemap definition has no end keyword",NULL,NULL);
    if(structure.name == NULL) panic("No structure named as",required_structure,NULL);
    verify_rc_data();
}

/* return pointer to print info */
static struct print *
search_print(char *name)
{
    struct print *p = print;

    while(p != NULL)
    {
        if(STRCMP(name,p->name) == 0) return p;
        p = p->next;
    }
    return NULL;
}

/* return pointer to tl info */
static struct tldef *
search_tl(char *name)
{
    struct tldef *p = tl;

    while(p != NULL)
    {
        if(STRCMP(name,p->name) == 0) return p;
        p = p->next;
    }
    return NULL;
}

/* return pointer to mappings */
static struct type_mappings *
search_mapping(char *name)
{
    struct type_mappings *p = type_maps;

    while(name != NULL && p != NULL)
    {
        if(STRCMP(name,p->name) == 0) return p;
        p = p->next;
    }
    return NULL;
}


/* verify data after read the whole rc-file */
static void
verify_rc_data()
{
    struct tlvdef *tlv;
    struct tlvlist *tlvl;
    struct tldef *t;

    structure.p = search_print(structure.print_name);
    if(structure.p == NULL) panic("No printing definition named as",structure.print_name,NULL);

    structure.content_tl = search_tl(structure.tl_name);
    if(structure.content_tl == NULL) panic("No tag-length definition named as",structure.tl_name,NULL);

    tlvl = structure.tlv;

    while(tlvl != NULL)
    {
        tlv = tlvl->tlv;
        if(tlv->content_tl_name != NULL)
        {
            tlv->content_tl = search_tl(tlv->content_tl_name);
            if(tlv->content_tl == NULL) panic("No tag-length definition named as",tlv->content_tl_name,NULL);
        }

        if(tlv->print_name != NULL) 
        {
            tlv->p = search_print(tlv->print_name);
            if(tlv->p == NULL) panic("No printing definition named as",tlv->print_name,NULL);
        }
        tlvl = tlvl->next;
    }

    t = tl;

    while(t != NULL)
    {
        if(t->print_name == NULL) t->print_name = structure.print_name;  // use one from structure if not defined

        t->p = search_print(t->print_name);
        if(t->p == NULL) panic("No printing definition named as",t->print_name,NULL);
        
        t->types = search_mapping(t->type_mapping);
        if(t->types == NULL && t->type_mapping != NULL) panic("No mapping named as",t->type_mapping,NULL);

        t = t->next;
    }
}
