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

/* for printing hex dump */
static char hex_to_ascii[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

struct print_list
{
    struct tlvitem *item;         // data to be printed
    int printed;                  // is the data printed or level header printed
    int trailer_printed;          // if constructor, tells is the trailer is also printed
    struct print_list *next;             
};


/* name list, if this contains names, only elements which match this list are printed */

#define MAX_NAME 1024

#define TAG_PREFIX '['
#define TAG_TRAILER ']'

struct name
{
    char *name;
    int length;
};

static struct name name_list[MAX_NAME];
static int name_count = 0;

static char *dump_buffer = NULL;
static size_t dump_buffer_len = 0;
/* expression list, used to select records */

#define MAX_EXPRESSION 128

struct expression
{
    char *name;     // name of the item to be validated
    char *value;    // value of the expression
#if HAVE_REGEX
    regex_t reg;    // Compiled expression
#endif
    int result;     // evaluation result
};


static struct expression expression_list[MAX_EXPRESSION];
static int expression_count = 0;
int expression_and = 0;                  // if true, all expressions must match, if not true one expression matching is enough


/* pointer to formatting function */
typedef char *(pt_to_print)(char,struct tlvitem *,char *,char *);

static struct print_list *print_list_start = NULL;

static FILE *ofp;   // output handle

struct path_name
{
    char *name;
    size_t length;
};


#define MAX_PATH_LEN (8 * 1024)
static char path[MAX_PATH_LEN] = {0};       // name of the current path
                                  // structure.level1_name.level2_name.<level3_tag>.....
                                  // ends allways with dot
static struct path_name path_names[MAX_LEVEL]; // Individual path names
static int path_level = 0;
static int start_print_level = 0;  // which is the first level to be printed, default is the first level
static int stop_print_level = MAX_LEVEL;  // which is the last level to be printed, default is the MAX_LEVEL

void
print_set_print_start_level(int level)
{
    if(level < 1) panic("Start level must be numeric and greater that zero",NULL,NULL);
    start_print_level = level;
}

void
print_set_print_stop_level(int level)
{
    if(level < 1) panic("Stop level must be numeric and greater that zero",NULL,NULL);
    stop_print_level = level;
}

void
print_init_path()
{
    int i = 0;

    while(i < MAX_LEVEL)
    {
        path_names[i].name = NULL;
        path_names[i].length = 0;
        i++;
    }
}



static void
make_printable_path()
{
    int i = 0;
    char sep[2];

    path[0] = 0;
    sep[0] = PATH_SEPARATOR;
    sep[1] = 0;

    while(i < path_level)
    {
        strcat(path,path_names[i].name);
        if(i < path_level - 1) strcat(path,sep);
        i++;
    }
}



/* returns the current path */
char *
print_list_path()
{
    if(path[0] == 0) make_printable_path();
    return path;
}

/* write string to output */
static inline void
print_list_writes(char *string)
{
    if(fputs(string,ofp) == EOF) panic("Error writing to output",strerror(errno),NULL);
}

/* write a char to output */
static inline void
print_list_writec(char c)
{
    if(fputc(c,ofp) == EOF) panic("Error writing to output",strerror(errno),NULL);
}

/* return the items name, if nameis not defined (in with keyword tlv) return
   the tag value enclosed  in <>. 

   value is in static buffer so it must be copied before use
 */
static char *
print_list_get_item_name(struct tlvitem *i)
{
    static char name[MAX_NAME];
    size_t tag_len;

    if(i->tlv != NULL && (i->tlv->name != NULL))
    {
        return i->tlv->name;
    }

    tag_len = strlen(i->tag);

    name[0] = TAG_PREFIX;
    strcpy(name + 1,i->tag);
    name[tag_len + 1] = TAG_TRAILER;
    name[tag_len + 2] = 0;

    return name;
}

/* Add names to name list, names are comma separated 
 */
void
print_list_add_names(char *names)
{
    char *p = names,*s;
    int done = 0;

    if(!*p) return;

    do
    {
        s = p;
        while(*p != ',' && *p) p++;
        if(!*p) done = 1;
        if(p > s)
        {
            *p = 0;
            name_list[name_count].name = xstrdup(s);
            name_list[name_count].length = strlen(s);
            name_count++;
        }
        p++;
    } while(!done);
}

static void
reset_expression_result()
{
    register int i = expression_count;

    while(i) expression_list[--i].result = 0;
}

/* return true if the whole list contains true results */
static int
expression_list_all_true()
{
    register int i = expression_count;

    while(i) if(!expression_list[--i].result) return 0;
    return 1;
}

/* return true if atleast one expression contains true result */
static int
expression_list_any_true()
{
    register int i = expression_count;

    while(i) if(expression_list[--i].result) return 1;
    return 0;
}

/* Add expression to list, expressions are in form NAME=VALUE, where name is the name
   of a item and value regular expression to be validated with name's converted_value
 */
void
print_list_add_expression(char *exp)
{
    char *name,*value,*errbuf;
    int rc;
    size_t buflen;

    value = strchr(exp,'=');

    if(!value) panic("An expression must contain =",exp,NULL);

    name = exp;
    *value=0;
    value++;

    expression_list[expression_count].name = xstrdup(name);
    expression_list[expression_count].value = xstrdup(value);
    expression_list[expression_count].result = 0;

    //print_list_add_names(expression_list[expression_count].name);          

#ifdef HAVE_REGEX
    rc = regcomp(&expression_list[expression_count].reg,value,REG_EXTENDED | REG_NOSUB);
    if(rc)
    {
        buflen = regerror(rc,&expression_list[expression_count].reg,NULL,0);
        errbuf = xmalloc(buflen + 1);
        regerror(rc,&expression_list[expression_count].reg,errbuf,buflen);
        panic("Error in regular expression",value,errbuf);
    }
#endif
    expression_count++;
}


/* create list item at the end of the list */
static void
print_list_add()
{
    struct print_list *p,*n;

    p = xmalloc(sizeof(struct print_list));

    p->item = NULL;
    p->printed = 0;
    p->trailer_printed = 0;
    p->next = NULL;

    n = print_list_start;

    if(n == NULL) 
    {
        print_list_start = p;
    } else
    {
        while(n->next != NULL) n = n->next;
        n->next = p;
    }
}

/* return true if item has been printed */
static int
print_list_is_printed(struct print_list *p)
{
    return (p->printed && 
               ((p->item->tlv_type != T_CONSTRUCTED) || p->trailer_printed));
}

/* copy a new item to print list */
/* as the tlvitem->converted_value is static it must be copied to new new place */
static void
print_list_copy(struct tlvitem *i, struct print_list *p)
{
    size_t cvl;
    char *cv;
    
    
    if(p->item == NULL)
    {
        p->item = xmalloc(sizeof(struct tlvitem)); 
        cvl = i->converted_value_len;
        cv = xmalloc(cvl);
    } else
    {
        cvl = p->item->converted_value_len;
        cv = p->item->converted_value;
    }

    *p->item = *i;

    p->printed = 0;
    p->trailer_printed = 0;


    if(i->converted_value_len > cvl)
    {
        cvl = i->converted_value_len;
        cv = xrealloc(cv,cvl);
    }

    p->item->converted_value_len = cvl;
    p->item->converted_value = cv;

    memcpy(p->item->converted_value,i->converted_value,i->converted_value_len);
}


/* update the global path name down (new constructor)
   */
void
print_list_down(struct tlvitem *item)
{
    char *name = print_list_get_item_name(item);
    size_t ilen = strlen(name);

    if(path_level == MAX_LEVEL) panic("Too deep hierarchy",NULL,NULL);

    if(path_names[path_level].name == NULL)
    {
        path_names[path_level].name = xmalloc(ilen+1);
        path_names[path_level].length = ilen+1;
    } else if(ilen + 1 > path_names[path_level].length) 
    {
        path_names[path_level].name = xrealloc(path_names[path_level].name,ilen+1);
        path_names[path_level].length = ilen+1;
    }

    path[0] = 0;              // mark path change

    strcpy(path_names[path_level].name,name);
    path_level++;
}

/* update the global path name up (constructor data has been read)
   */
void
print_list_up()
{
    path[0] = 0;              // mark path change
    if(path_level) path_level--;
}

/* check that names and expression names are in structure->tlv, so we do
   not start executing if name is misspelled
 */
void
print_list_check_names()
{
    int i,f,name_list_empty = 0;
    struct tlvlist *t;

    if(!name_count && start_print_level == 0) name_list_empty = 1;  // add epxression names to name list if there is no names 
                                                                    // or no start levels are defined

    i = 0;
    while(i < expression_count)
    {
        t = structure.tlv;
        f = 0;
        if(expression_list[i].name[0] != TAG_PREFIX)   // tag names start with "<"
        {
            while(t != NULL && !f)
            {
                if(STRCMP(t->tlv->name,expression_list[i].name) == 0) f = 1;
                t = t->next;
            }
            if(!f) panic("Expression name not found in tlv names",expression_list[i].name,NULL);
        }
        if(name_list_empty) print_list_add_names(expression_list[i].name);
        i++;
    }

    i = 0;
    while(i < name_count)
    {
        t = structure.tlv;
        f = 0;
        if(name_list[i].name[0] != TAG_PREFIX)   // tag names start with "<"
        {
            while(t != NULL && !f)
            {
                if(STRCMP(t->tlv->name,name_list[i].name) == 0) f = 1;
                t = t->next;
            }
            if(!f) panic("Name not found in tlv names",name_list[i].name,NULL);
        }
        i++;
    }
}

/* checks if item should be added to print list,

   first check if printing level(s) are defined, if item level is not in range return false
   
   else

   Item will be added if there is no names in names list,
   
   or if the name of the item is in the list or in case non constructed item
   if one if the names in the list  appears in the current path (if the constructor is in list and
   in path, then all items after that will be added to list)
*/
static int
print_list_check_item(struct tlvitem *item)
{
    register int i,j;
    char *item_name;

    if(start_print_level != 0 || stop_print_level != MAX_LEVEL)  // should we first check start/stop levels
    {
        if(item->level < start_print_level || item->level > stop_print_level) return 0;
    }

    if(!name_count) return 1;

    item_name = print_list_get_item_name(item);
    
    i = 0;

    while(i < name_count)
    {
        if(STRCMP(item_name,name_list[i].name) == 0) return 1;
        j = 0;
        while(j < path_level)
        {
            if(STRCMP(name_list[i].name,path_names[j].name) == 0) return 1;
            j++;
        }
        i++;
    }

    return 0;
}

/* search last item in the print list */
static struct print_list *
print_list_last()
{
    register struct print_list *p = print_list_start;

    while(p != NULL)
    {
        if(p->next == NULL) return p;
        p = p->next;
    }
    return NULL;
}

/* find the first constructor in the list */

/* find expression comparing name to expression list's names */
static struct expression *
find_expression(char *name,int index)
{
    register int i=index;

    while (i < expression_count)
    {
        if(STRCMP(name,expression_list[i].name) == 0) return &expression_list[i];
        i++;
    }

    return NULL;
}


/* checks if the expression results should be evaluated. 
   This happens when the first item in list is primitive
   or when the first item is constructed and the current level
   is the same or higher as the level of the constructor (effectively
   means that the data for a constructor is read)

 */
static int
check_expression_results()
{
    struct print_list *p = print_list_start;

    if(p != NULL)
    {
        switch(p->item->tlv_type)
        {
            case T_PRIMITIVE:
            case T_EOC:
                if(start_print_level != 0)
                { 
                    if(start_print_level >= get_current_level()) return 1;
                } else
                {
                    return 1;
                }
                break;
            case T_CONSTRUCTED:
                if(p->item->level >= get_current_level()) return 1;
                break;
        }
    }
    return 0;
}

/* evaluates the results of the expression in print list
   returns true if list can be printed
 */
static int
eval_expression_results()
{

    if(expression_and)
    {
        return expression_list_all_true();
    } else
    {
        return expression_list_any_true();
    }
}
                


/* evaluates item related expression
 */
static void
evaluate_expression(struct tlvitem *item)
{
    register int i = 0;
    struct expression *e;

    while(i < expression_count)
    {
        if((e = find_expression(print_list_get_item_name(item),i)) != NULL)
        {
#ifdef HAVE_REGEX
            if(regexec(&e->reg,item->converted_value,(size_t) 0, NULL, 0) == 0) 
#else
            if(strcmp(e->value,item->converted_value) == 0) 
#endif
            {
                if(!e->result) e->result = 1;
            }
        }
        i++;
    }
}

/* replace data in hold buffer */
static void
print_list_add_to_hold(struct hold *hold_buffer,char *data)
{
    if(data != NULL)
    {
        if(hold_buffer->buffer != NULL) free(hold_buffer->buffer);
        hold_buffer->buffer = xstrdup(data);
    }
}


/* clear hold list for each input file */
void
print_list_clear_hold()
{
    struct hold *h = hold;

    while(h != NULL)
    {
        if(h->buffer != NULL)
        {
            free(h->buffer);
            h->buffer = NULL;
        }
        h = h->next;
    }
}


/* add one item to print list */
/* item is static so it will be copied to the list as the last one */
/* if the last item is printed it will be reused */
/* evaluates also expression */
void
print_list_add_item(struct tlvitem *item)
{
    struct print_list *last_item = print_list_last();


    if(print_list_check_item(item))
    {
        if(last_item == NULL || (!print_list_is_printed(last_item)))
        {
            print_list_add();
            last_item = print_list_last();
        }
        print_list_copy(item,last_item);
    }

    switch(item->tlv_type)
    {
        case T_PRIMITIVE:
            if(expression_count) evaluate_expression(item);
            if(item->tlv != NULL && item->tlv->hold_buffer != NULL) print_list_add_to_hold(item->tlv->hold_buffer,item->converted_value);
            break;
        case T_CONSTRUCTED:
            if(item->tlv != NULL && item->tlv->hold_buffer != NULL) print_list_add_to_hold(item->tlv->hold_buffer,item->tlv->name);
            break;
    }
}

/* open the output file, "-" is stdout */
void 
print_list_open_output(char *file)
{
    if(file[0] == '-' && !file[1])
    {
        ofp = stdout;
    } else
    {
        ofp = xfopen(file,"w",'a');
    }
}

/* close the output file */
void 
print_list_close_output()
{
    if(fclose(ofp) != 0) panic("Error closing output file",strerror(errno),NULL);
}

/* print indent */
static void 
print_list_indent(char *indent,unsigned int level)
{
    if(indent == NULL) return;
    if(indent[0] == 0) return;

    while(--level) print_list_writes(indent);
}

/* format a hex dump as xnnxnn..., where nn is the hex-value of an octet 
 */
char *
print_list_hex_dump(BUFFER *data,size_t length)
{
    char *p;
    size_t data_len = 3*length + 1;
    size_t i;

    if(dump_buffer == NULL) 
    {
        dump_buffer_len = data_len;
        dump_buffer = xmalloc(dump_buffer_len);
    } else if(dump_buffer_len < data_len)
    {
        dump_buffer_len = data_len;
        dump_buffer = xrealloc(dump_buffer,dump_buffer_len);
    }

    i = 0;
    p = dump_buffer;

    while(i < length)
    {
        *p++ = 'x';
        *p++ = hex_to_ascii[(data[i] >> 4) & 0x0f];
        *p++ = hex_to_ascii[data[i] & 0x0f];
        i++;
    }
    *p = 0;

    return dump_buffer;
}
    


/* Format common directives */
static char *
format_common(char c,struct tlvitem *i,char *fencoding, char *toencoding)
{
    static char number[128];

    switch(c)
    {
        case '%':
            return "%";
            break;
        case '$':
            return "$";
            break;
        case '>':
            sprintf(number,"%lld",(long long int) i->level);
            return number;
            break;
        case 'l':
            sprintf(number,"%lld",(long long int) i->length);
            return number;
            break;
        case 'c':
            sprintf(number,"%lld",(long long int) (i->raw_tl_length + i->raw_value_length));
            return number;
            break;
        case 't':
            return i->tag;
            break;
        case 'n':
            return print_list_get_item_name(i);
            break;
        case 'p':
            if(!expression_count) return print_list_path();          // path is safe only when not looking for something...
            return "";
            break;
        case 'o':
            sprintf(number,"%lld",(long long int) i->file_offset);
            return number;
            break;
        case 'O':
            sprintf(number,"%lld",(long long int) i->total_offset);
            return number;
            break;
        case 'f':
            return get_current_file_name();
            break;
        case 's':
            return structure.name;
            break;
        case 'd':
            if(get_buffer_state() == S_BUFFER_OK) 
            {
                return print_list_hex_dump(i->raw_tl,i->raw_tl_length);
            }
            break;
        case 'D':
            if(get_buffer_state() == S_BUFFER_OK) 
            {
                return print_list_hex_dump(i->raw_value,i->raw_value_length);
            }
            break;
    }
    return "";
}

/* trim value, remove whitespace from start end end
 */
static char *
trim(char *value)
{
    static char *trimmed = NULL;
    static int tsize = 0;
    char *p,*e;
    int value_len;
     

    if(!value) return "";
    
    value_len = strlen(value);

    if(!value_len) return "";

    if(trimmed == NULL) 
    {
        trimmed=xstrdup(value);
        tsize = value_len + 1;
    } else
    {
        if(value_len > tsize)
        {
            trimmed = xrealloc(trimmed,(size_t) (value_len + 1));
            tsize = value_len;
        }
        strcpy(trimmed,value);
    }

    p = trimmed;
    e = &trimmed[value_len - 1];
    while(isspace(*p)) p++;
    while(isspace(*e) && e > trimmed) e--;
    *(e + 1) = 0;

    return p;
}



/* format primitive item's data */
static char *
format_primitive(char c,struct tlvitem *i,char *fencoding, char *toencoding)
{
    switch(c)
    {
        case 'v':
            if(fencoding && toencoding) return make_iconv(i->converted_value,fencoding,toencoding);
            return i->converted_value;
            break;
        case 'T':
            if(fencoding && toencoding) return trim(make_iconv(i->converted_value,fencoding,toencoding));
            return trim(i->converted_value);
            break;
        default:
            return format_common(c,i,fencoding,toencoding);
    }
}

/* format level head data */
static char *
format_level_head(char c,struct tlvitem *i,char *fencoding, char *toencoding)
{
    return format_common(c,i,fencoding,toencoding);
}

/* format level trailer data */
/* remove d and D, because raw data is not necessary available in buffer any more */
static char *
format_level_trailer(char c,struct tlvitem *i,char *fencoding, char *toencoding)
{
    if(c == 'd' || c == 'D') return "";
    return format_common(c,i,fencoding,toencoding);
}

/* format file data*/
/* only f and s directives can be used*/
static char *
format_file(char c,struct tlvitem *i,char *fencoding, char *toencoding)
{
    if(c != 'f' && c != 's' && c != '%') return "";
    return format_common(c,i,fencoding,toencoding);
}

/* search the hold list for element name, select the longest match */
/* returns the elements name length when found, else 0 */
static int
find_hold_data(char *name,char **data)
{
    struct hold *hl;
    struct hold *found = NULL;
    int found_len = 0;


    hl = hold;

    while(hl != NULL)
    {
        if(STRNCMP(hl->name,name,hl->name_len) == 0)
        {
            if(hl->name_len > found_len)
            {
                found = hl;
                found_len = hl->name_len;
            }
        }
        hl = hl->next;
    }

    if(found != NULL)
    {
        if(found->buffer != NULL)
        {
            *data = found->buffer;
        } else
        {
            *data = "";
        }
        return found_len;
    }
    return 0;
}



/* print a item, use formatting function format %-directives */
static void
print_item(struct tlvitem *i,char *data,char *indent,char *fencoding, char *toencoding,pt_to_print pf)
{
    int level;
    int hold_name_len;
    char *hold_data;

    if(data == NULL) return;
    if(data[0] == 0) return;

    if(i == NULL) 
    {
        level = FIRST_LEVEL;
    } else
    {
        level = i->level;
    }

    print_list_indent(indent,level);

    while(1)
    {
        switch(*data)
        {
            case '%':
                data++;
                print_list_writes((pf)(*data,i,fencoding,toencoding));
                data++;
                break;
            case '\n':
                print_list_writec(*data);
                if(data[1]) print_list_indent(indent,level);        // if not last \n print indent to keep output nice
                data++;
                break;
            case '$':
                hold_name_len = find_hold_data(data + 1,&hold_data);
                if(hold_name_len)
                {
                    print_list_writes(hold_data);
                    data += hold_name_len + 1;
                } else
                {
                    print_list_writec(*data);
                    data++;
                }
                break;
            case 0:
                return;
                break;
            default:
                print_list_writec(*data);
                data++;
                break;
        }
    }
}

/* print file header */
void
print_file_header()
{
    print_item(NULL,structure.p->file_head,structure.p->indent,NULL,NULL,format_file);
}

/* print file trailer */
void
print_file_trailer()
{
    print_item(NULL,structure.p->file_trailer,structure.p->indent,NULL,NULL,format_file);
}

/* Purge one item */
/* item to purge is pitem */
static void
print_list_purge_item(struct print_list *pitem)
{
    if(pitem->item->converted_value_len) free(pitem->item->converted_value);
    free(pitem->item);
    free(pitem);
}


/* purge the print list 
   if force=true, the whole list is purged even not printed (this is the case when
   list evaluates false in case expressions are used
*/

static void
print_list_purge(int force)
{
    struct print_list *p;
    struct print_list *s;

    p = print_list_start;

    if(p == NULL) return;

    if(force)                  // mark first as printed
    {
        p->printed = 1;
        p->trailer_printed = 1;
    } else                     // search last printed
    {
        while(p != NULL && (!print_list_is_printed(p))) p = p->next;
        if(p == NULL) return;
    }

    s = p->next;
    p->next = NULL;      // save the printed first for reuse
    p = s;         

    while(p != NULL)
    {
        s = p->next;
        print_list_purge_item(p);
        p = s;
    }
}

/* search list for constructor, which is the constructor for given item
   and trailer_printed_must be false
 */
static struct print_list *
search_prev_constructor_tr_not_printed(struct tlvitem *item)
{
    register struct print_list *p;
    struct print_list *ret = NULL;

    if(item == NULL) return NULL;

    p = print_list_start;

    while(p != NULL)
    {
        if(p->item->tlv_type == T_CONSTRUCTED && !p->trailer_printed) ret = p;
        if(p->item == item && ret != NULL) return ret;
        p = p->next;
    }

    return NULL;
}

/* print seprator char */
static void
print_list_separator(char separator)
{
    if(separator) print_list_writec(separator);
}

/* get printlist items printing definitions 
   use one from tlv definition if given, other cases use on from tl
 */
static struct print *
print_list_print_data(struct print_list *pitem)
{
    if(pitem->item->tlv != NULL)
    {
        if(pitem->item->tlv->p != NULL) return pitem->item->tlv->p;
    }
    return pitem->item->tl->p;
}

/* return true if there is something to print in print list
 */
static int
print_list_printable()
{
    register struct print_list *p;

    p = print_list_start;

    while(p != NULL)
    {
        if(!p->printed) return 1;
        p = p->next;
    }
    return 0;
}
 

/* go through the print list and print the items
 */
static void
print_list_do_print()
{
    register struct print_list *p;
    struct print_list *prev_c;
    struct print *pdata;
    struct tlvitem *item,*last_item = NULL;
    unsigned int prev_level = FIRST_LEVEL;
    char *from,*to;


    p = print_list_start;

    while(p != NULL)
    {
        item = p->item;
        
        if(prev_level > item->level)    // one level up, print level trailer
        {
            while((prev_c = search_prev_constructor_tr_not_printed(last_item)) != NULL &&
                    (prev_c->item->level >= item->level))
            {
                pdata = print_list_print_data(prev_c);
                print_item(prev_c->item,pdata->level_trailer,pdata->indent,NULL,NULL,format_level_trailer);
                prev_c->trailer_printed = 1;
            }
        } 

        if(!p->printed)
        {
            pdata = print_list_print_data(p);

            switch(item->tlv_type)
            {
                case T_CONSTRUCTED:
                    print_item(item,pdata->level_head,pdata->indent,NULL,NULL,format_level_head);
                    break;
                default:
                    from = item->tlv != NULL && item->tlv->encoding != NULL ? item->tlv->encoding : NULL;
                    to = pdata->encoding != NULL ? pdata->encoding : codeset;
                    print_item(item,pdata->content,pdata->indent,from,to,format_primitive);
                    if(p->next) print_list_separator(pdata->separator);
                    break;
            }
            p->printed = 1;
        }

        last_item = item;
        prev_level = item->level;
        p = p->next;
    }

    while((prev_c = search_prev_constructor_tr_not_printed(last_item)) != NULL &&
            (prev_c->item->level >= get_current_level()))
    {
        pdata = print_list_print_data(prev_c);
        print_item(prev_c->item,pdata->level_trailer,pdata->indent,NULL,NULL,format_level_trailer);
        prev_c->trailer_printed = 1;
    }

}


/* print the list */
void
print_list_print()
{
    int print_something;

    if(expression_count || start_print_level > 0)
    {
        if(check_expression_results())
        {
            if(eval_expression_results() || !expression_count)
            {
                print_something = print_list_printable();

                if(print_something) print_item(NULL,structure.p->block_start,structure.p->indent,NULL,NULL,format_file);
                print_list_do_print();
                if(print_something) print_item(NULL,structure.p->block_end,structure.p->indent,NULL,NULL,format_file);
            }
            print_list_purge(1);
            buffer(B_PRINTED,0);
            reset_expression_result();
        }
    } else
    {
        print_list_do_print();
        print_list_purge(0);
        buffer(B_PRINTED,0);
    } 
}

        



