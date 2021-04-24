#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if __STDC__
# define VOID void
#else
# define VOID char
#endif

#if STDC_HEADERS

#include <sys/types.h>
#include <string.h>             /* for strlen etc. */
#include <stdlib.h>

#endif  /* !STDC_HEADERS */

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_ERROR_H
#include <error.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#include <stdio.h>

#if defined(__MINGW32__)
#ifndef WIN32
#define WIN32 1
#endif
#endif

#ifndef HAVE_STRTOLL
#define strtoll strtol
#endif

#ifndef HAVE_STRTOULL
#define strtoull strtoul
#endif

#ifndef HAVE_ATOLL
#define atoll atol
#endif

#if defined(HAVE_REGEX) && !defined(HAVE_REGCOMP)
#undef HAVE_REGEX
#endif

/* string comparison function for parsing */
#ifdef HAVE_STRCASECMP
#define STRCMP strcasecmp
#else
#define STRCMP strcmp
#endif

#ifdef HAVE_STRNCASECMP
#define STRNCMP strncasecmp
#else
#define STRNCMP strncmp
#endif

#define PATH_SEPARATOR '.'

#ifdef WIN32
#define PATH_SEPARATOR_STRING "\\"
#else
#define PATH_SEPARATOR_STRING "/"
#endif

#define MAX_LEVEL 1024

/* Global type values */
#define T_UNKNOWN 0
#define T_INTBE 1
#define T_INTLE 2
#define T_STRING 3
#define T_CONSTRUCTED 4
#define T_PRIMITIVE 5
#define T_EOC 6
#define T_BER 7
#define T_INT 8
#define T_HEX 9
#define T_BCD 10
#define T_UINTBE 11
#define T_UINTLE 12
#define T_UINT 13
#define T_DEFINITE 14
#define T_INDEFINITE 15
#define T_OID 16
#define T_BITSTRING 17
#define T_ESCAPED 18
#define T_BCDS 19
#define T_DEC 20
#define T_HEXS 21
#define T_MAX T_HEXS


/* Global structures */

typedef unsigned int TYPE;
typedef unsigned char BUFFER;
typedef long long int FILE_OFFSET;   // use system maximum regardless real offset

/* Type mappings */
struct type_map
{
    char *source_type;
    TYPE valuetype;
    struct type_map *next;
};

struct type_mappings
{
    char *name;
    struct type_map *mappings;
    struct type_mappings *next;
};


/* Binary Object, stores tag or length data */
struct bo
{
    TYPE type;              // T_INTBE,T_INTLE,T_STRING, T_BER or T_UNKNOWN if not applicable
    size_t length;          // length of the object, use terminator if zero
    char terminator;        // terminating char for the object must have either length or terminator, if length == 0, use this
    int use_terminator;     // should length or termiantor be used, (terminator migth be null...) so extra flag
    unsigned long int mask; // bitmask for object
    int shift;              // should object be shifted after rading from input, positive left, negative right
    size_t offset;          // relative to start of the tlv object
    int use_offset;         // offset might be zero, so extra flag is needed...
};

/* Printing directives */
struct print
{
    char *name;             // Name of this printing schema
    char *file_head;        // data to be printed when new file is opened
    char *file_trailer;     // data to be printed when file is closed
    char *level_head;       // data to be printed when level changes down
    char *level_trailer;    // data to be printed when level changes up
    char *block_start;      // data to be printed before data block, which have been found using expression
    char *block_end;        // data to be printed after data block, which have been found using expression
    char *content;          // data to be printed for every tlv
    char *ucontent;         // data to be printed for every tlv which is not named using tlv info
    char *indent;           // string to be used when indenting
    char *encoding;         // which encoding to use in printing when data encoding is known
    char separator;         // character to be printed after every conted in level, except the last
    struct print *next;
};

/* one tag-length pair */
struct tldef
{ 
    char *name;             // name for this
    struct bo *tag;         // tag information
    struct bo *type;        // Type information
    struct bo *len;         // length information
    TYPE form;              // T_DEFINITE or T_INDEFINITE
    int tl_included;        // TRUE = length includes the tag-length part the tlv, FALSE = length is the legngth of the value only
    BUFFER *value_terminator; // if length is not used, this char will indicate the end of content
    size_t value_terminator_len; // length of the content_terminator
    char *print_name;        // which printing definition should be used with this type of data
    struct print *p;        // Pointer to print information
    char *type_mapping;      // mapping name
    struct type_mappings *types; // mapping info from source types to internal types
    struct tldef *next;
};

/* hold buffer list, contains persistent data for each tlvitem, which should hold last
   value for later printing
   */
struct hold
{
    char *name;             // tlv name, pointer here for faster search
    int name_len;           // length of the name
    char *buffer;           // pointer to visible data
    struct hold *next;
};

/* Information for tag-length-value triplet */
struct tlvdef
{
    char *path;             // if != NULL, name is check only if this is the same as current path
    char *name;             // name of the tlv triplet
    char *stag;             // tag to identify the triplet, if range is used this is the first value
    char *etag;             // end value for tag range, if no range -> stag == etag; 
    TYPE type;              // T_CONSTRUCTED, T_PRIMITIVE or T_EOC
    TYPE form;              // T_DEFINITE or T_INDEFINITE
    TYPE valuetype;         // T_INTLE, T_INTBE, T_STRING, T_HEX, T_BCD
    int maybe_constructor;  // if yes, check the start of the data if it is a valid tl-pair -> this is constructor
    char *content_tl_name;  // tag-length info to use
    struct tldef *content_tl;  // pointer to tag-length info in case this is a constructor, if NULL use one from structure
    char *print_name;       // print-info to be used
    struct print *p;        // Pointer to print info
    char *encoding;         // Content encoding
    char *format;           // Printf format to print this data
    int length_adjust;      // adjustment for length when reading the value
    struct hold *hold_buffer; // place to store data for later use.
};

/* list for seaarching tlvedef, used also in bash table */
struct tlvlist
{
    struct tlvdef *tlv;     
    struct tlvlist *next;
};


/* structure for one found tlv triplet */
#define MAX_TAG_SIZE 128

struct tlvitem
{
    unsigned int level;     // in which level this tlv was found
    char tag[MAX_TAG_SIZE]; // tag as visible null-terminated string 
    char type[MAX_TAG_SIZE]; // type as visible null-terminated string 
    FILE_OFFSET length;     // length from the tl-pair
    FILE_OFFSET file_offset;  // Offset of the current file where this data was found
    FILE_OFFSET total_offset; // Offset of the total input data where this data was found
    TYPE tlv_type;          // T_CONSTRUCTED, T_PRIMITIVE or T_EOC if recognized from data, otherwise T_UNKNOWN
    TYPE form;              // T_DEFINITE or T_INDEFINITE
    BUFFER *raw_tl;         // pointer to whole tlv raw data;
    size_t raw_tl_length;   // length of the raw tl part
    BUFFER *raw_value;        // pointer to the value part
    size_t raw_value_length;// length of the value part, contains also possible terminating string
    size_t converted_value_len; // length of the converted_value
    char *converted_value;  // data after conversions etc, visible string
    struct tldef *tl;       // pointer to tl-data, cannot be null
    struct tlvdef *tlv;     // pointer to tlv-data, can be null
};

struct printlist
{
    struct tlvitem *item;    // pointer to found data, cannot be null
    int printed;             // is the tlv data or level header printed
    int trailer_printed;     // in case a constructed item, is the level trailer printed
    struct printlist *prev;  // previous item, NULL if first
    struct printlist *next;  // next item, NULL if last
};

/* level information */
struct level
{
    TYPE form;               // T_DEFINITE or T_INDEFINITE
    struct tldef *content_tl;  // pointer to tag-length info for this level
    FILE_OFFSET size;        // raw data size known to this level, will be decrement after every tlv read, when reaches 0, level is done
};                           // size will get negative for indefinite levels, must be signed

struct structure
{
    char *name;             // Name of the structure
    char *print_name;       // printing definitions to be used when printing data
    struct print *p;        // pointer to printing info
    char *tl_name;          // name of the tl-info to be used when reading this type of data
    struct tldef *content_tl;  // pointer to tl-info, cannot be NULL
    struct tlvlist *tlv;    // tlv data list to be used, may be NULL
    char *filler_string;    // filler string to be skipped in input data
    size_t filler_length;   // filler string length, 0 = if not used
    int hex_caps;           // print hexadecimal in capital letters
};


#if defined (__STDC__) && __STDC__
/* tlve.c prototypes */
void panic(char *,char *,char *);

/* xmalloc.c prototypes */
VOID *xmalloc (size_t);
VOID *xcalloc (size_t, size_t);
VOID *xrealloc (VOID *, size_t);
char *xstrdup (char *);
FILE * xfopen(char *, char *, char);

/* parse.rc prototypes */
void parse_rc(char *, char *,char *);

/* buffer.c prototypes */
void set_input_file(char *);
int open_next_input_file();
int buffer(int, size_t);
int get_buffer_state();
int search_buffer_c(BUFFER,size_t);
int search_buffer_s(BUFFER *,size_t,size_t);
size_t buffer_unread();
VOID buffer_read(size_t);
BUFFER *buffer_data();
char *get_current_file_name();
FILE_OFFSET file_offset();
FILE_OFFSET total_offset();
int buffer_eof();
void buffer_error(char *,struct tlvitem *);
void buffer_ahead();
void buffer_back();
int buffer_address_safe(BUFFER *);

/* tlv.c prototypes */
int get_current_level();
void execute();

/* print.c prototypes */
void print_set_print_start_level(int);
void print_set_print_stop_level(int);
void print_list_add_names(char *);
void print_list_down(struct tlvitem *);
void print_list_up();
void print_list_add_item(struct tlvitem *);
void print_list_open_output(char *);
void print_list_close_output();
void print_list_print();
void print_list_add_expression(char *);
void print_file_header();
void print_file_trailer();
void print_list_check_names();
char *print_list_path();
void print_init_path();
void print_list_clear_hold();
char *print_list_hex_dump(BUFFER *,size_t); 


/* ber.c prototypes */
size_t read_ber_tag(char *,TYPE *,TYPE *);
size_t read_ber_length(FILE_OFFSET *,size_t);
void format_ber_bit_string(char *,BUFFER *, size_t);
void format_oid(char *,BUFFER *, size_t);



/* inconv.c prototypes */
char *make_iconv(char *,char *,char *);



#endif

/* buffer.c values */
#define S_BUFFER_OK 0
#define S_BUFFER_STALE 1

#define B_INIT 0
#define B_DESIRED 1
#define B_NEEDED 2
#define B_FLUSH 3
#define B_PRINTED 4
#define B_FLUSH_FORCE 5



/* Global data */
#define FIRST_LEVEL 1
extern struct structure structure;
extern struct tldef *tl;
extern struct print *print;
extern struct hold *hold;
extern struct type_mappings *type_maps;
extern int debug;
extern int expression_and;
extern char *codeset;

extern char *program_name;
extern char *version;
extern char *host;
extern char *build_date;
extern char *email_address;
extern char *tlve_open;
