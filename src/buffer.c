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


/* input buffer size, this dictates etc. the maximum tlv triplet size */
#define BUFFER_SIZE ((size_t) 10485760)

/* Pointers to different points in buffer */
/* Start of the buffer */
static BUFFER *buffer_start;

/* Low water, point after the flush command reads new data and makes buffer stale */
static BUFFER *low_water;

/* pointer to the next readable octet */
static BUFFER *new_data;

/* Data end point, pointer to the last octet + 1  of the data */
static BUFFER *data_end;

/* buffer end point, pointer to the last octet + 1 of the data */
static BUFFER *buffer_end;

/* Peeked char from input preprosessor */
static int ungetchar = -1;

/* state variable */
static int buffer_state;

/* List of input files */
struct input_file
{
    char *name;
    FILE_OFFSET offset;
    FILE *fp;
    struct input_file *next;
};

/* file list start */
static struct input_file *files = NULL;

/* Current file */
static struct input_file *current_file = NULL;

/* Total offset for all files */
static FILE_OFFSET toffset = (FILE_OFFSET) 0;



/* Add one input file to list */
void
set_input_file(char *name)
{
    register struct input_file *f = files;

    if(files == NULL)
    {
        files = xmalloc(sizeof(struct input_file));
        f = files;
    } else
    {
        while(f->next != NULL) f = f->next;
        f->next = xmalloc(sizeof(struct input_file));
        f = f->next;
    }

    f->next = NULL;
    f->offset = (FILE_OFFSET) 0;
    f->name = xstrdup(name);
    f->fp = NULL;
}

/* open next input file, return 0 if no more files */
/* stdin is a file named as "-" */
int
open_next_input_file()
{
    if(current_file == NULL)
    {
        current_file = files;
    } else
    {
        fclose(current_file->fp); 
        current_file = current_file->next;
    }

    if(current_file == NULL) return 0;

    if(current_file->name[0] == '-' && current_file->name[1] == 0)
    {
        current_file->fp = stdin;
        current_file->name = "stdin";
    } else
    {
        int fds[2];
        pid_t pid;
        char command[1024];

        if(tlve_open != NULL && tlve_open[0] != '\000')                // use preprocessor
        {
#if defined(HAVE_WORKING_FORK) && defined(HAVE_DUP2) && defined(HAVE_PIPE)
            sprintf(command,tlve_open,current_file->name);
            if (pipe(fds) != 0) panic("Cannot create pipe",strerror(errno),NULL);
            pid = fork();
            if(pid == (pid_t) 0) /* Child */
            {
                close(fds[0]);
                if(dup2(fds[1],STDOUT_FILENO) == -1) panic("dup2 error",strerror(errno),NULL);
                if(execl(SHELL_CMD, "sh", "-c", command, NULL) == -1) panic("Starting a shell with execl failed",command,strerror(errno));
                close(fds[1]);
                _exit(EXIT_SUCCESS);
            } else if(pid > (pid_t) 0)
            {
                close(fds[1]);
                current_file->fp = fdopen(fds[0],"r");
                if(current_file->fp == NULL) panic("Cannot read from command",command,strerror(errno));

                ungetchar = fgetc(current_file->fp);

                if(ungetchar == EOF)       // check if pipe returns something, if not open file normally
                {
                    ungetchar = -1;
                    fclose(current_file->fp);
                    current_file->fp = NULL;
                }

            } else
            {
                panic("Cannot fork",strerror(errno),NULL);
            }
#else
        panic("Input preprocessing is not supported in this system",NULL,NULL);
#endif
        }
        if(current_file->fp == NULL) current_file->fp = xfopen(current_file->name,"r",'b');
    }
    return 1;
}

/* read from input stream. 
   Check if ungetchar contains a valid char and write it to buffer then read nmenb - 1 chars
   NOTE! it is assumed that size == 1...
*/

static size_t
uc_fread(uint8_t *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = 0;

    if(ungetchar != -1)  // there is peeked char in ungetchar, write it to buffer and read the rest
    {
        *ptr = (uint8_t) ungetchar;
        ungetchar = -1;
        ptr++;
        nmemb--;
        ret = 1;
    }

    ret += fread(ptr,size,nmemb,stream);
    return ret;
}



/* flush buffer
   discard read data, and fill the rest of the buffer with new data
*/
void
flush_buffer()
{
    size_t tomove;
    if(buffer_start == new_data) return;
    if(data_end < buffer_end) return;

    tomove = data_end - new_data;

    memmove(buffer_start,new_data,tomove);
    data_end = buffer_start + tomove + uc_fread(buffer_start + tomove,(size_t) 1,(size_t) BUFFER_SIZE - tomove,current_file->fp);
    new_data = buffer_start;

    buffer_state = S_BUFFER_STALE; 
}

/* returns true if buffer has good data in address
 */
inline int
buffer_address_safe(BUFFER *address)
{
    return (address >= buffer_start && address < data_end);
}


/* return pointer to new_data */
inline BUFFER *
buffer_data()
{
    return new_data;
}


/* buffer management */
/* commands are:
   B_INIT - initialize buffer after opening a file, return 0 if nothing could be read
   B_DESIRED - try to get size data on buffer, return 1 in every case
   B_NEEDED -  try to get size data on buffer, return 1 if success, 0 id not
   B_FLUSH - data in buffer has been used, read more if low_water has been reached
   B_PRINTED - data in buffer (below new_data) has been printed, so state can be changed to OK

   return 1 if ok, 0 if not possible or error
*/
int
buffer(int command, size_t size)
{
    switch(command)
    {
        case B_INIT:
            if(buffer_start == NULL) 
            {
                buffer_start = xmalloc(BUFFER_SIZE);
                buffer_end = buffer_start + BUFFER_SIZE;
                low_water = buffer_end - (BUFFER_SIZE >> 3);    // low water is bufferSize/8 before end
            }

            data_end = buffer_start + uc_fread(buffer_start,(size_t) 1,BUFFER_SIZE,current_file->fp);
            buffer_state = S_BUFFER_OK; 
            new_data = buffer_start;
            if(buffer_start == data_end) return 0;                   // got nothing, probably empty file
            break;
        case B_DESIRED:
            if(data_end - new_data >= size) return 1;
            flush_buffer();
            break;
        case B_NEEDED:
            if(data_end - new_data >= size) return 1;
            flush_buffer();
            if(data_end - new_data >= size) return 1;
            return 0;
            break;
        case B_FLUSH:
            if(new_data >= low_water) flush_buffer();
            break;
        case B_FLUSH_FORCE:
            flush_buffer();
            break;
        case B_PRINTED:
            if(new_data >= low_water) flush_buffer();                // flush if sensible
            buffer_state = S_BUFFER_OK;
            break;
    }
    return 1;
}

/* return buffer state */
int
get_buffer_state()
{
    return buffer_state;
}

/* search buffer for a octet */
/* return the number of bytes from new_data + offset pointer where octet has found */
/* skips first offset bytes */
/* return -1 if not found */
static int
do_search_buffer_c(BUFFER c,size_t offset)
{
    register BUFFER *p;

    p = buffer_data() + offset;
    while(buffer_address_safe(p) && *p != c) p++;
    if(!buffer_address_safe(p)) return -1;
    return (int) (p - new_data);
}

/* search buffer for a octet */
/* return the number of bytes from new_data + offset pointer where octet has found */
/* return -1 if not found */
int
search_buffer_c(BUFFER c,size_t offset)
{
    int ret;
    
    ret = do_search_buffer_c(c,offset);
    if(ret == -1)                          // flush and search again
    {
        buffer(B_FLUSH_FORCE,0);
        ret = do_search_buffer_c(c,offset);
    }
    return ret;
}

/* search buffer for a string (not null terminated) */
/* return the number of bytes from new_data + offset pointer where octet has found */
/* return -1 if not found */
static int
do_search_buffer_s(BUFFER *s,size_t len,size_t offset)
{
    register BUFFER *p;

    p = buffer_data() + offset;

    while(buffer_address_safe(p + len - (size_t) 1) && memcmp(p,s,len) != 0) p++;
    if(!buffer_address_safe(p + len - (size_t) 1)) return -1;
    return (int) (p - new_data);
}

/* search buffer for a string (not null terminated) */
/* return the number of bytes from new_data + offset pointer where octet has found */
/* return -1 if not found */
int
search_buffer_s(BUFFER *s,size_t len,size_t offset)
{
    int ret;
    
    if(len == 0) return -1;
    
    if(len == 1) return search_buffer_c(*s,offset);

    ret = do_search_buffer_s(s,len,offset);
    if(ret == -1)                          // flush and search again
    {
        buffer(B_FLUSH_FORCE,0);
        ret = do_search_buffer_s(s,len,offset);
    }
    return ret;
}

/* return the size of unread data */
inline size_t
buffer_unread()
{
    return (data_end - new_data);
}

/* return true if there is no unread data on disk, everything is in buffer */
int
is_file_read()
{
    return (data_end < buffer_end);
}

/* move the new_data forward */
/* buffer_unread buffer_address_safe should be called before doing this */
VOID
buffer_read(size_t size)
{
    new_data += size;
    current_file->offset += (FILE_OFFSET) size;
    toffset += (FILE_OFFSET) size;
}

/* move pointer forward for peeking the next value */
VOID
buffer_ahead()
{
    if(buffer_address_safe(buffer_data() + 1)) new_data++;
}

/* move pointer back after peeking the next value */
VOID
buffer_back()
{
    if(buffer_address_safe(buffer_data() - 1)) new_data--;
}


/* current file */
char *
get_current_file_name()
{
    return current_file->name;
}

/* return current file offset */
FILE_OFFSET 
file_offset()
{
    return current_file->offset;
}


/* return current total offset */
FILE_OFFSET 
total_offset()
{
    return toffset;
}

/* return true if End of file is reached */
int 
buffer_eof()
{
    return (is_file_read() && !buffer_unread());    // nothing to read from file and buffer is exhausted
}


/* buffer could not be read, e.g. there was not enough data for tag to read */
void
buffer_error(char *message,struct tlvitem *e)
{
    size_t write_to_debug;
    char *file = "tlve.debug";
    FILE *fp;

    if(message) fprintf(stderr,"%s: %s, in file '%s', offset %lld\n",program_name,message,current_file->name,(long long int) current_file->offset - (long long int) (e ? e->raw_tl_length : 0));

    if(debug)
    {
        write_to_debug = buffer_unread();
        if(write_to_debug > 256) write_to_debug = 256;
        if(write_to_debug)
        {
            fp = xfopen(file,"w",'b');
            fwrite(buffer_data(),write_to_debug,1,fp);
            fprintf(stderr,"%s: first %d bytes of unprocessable data written to %s\n",program_name,(int) write_to_debug,file);
            fclose(fp);
        }
    }

    if(e)
    {
        size_t pl = 10;
        
        fprintf(stderr,"%s: Item info: Level: %u, Tag: %s, Length: %lld, Consumed: %lld, Remaining in buffer: %u, Dump: "
                ,program_name,e->level,e->tag,(long long int) e->length,(long long int) (e->raw_tl_length + e->raw_value_length)
                ,(unsigned int) buffer_unread());
        
        if(e->raw_tl_length + e->raw_value_length < pl) pl = e->raw_tl_length + e->raw_value_length;
        fprintf(stderr," %s\n",print_list_hex_dump(e->raw_tl,pl));

    }
    panic(NULL,NULL,NULL);
}
