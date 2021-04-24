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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif


#ifdef PACKAGE
char *program_name = PACKAGE;
#else
char *program_name = "tlve";
#endif

#ifdef PACKAGE_VERSION
char *version = PACKAGE_VERSION;
#else
char *version = "0.1.0";
#endif

#ifdef HOST
char *host = HOST;
#else
char *host = "";
#endif

#ifdef BUILD_DATE
char *build_date = BUILD_DATE;
#else
char *build_date = "";
#endif

#ifdef PACKAGE_BUGREPORT
char *email_address = PACKAGE_BUGREPORT;
#else
char *email_address = "tjsa@iki.fi";
#endif


#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

/* Global data */

struct structure structure;
struct tldef *tl = NULL;
struct print *print = NULL;
struct hold *hold = NULL;
struct type_mappings *type_maps = NULL;
char *codeset = "";           // current code set
int debug = 0;                // write debug data in case of processing error
char *tlve_open = NULL;

static void usage (int status);

static char short_opts[] = "o:hVc:dn:s:e:ap:l:L:";

#ifdef HAVE_GETOPT_LONG
static struct option long_opts[] =
{
  {"output", 1, 0, 'o'},
  {"help", 0, 0, 'h'},
  {"version", 0, 0, 'V'},
  {"configuration", 1, 0, 'c'},
  {"debug", 0, 0, 'd'},
  {"name-list", 1, 0, 'n'},
  {"structure", 1, 0, 's'},
  {"expression", 1, 0, 'e'},
  {"and", 0, 0, 'a'},
  {"print", 1, 0, 'p'},
  {"start-level", 1, 0, 'l'},
  {"stop-level", 1, 0, 'L'},
  {NULL, 0, NULL, 0}
};
#endif

static void
usage (int);

void
panic(char *msg,char *info,char *syserror)
{
    if(msg != NULL)
    {
        if (info == NULL && syserror == NULL)
        {
            fprintf(stderr,"%s: %s\n",program_name,msg);
        } else if(info != NULL && syserror == NULL)
        {
            fprintf(stderr,"%s: %s: %s\n",program_name,msg,info);
        } else if(info != NULL && syserror != NULL)
        {
            fprintf(stderr,"%s: %s: %s; %s\n",program_name,msg,info,syserror);
        } else if(info == NULL && syserror != NULL)
        {
            fprintf(stderr,"%s: %s; %s\n",program_name,msg,syserror);
        }
    }
    exit(EXIT_FAILURE);
}

char *
get_default_rc_name()
{
    char *home;
    char *result;
#ifdef WIN32
    char *file = "tlve.rc";
#else
    char *file = ".tlverc";
#endif

    result = NULL;
    home = getenv("HOME");
#ifdef WIN32
    if(home == NULL)
    {
        home = getenv("USERPROFILE");
    }
#endif
    if(home != NULL)
    {
        result = xmalloc(strlen(home) + strlen(file) + strlen(PATH_SEPARATOR_STRING) + 2);
        strcpy(result,home);
        strcat(result,PATH_SEPARATOR_STRING);
        strcat(result,file);
    } else
    {
        result = file;
    }
    return result;
}

void
print_version()
{
    printf("%s version %s\n%s %s %s\n",program_name,version,build_date,host,codeset);
    printf("Copyright (c) 2009 Timo Savinen\n\n");
    printf("This is free software; see the source for copying conditions.\n");
    printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
}


int
main (int argc, char **argv)
{
    int opt;
    char *print_to_use = NULL;
    char *config_to_use = NULL;
    char *output_to_use = NULL;
    char *structure_to_use = NULL;

#ifdef HAVE_SIGACTION
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    act.sa_flags = SA_NOCLDWAIT;
    sigaction (SIGCHLD, &act, NULL);
#endif

    setlocale(LC_ALL,"");

#ifdef HAVE_NL_LANGINFO
    codeset = xstrdup(nl_langinfo(CODESET));
#endif

#ifdef HAVE_GETOPT_LONG
    while ((opt = getopt_long(argc,argv,short_opts,long_opts,NULL)) != -1)
#else
    while ((opt = getopt(argc,argv,short_opts)) != -1)
#endif
    {
        switch(opt)
        {
            case 'c':
                if(config_to_use == NULL)
                {
                    config_to_use = xstrdup(optarg);
                } else
                {
                    panic("Only one -c option allowed",NULL,NULL);
                }
                break;
            case 's':
                if(structure_to_use == NULL)
                {
                    structure_to_use = xstrdup(optarg);
                } else
                {
                    panic("Only one -s option allowed",NULL,NULL);
                }
                break;
            case 'p':
                if(print_to_use == NULL)
                {
                    print_to_use = xstrdup(optarg);
                } else
                {
                    panic("Only one -p option allowed",NULL,NULL);
                }
                break;
            case 'o':
                if(output_to_use == NULL)
                {
                    output_to_use = xstrdup(optarg);
                } else
                {
                    panic("Only one -o option allowed",NULL,NULL);
                }
                break;
            case 'n':
                print_list_add_names(optarg);
                break;
            case 'e':
                print_list_add_expression(optarg);
                break;
            case 'a':
                expression_and = 1;
                break;
            case 'd':
                debug = 1;
                break;
            case 'l':
                print_set_print_start_level(atoi(optarg));
                break;
            case 'L':
                print_set_print_stop_level(atoi(optarg));
                break;
            case '?':
                usage(EXIT_SUCCESS);
                break;
            case 'V':
                print_version();
                exit(EXIT_SUCCESS);
                break;
            default:
                usage(EXIT_FAILURE);
                break;
        }
    }

    if(optind < argc)
    {
        while(optind < argc) set_input_file(argv[optind++]);
    } else
    {
        set_input_file("-");
    }
     
    tlve_open = getenv("TLVEOPEN");

    if(config_to_use == NULL) config_to_use = get_default_rc_name();
    if(structure_to_use == NULL) structure_to_use = "default";

    parse_rc(config_to_use,structure_to_use,print_to_use);

    print_list_check_names();

    if(output_to_use == NULL) output_to_use = "-";
    print_list_open_output(output_to_use);

    execute();

    print_list_close_output();

    exit (EXIT_SUCCESS);
}


static void
usage (int status)
{
  printf ("%s - \
A program to parse tag-length-value structures and print them in different formats\n", program_name);
  printf ("Usage: %s [OPTION]... [FILE]...\n", program_name);
  printf ("\
Options:\n\
  -c, --configuration NAME    read configuration from NAME instead of ~/.tlverc\n\
  -d, --debug                 dump unprocessable data to tlve.debug\n\
  -n, --name-list LIST        print only elements having name or tag in comma separated list LIST\n\
  -s, --structure NAME        use structure NAME to process the input data\n\
  -e, --expression NAME=VALUE print only elements for which the expression NAME=VALUE evaluates true\n\
  -a, --and                   all expressions must evaluate true\n\
  -p, --print NAME            use printing definition NAME to print the data\n\
  -o, --output NAME           send output to NAME instead of standard output\n\
  -l, --start-level LEVEL     first level in element hierarchy to be printed\n\
  -L, --stopt-level LEVEL     last level in element hierarchy to be printed\n\
  -h, --help                  display this help and exit\n\
  -V, --version               output version information and exit\n\
\nAll remaining arguments are names of input files;\n\
if no input files are specified, then the standard input is read.\n\
");
  printf ("\nSend bug reports to %s\n", email_address);
  exit (status);
}
