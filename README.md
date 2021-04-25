# tlve
tlve is a command-line tool to parse different tlv (tag-length-value) structures and for printing them in different text-based formats. tlve is mentioned for processing tlv files in server environments.
See [manual](http://htmlpreview.github.io/?https://github.com/TimoSavi/tlve/blob/main/doc/tlve.html) for more details.

## Build from source
GNU autotools and gcc are required to build tlve.

Clone from github and then:

    cd tlve
    autoreconf -is
    ./configure
    make

