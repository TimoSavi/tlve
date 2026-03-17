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

## Build Debian package
Before you can build the Debian package, you need to install

    - build-essential
    - debhelper
    - dpkg-dev

Building the Debian package is done with a simple command:

    dpkg-buildpackage -us -uc

The build results, including the Debian packages, can be found one directory up:

    ../tlve-dbgsym_2.3-24_amd64.ddeb
    ../tlve_2.3-24.dsc
    ../tlve_2.3-24.tar.gz
    ../tlve_2.3-24_amd64.buildinfo
    ../tlve_2.3-24_amd64.changes
    ../tlve_2.3-24_amd64.deb
