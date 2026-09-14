# tlve
tlve is a command-line tool for parsing different TLV (tag-length-value) structures and printing them in various text-based formats. tlve is designed for processing TLV files in server environments.
See [manual](http://htmlpreview.github.io/?https://github.com/TimoSavi/tlve/blob/main/doc/tlve.html) for more details.

## Build from source
GNU Autotools and GCC are required to build tlve.

Clone from GitHub and then:

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
