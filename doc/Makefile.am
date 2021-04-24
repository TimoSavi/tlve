AUTOMAKE_OPTIONS = info-in-builddir
man_MANS = tlve.1
info_TEXINFOS = tlve.texi
tlve_TEXINFOS = texinfo.css
CLEANFILES = tlve.html tlve.info

htmldir=$(docdir)
html_DATA = tlve.html 
AM_MAKEINFOHTMLFLAGS = --no-split --css-include=texinfo.css --no-headers

EXTRA_DIST = $(man_MANS) $(info_TEXINFOS) $(html_DATA)
