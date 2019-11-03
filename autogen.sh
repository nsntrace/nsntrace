#!/bin/sh
aclocal \
&& autoreconf --install \
&& automake --add-missing
