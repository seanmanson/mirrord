# s4284641 - Sean Manson
# COMP3301 Assignment 1 - basic web server

.PATH: ${.CURDIR}/http_parser

PROG=mirrord
SRCS=mirrord.c
SRCS+= http_parser.c
MAN=
LDADD=-levent
DPADD=${LIBEVENT}
CFLAGS+= -g -Wall -Werror

.include <bsd.prog.mk>
