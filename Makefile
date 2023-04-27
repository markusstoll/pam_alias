SRCS=	pam_alias.c
OBJS=	${SRCS:.c=.o}
SOLIB=	pam_alias.so
MAN=	pam_alias.8

PAMDIR?=	/lib/x86_64-linux-gnu/security
MANDIR?=	/usr/share/man

CFLAGS+=	-std=c99 -fPIC -Wall

all: ${SOLIB} ${MAN}

install:
	install -o root -g root -m 755 ${SOLIB} ${PREFIX}${PAMDIR}
	install -o root -g root -m 444 ${MAN} ${PREFIX}${MANDIR}/man8

${SOLIB}: ${OBJS}
	${CC} -shared -o $@ $<

%: %.xml
	xsltproc -o $@ --path . --xinclude --nonet /usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl $<

clean:
	-rm -f ${SOLIB} ${OBJS} ${MAN}
