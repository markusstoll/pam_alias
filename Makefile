SRCS=	pam_alias.c
OBJS=	${SRCS:.c=.o}
SOLIB=	pam_alias.so
SOLIBDB= pam_aliasdb.so
MAN=	pam_alias.8
MANDB=	pam_aliasdb.8

PAMDIR?=	/lib/x86_64-linux-gnu/security
MANDIR?=	/usr/share/man

CFLAGS+=	-std=c99 -fPIC -Wall

all: ${SOLIB} ${MAN} ${SOLIBDB} ${MANDB}

install: all
	install -o root -g root -m 755 ${SOLIB} ${PREFIX}${PAMDIR}
	install -o root -g root -m 444 ${MAN} ${PREFIX}${MANDIR}/man8
	install -o root -g root -m 755 ${SOLIBDB} ${PREFIX}${PAMDIR}
	install -o root -g root -m 444 ${MANDB} ${PREFIX}${MANDIR}/man8

pam_alias.so: pam_alias.c
	${CC} -D_GNU_SOURCE -shared -o $@ $<

pam_aliasdb.so: pam_aliasdb.o
	${CC} -shared -o $@ $< -ldb

pam_aliasdb.o: pam_aliasdb.c
	${CC} -c $<

%.8: %.8.xml
	xsltproc -o $@ --path . --xinclude --nonet /usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl $<

clean:
	-rm -f ${SOLIBDB} ${MANDB} ${SOLIB} ${OBJS} ${MAN} *.o *~
