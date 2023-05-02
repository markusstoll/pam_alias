pam_alias - map user names using an arbitrary file
pam_aliasdb - map user names using a berkeley db file
=====================================================

pam_alias is a PAM module which provides a way to map user names using
an arbitrary file.

For example, it can rewrite mail address- or jid-style user names to
local user names.

      foo@sub.example.org	loclfoo

will map the user name `foo@sub.example.org` to `loclfoo`, which will
then be used in turn by the following PAM modules.

pam_aliasdb is a PAM module which provides a way to map user names using
a berkeley db file. You can create such a berkeley db file from the flat file 
described above using

    exim_dbmbuild useralias useralias.db


Prerequirements
---------------

  apt install linux-libc-dev
  apt install libpam0g-dev
  apt install docbook-xsl
  apt install xsltproc
  
Installation
------------

make install


Usage
-----

Add something like this to the beginning of select PAM configs:

    auth required pam_alias.so file=/etc/security/useralias

or using the berkeley db file

    auth required pam_aliasdb.so db=/etc/security/useralias.db

For more details, see the pam_alias(8) and pam_aliasdb(8) manual pages.


Author
------

Copyright (c) 2012 Simon Schubert <2@0x2c.org>
Copyright (c) 2023 Markus Stoll <markus.stoll@junidas.de>

pam_alias and pam_aliasdb are licensed under the GPL3 or later.
