#--------------------------------------------------------------------------
#
# [ pam_capability ] the capabilities pam module
#
# Copyright (C) 2002 Erik M. A. Kline
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Please see the file "GPL" in the "meta" subdirectory of the top level source
# directory, if you have received this program with source code.
#
# For further information or concerns please contact:
#
#     Erik Kline
#     ekline@ekline.com, or
#     erik@alum.mit.edu
#
#--------------------------------------------------------------------------

# BEGIN  user-modifiable parts
PAM_MOD_DIR  = /lib/security
PAM_CAP_CONF = /etc/security/capability.conf
MAN_TOP_DIR  = /usr/share/man
DOC_TOP_DIR  = /usr/share/doc
# END    user-modifiable parts

PAM_MOD_NAME = pam_capability
PAM_MOD_VERS = 0.23-pre

FILES =		$(PAM_MOD_NAME).o

MAN_FILES =	capability.conf.5       \
		pam_capability.8

DOC_FILES =	ACKNOWLEDGEMENTS        \
		CHANGELOG               \
		README                  \
		patch-capfix-2.4.18     \
		sample-capability.conf

DOC_DIR =	$(DOC_TOP_DIR)/$(PAM_MOD_NAME)-$(PAM_MOD_VERS)

CC = gcc
CFLAGS = -Wall -O2 -fPIC -D"CONF_FILE=\"$(PAM_CAP_CONF)\"" \
         -D"MOD_VERS=\"$(PAM_MOD_VERS)\""
LD = ld
LDFLAGS = --shared -x
LIBS = -lcap
INSTALL = cp

all:		$(PAM_MOD_NAME).so

$(PAM_MOD_NAME).so:	$(FILES)
	$(LD) $(LDFLAGS) $(LIBS) -o $(PAM_MOD_NAME).so $(FILES)

install:	install-pam install-man

install-all:	install install-doc

install-pam:	all
	$(INSTALL) $(PAM_MOD_NAME).so $(PAM_MOD_DIR)
	@echo ""

install-conf:	all
	if [ ! -f $(PAM_CAP_CONF) ]; then                         \
	    $(INSTALL) sample-capability.conf $(PAM_CAP_CONF)  && \
	      chown root:root $(PAM_CAP_CONF)                  && \
	      chmod 0644 $(PAM_CAP_CONF);                         \
	fi
	@echo ""

install-man:
	for man_file in $(MAN_FILES); do                                      \
		section=`echo $${man_file} | awk -F. '{ print $$NF }'         \
			 2>/dev/null`;                                        \
		$(INSTALL) $${man_file} $(MAN_TOP_DIR)/man$${section} &&      \
		chown root:root $(MAN_TOP_DIR)/man$${section}/$${man_file} && \
		chmod 0644 $(MAN_TOP_DIR)/man$${section}/$${man_file};        \
	done
	@echo ""

install-doc:
	if [ ! -d $(DOC_DIR) ]; then mkdir $(DOC_DIR); fi
	$(INSTALL) $(DOC_FILES) $(DOC_DIR)
	@echo ""
	for man_file in $(MAN_FILES); do                                      \
		section=`echo $${man_file} | awk -F. '{ print $$NF }'         \
			 2>/dev/null`;                                        \
		if [ ! -d $(DOC_DIR)/man$${section} ]; then                   \
			mkdir $(DOC_DIR)/man$${section};                      \
		fi;                                                           \
		$(INSTALL) $${man_file} $(DOC_DIR)/man$${section};            \
	done
	@echo ""
	chown -R root:root $(DOC_DIR)
	chmod -R go-w $(DOC_DIR)

clean:
	rm -f *.o *.so core

.c.o:
	$(CC) $(CFLAGS) -c -o $*.o $<

