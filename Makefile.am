AUTOMAKE_OPTIONS	=	foreign

SUFFIXES		=	.sysconfig .sysconfig.in		\
				.service .service.in			\
				.init .init.in				\
				.8 .8.in

sbin_PROGRAMS		=	saveclock

saveclock_SOURCES	=	saveclock.c

storage_DATA		=	lastclock

EXTRA_DIST		=	saveclock.spec				\
				saveclock.sysconfig.in			\
				saveclock.init.in			\
				saveclock.service.in			\
				saveclock.8.in

man8_MANS		=	saveclock.8

noinst_DATA		=	saveclock.service			\
				saveclock.init				\
				saveclock.sysconfig

lastclock:	FRC
	LANG=C date -u +%c > lastclock

FRC:


SED_CMD			=	sed -e "s,[@]SYSCONFDIR[@],${sysconfdir},g" \
				    -e "s,[@]SBINDIR[@],${sbindir},g"	\
				    -e "s,[@]RUNDIR[@],${RUNDIR},g"	\
				    -e "s,[@]LOCKDIR[@],${LOCKDIR},g"	\
				    -e "s,[@]STORAGEDIR[@],${STORAGEDIR},g"

.sysconfig.in.sysconfig:
	${SED_CMD} < $< > $@ && touch -r $< $@

.service.in.service:
	${SED_CMD} < $< > $@ && touch -r $< $@

.init.in.init:
	${SED_CMD} < $< > $@ && touch -r $< $@

.8.in.8:
	${SED_CMD} < $< > $@ && touch -r $< $@
