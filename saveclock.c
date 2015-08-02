/*
 *	saveclock - Save/restore clock from file.
 *	Copyright (C) 2015 Patrick Monnerat <pm@datasphere.ch>
 *
 *	To be used with NTP when no hardware clock is available.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>


/* Daemon flags. */

#define DMN_LOG_TO_STDERR	0000001
#define DMN_NO_SYSLOG		0000002
#define DMN_LOCKFILE_CREATED	0000004
#define DMN_PIDFILE_CREATED	0000010

typedef struct {
	const char *		program;	/* Program name (for log). */
	const char *		user;		/* Running user. */
	const char *		group;		/* Running group. */
	uid_t			uid;		/* Running user id. */
	gid_t			gid;		/* Running group id. */
	const char *		home;		/* Current directory. */
	const char *		jail;		/* Jail directory. */
	const char *		lock_file;	/* Lock file path. */
	const char *		pid_file;	/* Process id file path. */
	sigset_t		signals;	/* Saved signal mask. */
	int			lockfd;		/* Lock file descriptor. */
	int			facility;	/* Syslog facility. */
	unsigned short		flags;		/* Flags. */
}		daemon_t;


#define ACTION_STOP		0001
#define ACTION_SAVE		0002
#define ACTION_RESTORE		0004


unsigned int		period = 60;
unsigned char		force = 0;
char *			clockfile = STORAGEDIR "/lastclock";
daemon_t		dmn;
unsigned char		actions;


static int
setString(const char * * cpp, const char * strg)

{
	size_t i;
	char * cp;

	if (*cpp) {
		free((char *) *cpp);
		*cpp = NULL;
		}

	if (!strg)
		return 0;

	i = strlen(strg) + 1;
	cp = malloc(i);

	if (!cp)
		return -1;

	memcpy(cp, strg, i);
	*cpp = cp;
	return 0;
}


int
setProgram(daemon_t * dp, const char * path)

{
	const char * cp;
	const char * pgmname;

	pgmname = NULL;

	for (cp = path; *cp;)
		if (*cp++ == '/')
			pgmname = cp;

	if (!pgmname || !pgmname[0])
		pgmname = path;

	return setString(&dp->program, pgmname);
}


int
setGroup(daemon_t * dp, const char * gid_or_name)

{
	struct group grp;
	struct group * gp;
	int err;
	char buf[1024];

	if (gid_or_name || !gid_or_name[0])
		setString(&dp->group, NULL);
	else if (geteuid()) {
		errno = EPERM;
		return -1;
		}
	else if ((err = getgrnam_r(gid_or_name, &grp, buf, sizeof buf, &gp))) {
		errno = err;
		return -1;
		}
	else if (gp) {
		if (setString(&dp->group, gid_or_name))
			return -1;

		dp->gid = grp.gr_gid;
		}
	else if (gid_or_name[strspn(gid_or_name, "0123456789")]) {
		errno = ENOENT;
		return -1;
		}
	else if ((err = getgrgid_r(atoi(gid_or_name),
		    		   &grp, buf, sizeof buf, &gp))) {
		errno = err;
		return -1;
		}
	else if (gp) {
		if (setString(&dp->group, grp.gr_name))
			return -1;

		dp->gid = grp.gr_gid;
		}
	else {
		errno = ENOENT;
		return -1;
		}

	return 0;
}


int
setGID(daemon_t * dp, gid_t groupid)

{
	struct group grp;
	struct group * gp;
	int err;
	char buf[1024];

	if (geteuid()) {
		errno = EPERM;
		return -1;
		}

	err = getgrgid_r(groupid, &grp, buf, sizeof buf, &gp);

	if (err) {
		errno = err;
		return -1;
		}

	if (!gp) {
		errno = ENOENT;
		return -1;
		}

	if (setString(&dp->group, grp.gr_name))
		return -1;

	dp->gid = grp.gr_gid;
	return 0;
}

int
setUser(daemon_t * dp, const char * uid_or_name)

{
	struct passwd pwd;
	struct passwd * pp;
	int err;
	char buf[1024];

	if (!uid_or_name || !uid_or_name[0])
		setString(&dp->user, NULL);
	else if (geteuid()) {
		errno = EPERM;
		return -1;
		}
	else if ((err = getpwnam_r(uid_or_name, &pwd, buf, sizeof buf, &pp))) {
		errno = err;
		return -1;
		}
	else if (pp) {
		if (setGID(dp, pwd.pw_gid) || setString(&dp->user, uid_or_name))
			return -1;

		dp->uid = pwd.pw_uid;
		}
	else if (uid_or_name[strspn(uid_or_name, "0123456789")]) {
		errno = ENOENT;
		return -1;
		}
	else if ((err = getpwuid_r(atoi(uid_or_name),
	    			   &pwd, buf, sizeof buf, &pp))) {
		errno = err;
		return -1;
		}
	else if (pp) {
		if (setGID(dp, pwd.pw_gid) || setString(&dp->user, pwd.pw_name))
			return -1;

		dp->uid = pwd.pw_uid;
		}
	else {
		errno = ENOENT;
		return -1;
		}

	return 0;
}


int
setUID(daemon_t * dp, uid_t userid)

{
	struct passwd pwd;
	struct passwd * pp;
	int err;
	char buf[1024];

	if (geteuid()) {
		errno = EPERM;
		return -1;
		}

	if ((err = getpwuid_r(userid, &pwd, buf, sizeof buf, &pp))) {
		errno = err;
		return -1;
		}

	if (!pp) {
		errno = ENOENT;
		return -1;
		}

	if (setGID(&dmn, pwd.pw_gid) || setString(&dp->user, pwd.pw_name))
		return -1;

	dp->uid = userid;
	return 0;
}


int setHome(daemon_t * dp, const char * home)

{
	return setString(&dp->home, home);
}


int setJail(daemon_t * dp, const char * jail)

{
	if (jail && !jail[0])
		jail = NULL;

	if (jail && geteuid()) {
		errno = EPERM;
		return -1;
		}

	return setString(&dp->jail, jail);
}


int
setLockFile(daemon_t * dp, const char * lockfile)

{
	char buf[1024];

	if (lockfile && !lockfile[0])
		lockfile = NULL;

	if (lockfile && !strchr(lockfile, '/')) {
		strcpy(buf, LOCKDIR "/");
		strcat(buf, lockfile),
		lockfile = buf;
		}

	return setString(&dp->lock_file, lockfile);
}


int
setPIDFile(daemon_t * dp, const char * pidfile)

{
	char buf[1024];

	if (pidfile && !pidfile[0])
		pidfile = NULL;

	if (pidfile && !strchr(pidfile, '/')) {
		strcpy(buf, RUNDIR "/");
		strcat(buf, pidfile),
		pidfile = buf;
		}

	return setString(&dp->pid_file, pidfile);
}


int
detach(daemon_t * dp)

{
	switch (fork()) {

	case -1:
		return -1;

	case 0:						// Child.
		break;

	default:					// Father.
		exit(EXIT_SUCCESS);
		}

	setsid();				// Create new session.

	/* Let the session master be adopted by the init process. */

	switch (fork()) {

	case -1:
		return -1;

	case 0:						// Child.
		break;

	default:					// Father.
		exit(EXIT_SUCCESS);
		}

	return 0;
}


void
closeAll(daemon_t * dp)

{
	int fd;

	for (fd = getdtablesize(); --fd > fileno(stderr);)
		close(fd);

	if (!(dp->flags & DMN_LOG_TO_STDERR))
		close(fd);

	while (fd--)
		close(fd);

	//	Open bit buckets on standard file descriptors.

	for (fd = open("/dev/null", O_RDWR); fd >= 0; fd = dup(fd))
		if (fd >= fileno(stderr)) {
			if (fd > fileno(stderr))
				close(fd);

			break;
			}
}


int
lock(daemon_t * dp)
{
	if (dp->lockfd >= 0) {
		errno = EDEADLK;
		return -1;
		}

	if (!dp->lock_file) {
		if (!dp->program) {
			errno = EINVAL;
			return -1;
			}

		if (setLockFile(&dmn, dp->program))
			return -1;
		}

	dp->lockfd = open(dp->lock_file, O_RDWR | O_CREAT,
	    		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (dp->lockfd < 0)
		return -1;

	if (lockf(dp->lockfd, F_TLOCK, 0) < 0) {
		close(dp->lockfd);

		if (errno == EACCES || errno == EAGAIN)
			return 0;		/* Already locked. */

		return -1;
		}

	dp->flags |= DMN_LOCKFILE_CREATED;

	/* Do not close the file to keep lock on it. */
	return 1;				/* We just locked it. */
}


void
unlock(daemon_t * dp)
{
	if (dp->lockfd >= 0) {
		close(dp->lockfd);
		dp->lockfd = -1;
		}
}


void
deleteLockFile(daemon_t * dp)

{
	unlock(dp);

	if (dp->flags & DMN_LOCKFILE_CREATED) {
		unlink(dp->lock_file);
		dp->flags &= ~DMN_LOCKFILE_CREATED;
		}
}


int
writePID(daemon_t * dp)

{
	FILE * fp;
	char buf[1024];

	if (!dp->pid_file) {
		if (!dp->program) {
			errno = EINVAL;
			return -1;
			}

		strcpy(buf, dp->program);
		strcat(buf, ".pid");
		if (setString(&dp->pid_file, buf))
			return -1;
		}

	fp = fopen(dp->pid_file, "w");

	if (!fp)
		return -1;

	dp->flags |= DMN_PIDFILE_CREATED;

	if (fprintf(fp, "%u", (unsigned int) getpid()) < 0) {
		fclose(fp);
		return -1;
		}

	fclose(fp);
	return 0;
}


void
deletePIDFile(daemon_t * dp)

{
	if (dp->flags & DMN_PIDFILE_CREATED) {
		unlink(dp->pid_file);
		dp->flags &= ~DMN_PIDFILE_CREATED;
		}
}


int
goHome(daemon_t * dp)

{
	return dp->home && chdir(dp->home)? -1: 0;
}


void
openLog(daemon_t * dp, int option)

{
	closelog();

	if (!(dp->flags & DMN_NO_SYSLOG)) {
		if (dp->jail)
			option = (option & LOG_ODELAY) | LOG_NDELAY;

		if (dp->flags & DMN_LOG_TO_STDERR)
			option |= LOG_PERROR;

		openlog(dp->program, option, dp->facility);
		}
}

int
incarcerate(daemon_t * dp)

{
	return dp->jail && chroot(dp->jail)? -1: 0;
}


int
changeIdentity(daemon_t * dp)

{
	if (dp->user || dp->group) {
		if (setgid(dp->gid))
			return -1;

		setgroups(1, &dp->gid);
		}

	return dp->user && setuid(dp->uid)? -1: 0;
}


void
blockSignals(daemon_t * dp)

{
	sigset_t all;

	sigfillset(&all);
	sigprocmask(SIG_BLOCK, &all, &dp->signals);
}


void
unblockSignals(daemon_t * dp)

{
	sigprocmask(SIG_SETMASK, &dp->signals, NULL);
}


void
ignoreSignals(daemon_t * dp)

{
	int signo;

	for (signo = 1; signo < _NSIG; signo++)
		signal(signo, SIG_IGN);
}


void
daemonInit(daemon_t * dp)

{
	memset(dp, 0, sizeof * dp);
	dp->lockfd = -1;
	dp->facility = LOG_DAEMON;
}


void
daemonDestroy(daemon_t * dp)

{
	unlock(dp);
	setString(&dp->program, NULL);
	setString(&dp->user, NULL);
	setString(&dp->group, NULL);
	setString(&dp->home, NULL);
	setString(&dp->jail, NULL);
	setString(&dp->lock_file, NULL);
	setString(&dp->pid_file, NULL);
}


void
vlogprintf(daemon_t * dp, int level, const char * fmt, va_list args)

{
	if (!(dp->flags & DMN_NO_SYSLOG))
		vsyslog(level | dp->facility, fmt, args);
	else if (dp->flags & DMN_LOG_TO_STDERR) {
		fprintf(stderr, "%s [%u]: ",
			dp->program, (unsigned int) getpid());
		vfprintf(stderr, fmt, args);
		putc('\n', stderr);
		}
}


/* VARARGS3 */
void
logprintf(daemon_t * dp, int level, const char * fmt, ...)

{
	va_list args;

	va_start(args, fmt);
	vlogprintf(dp, level, fmt, args);
	va_end(args);
}



void
myexit(int status)

{
	deletePIDFile(&dmn);
	deleteLockFile(&dmn);
	closelog();
	daemonDestroy(&dmn);
	exit(status);
	/* NOTREACHED */
}


int
saveclock(void)

{
	int fd;
	time_t now;
	size_t len;
	int i;
	struct tm tms;
	char buf[30];

	actions &= ~ACTION_SAVE;
	fd = open(clockfile, O_RDWR | O_CREAT,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

	if (fd < 0) {
		logprintf(&dmn, LOG_ERR, "%s: %s", clockfile, strerror(errno));
		return 2;
		}

	time(&now);
	gmtime_r(&now, &tms);
	asctime_r(&tms, buf);
	len = strlen(buf);
	i = write(fd, buf, len);

	if (i != len) {
		if (i >= 0)
			errno = EIO;

		close(fd);
		logprintf(&dmn, LOG_ERR, "&s: %s", clockfile, strerror(errno));
		return 2;
		}

	if (ftruncate(fd, (off_t) len)) {
		close(fd);
		logprintf(&dmn, LOG_ERR, "%s: %s", clockfile, strerror(errno));
		return 2;
		}

	if (fsync(fd)) {
		close(fd);
		logprintf(&dmn, LOG_ERR, "%s: %s", clockfile, strerror(errno));
		return 2;
		}

	close(fd);
	return 0;
}


int
restoreclock(void)

{
	int fd;
	int i;
	char * cp;
	time_t now;
	struct timeval tv;
	struct tm tms;
	char buf[30];

	actions &= ~ACTION_RESTORE;
	memset(&tms, 0, sizeof tms);
	memset(&tv, 0, sizeof tv);
	fd = open(clockfile, O_RDONLY);

	if (fd < 0) {
		logprintf(&dmn, LOG_ERR, "%s: %s", clockfile, strerror(errno));
		return 2;
		}

	i = read(fd, buf, sizeof buf);
	close(fd);

	if (i < 0) {
		logprintf(&dmn, LOG_ERR, "%s: %s", clockfile, strerror(errno));
		return 2;
		}

	if (i >= sizeof buf) {
		logprintf(&dmn, LOG_ERR, "%s: file too long", clockfile);
		return 2;
		}

	while (i-- && (buf[i] == '\r' || buf[i] == '\n' ||
	       buf[i] == ' ' || buf[i] == '\t'))
		;

	buf[++i] = '\0';
	cp = strptime(buf, "%c", &tms);

	if (!cp || cp != buf + i) {
		logprintf(&dmn, LOG_ERR, "%s: invalid data", clockfile);
		return 2;
		}

	tv.tv_sec = timegm(&tms);

	if (!force) {
		time(&now);

		if (tv.tv_sec < now) {
			logprintf(&dmn, LOG_ERR, "saved clock < now");
			return 2;
			}
		}

	if (settimeofday(&tv, NULL)) {
		logprintf(&dmn, LOG_ERR, "settimeofday: %s", strerror(errno));
		return 2;
		}

	return 0;
}


void
timepump(int signo)

{
	if (signo == SIGALRM)
		actions |= ACTION_SAVE;

	signal(SIGALRM, timepump);
	alarm(period);
}


void
bailout(int signo)

{
	actions |= ACTION_SAVE | ACTION_STOP;
}


void
usage(void)

{
	fprintf(stderr,
		"Usage: %s [-c <clockfile>] [-d] [-e] [-f] [-g <group>] \\\n",
		dmn.program);
	fprintf(stderr,
		"\t[-h <home>] [-i <period-seconds>] [-j <jaildir>\\\n");
	fprintf(stderr,
		"\t[-l <lockfile>] [-n] [-p <pidfile>] [-u <user>] %s\n",
		"[save | restore]");
	setPIDFile(&dmn, NULL);
	setLockFile(&dmn, NULL);
	myexit(1);
}


int
main(int argc, char * * argv)

{
	char * cp;
	unsigned short daemonize = 0;
	int i;

	daemonInit(&dmn);
	setProgram(&dmn, argv[0]);

	while (--argc) {
		cp = *++argv;

		if (*cp != '-')
			break;

		while (*++cp) {
			switch (*cp) {

			case 'c':
				if (!--argc)
					usage();

				clockfile = *++argv;
				break;

			case 'd':
				daemonize = 1;
				break;

			case 'e':
				dmn.flags |= DMN_LOG_TO_STDERR;
				break;

			case 'f':
				force = 1;

			case 'g':
				if (!--argc)
					usage();

				if (setGroup(&dmn, *++argv)) {
					perror(*argv);
					usage();
					}

				break;

			case 'h':
				if (!--argc)
					usage();

				setHome(&dmn, *++argv);
				break;

			case 'i':
				++argv;

				if (!--argc ||
				    (*argv)[strspn(*argv, "0123456789")])
					usage();

				period = atoi(*argv);
				break;

			case 'j':
				if (!--argc)
					usage();

				setJail(&dmn, *++argv);
				break;

			case 'l':
				if (!--argc)
					usage();

				setLockFile(&dmn, *++argv);
				break;

			case 'n':
				dmn.flags |= DMN_LOG_TO_STDERR | DMN_NO_SYSLOG;
				break;

			case 'p':
				if (!--argc)
					usage();

				setPIDFile(&dmn, *++argv);
				break;

			case 'u':
				if (!--argc)
					usage();

				if (setUser(&dmn, *++argv)) {
					perror(*argv);
					usage();
					}

				break;

			default:
				usage();
				}
			}
		}

	switch (argc) {

	case 0:
		break;

	case 1:
		dmn.flags |= DMN_LOG_TO_STDERR | DMN_NO_SYSLOG;

		if (!strcmp(*argv, "save"))
			myexit(saveclock());

		if (!strcmp(*argv, "restore"))
			myexit(restoreclock());

	default:
		usage();
		}

	blockSignals(&dmn);
	ignoreSignals(&dmn);

	if (daemonize)
		detach(&dmn);

	closeAll(&dmn);
	openLog(&dmn, LOG_PID);
	signal(SIGABRT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGILL, SIG_DFL);
	signal(SIGIOT, SIG_DFL);
	signal(SIGBUS, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
	signal(SIGSTKFLT, SIG_DFL);
	unblockSignals(&dmn);

	if (daemonize) {
		i = lock(&dmn);

		if (i < 0) {
			logprintf(&dmn, LOG_ERR,
				  "Lock file error: %s", strerror(errno));
			myexit(2);
			}

		if (!i) {
			logprintf(&dmn, LOG_WARNING,
				  "daemon already running: exit");
			myexit(2);
			}

		if (writePID(&dmn)) {
			logprintf(&dmn, LOG_ERR,
				  "PID file error: %s", strerror(errno));
			myexit(2);
			}
		}

	if (goHome(&dmn)) {
		logprintf(&dmn, LOG_ERR,
			  "Home directory: %s", strerror(errno));
		myexit(2);
		}

	umask(0002);
	incarcerate(&dmn);
	changeIdentity(&dmn);
	actions = ACTION_RESTORE;
	signal(SIGHUP, bailout);
	signal(SIGQUIT, bailout);
	signal(SIGTERM, bailout);

	if (period)
		timepump(SIGUSR1);

	for (;;)
		if (actions & ACTION_RESTORE)
			restoreclock();
		else if (actions & ACTION_SAVE)
			saveclock();
		else if (actions & ACTION_STOP)
			break;
		else
			pause();

	myexit(0);
	return 0;
}
