/**
 * pam_alias - map user names using an arbitrary file
 *
 * Copyright (c) 2012 Simon Schubert <2@0x2c.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _POSIX_SOURCE

#include <sys/stat.h>

#include <linux/unistd.h>
#include <rpc/types.h>
#include <stdio.h>
#include <syslog.h>
#include <db.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>


static const char *module_id = "pam_aliasdb.0x2c.org";


static const char *
longoptarg(const char *arg, const char *name)
{
	if (strncmp(arg, name, strlen(name)) != 0)
		return (NULL);
	if (arg[strlen(name)] != '=')
		return (NULL);
	return (&arg[strlen(name) + 1]);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	int debug = 0;
	const char *aliasfn = NULL;
	enum {
		NOMATCH_IGNORE,
		NOMATCH_FAIL,
	} nomatch = NOMATCH_IGNORE;
	const char *opt;

	/* exit early if we've been through this before */
	const void *dummy;
	if (pam_get_data(pamh, module_id, &dummy) == PAM_SUCCESS)
		return (PAM_IGNORE);

	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if ((opt = longoptarg(argv[i], "db"))) {
			aliasfn = opt;
		} else if ((opt = longoptarg(argv[i], "nomatch"))) {
			if (strcmp(opt, "fail") == 0) {
				nomatch = NOMATCH_FAIL;
			} else if (strcmp(opt, "ignore") == 0) {
				nomatch = NOMATCH_IGNORE;
			} else {
				pam_syslog(pamh, LOG_ERR,
					   "invalid argument \"%s\" for nomatch option",
					   opt);
			}
		} else {
			pam_syslog(pamh, LOG_ERR,
				   "bad option \"%s\"",
				   argv[i]);
		}
	}

	if (!aliasfn) {
		pam_syslog(pamh, LOG_ERR,
			   "Alias dbname not specified");
		return (PAM_SERVICE_ERR);
	}

	DB *dbp;
	DBT key, data;
	int ret;

	if ((ret = db_create(&dbp, NULL, 0)) != 0) {
	  pam_syslog(pamh, LOG_ERR,
		     "db_create: %s\n", db_strerror(ret));
	  goto fail;
	}

	if ((ret = dbp->open(dbp, NULL, aliasfn, NULL, DB_UNKNOWN, 0, 0664)) != 0) {
	  pam_syslog(pamh, LOG_ERR,
		     "%s", aliasfn);
	  goto fail;
	}

	char *user;
	int rv;
	if ((rv = pam_get_item(pamh, PAM_USER, (void *)&user)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
			   "Cannot obtain current pam user: %s",
			   pam_strerror(pamh, rv));
		goto fail;
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = user;
	key.size = strlen(user)+1;
	char buffer[256];

	if ((ret = dbp->get(dbp, NULL, &key, &data, 0)) != DB_NOTFOUND)
	  {
	    pam_syslog(pamh, LOG_INFO,
		       "matched user alias \"%s\" to \"%s\"",
		       user, data.data);
	    if (pam_set_item(pamh, PAM_USER, data.data) != PAM_SUCCESS) {
	      pam_syslog(pamh, LOG_ERR,
			 "Cannot set pam user to \"%s\": %s",
			 data.data,
			 pam_strerror(pamh, rv));
	      goto fail;
	    }

	    /**
	     * Set a flag so that we know that we've done
	     * a pass.
	     *
	     * If this fails, we can't do anything about
	     * it.
	     */
	    
	    pam_set_data(pamh, module_id, (void *)1, NULL);

	    dbp->close(dbp, 0);
	    /* success changing the user */
	    return (PAM_IGNORE);
	}

        dbp->close(dbp, 0);

	switch (nomatch) {
	case NOMATCH_IGNORE:
		return (PAM_IGNORE);
	case NOMATCH_FAIL:
		return (PAM_AUTH_ERR);
	}

fail:
	dbp->close(dbp, 0);

	return (PAM_SERVICE_ERR);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
	return (PAM_SUCCESS);
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}
