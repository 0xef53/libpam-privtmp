#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include <linux/unistd.h>
#include <linux/sched.h>

#define PROG_IDENT "PAM-PRIVTMP"
#define MIN_USER_ID 1000


void to_log(int prio, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog(PROG_IDENT, LOG_CONS|LOG_PID, LOG_USER);
    vsyslog(prio, format, args);
    va_end(args);
    closelog();
}


int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *PAM_user = NULL;
    struct passwd* pw;
    char usertmp[200];
    struct stat statbuf;
    int ret = 0;

    ret = pam_get_user(pamh, &PAM_user, NULL);
    if (ret != PAM_SUCCESS) {
        to_log(LOG_ERR, "pam_get_user error: cannot retrieve user\n");
        return PAM_SESSION_ERR;
    }

    pw = getpwnam(PAM_user);
    if (pw == NULL) {
        to_log(LOG_ERR, "invalid username: %s\n", PAM_user);
        return PAM_SESSION_ERR;
    }

    if (pw->pw_uid < MIN_USER_ID)
        return PAM_SUCCESS;

    snprintf(usertmp, 200, "%s/tmp", pw->pw_dir);
    ret = stat(usertmp, &statbuf);
    if (ret == 0 && S_ISDIR(statbuf.st_mode)) {
        // Try to unshare
        ret = unshare(CLONE_NEWNS);
        if (ret) {
            to_log(LOG_ERR, "failed to unshare mounts namespace for user %s\n", pw->pw_name);
            return PAM_SESSION_ERR;
        }
        // Mark / as slave
        ret = mount("", "/", "none", MS_REC|MS_SLAVE, NULL);
        if (ret) {
            to_log(LOG_ERR, "failed to mark root tree as rslave for user %s\n", pw->pw_name);
            return PAM_SESSION_ERR;
        }
        // Mount user's tmp
        ret = mount(usertmp, "/tmp", "none", MS_BIND, NULL);
        if (ret) {
            to_log(LOG_ERR, "failed to bind mount temp dir for user %s\n", pw->pw_name);
            return PAM_SESSION_ERR;
        }
    } else
        to_log(LOG_INFO, "user's temp dir not found: %s\n", usertmp);

     return PAM_SUCCESS;
}
