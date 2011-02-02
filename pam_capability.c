/*___________________________________________________________________________

[ pam_capability ] the capabilities pam module

Copyright (C) 2002 Erik M. A. Kline

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

Please see the file "GPL" in the "meta" subdirectory of the top level source
directory, if you have received this program with source code.

For further information or concerns please contact:

    Erik Kline
    ekline@ekline.com, or
    erik@alum.mit.edu
  ___________________________________________________________________________
*/

#define PAM_SM_SESSION

#include <sys/capability.h>
// #include <security/_pam_aconf.h>
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

///////////////////////////////////////////////////////////////////////////
// local defines, typedefs, and prototypes ////////////////////////////////
///////////////////////////////////////////////////////////////////////////

#define  MAX_ROLENAME  35
#define  MAX_CAPTEXT  2048
#define  MAX_USERNAME  35
#define  MAX_GROUPNAME  35
#define  MAX_LINE  2048

#define  CAP_CONF  CONF_FILE
#define  PAMCAP_VERS  MOD_VERS

#define  CONF_BAD_PERMS  (S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH)
#define  WHITESPACE  " \t\r\n"
#define  PAMCAP_DEFAULT_PRE  "all+ep all-i "
#define  PAMCAP_NONE    "all-i "
#define  PAMCAP_FS_MASK    " cap_chown+i cap_dac_override+i cap_dac_read_search+i cap_fowner+i cap_fsetid+i "
#define  PAMCAP_DEFAULT_POST  " cap_setpcap-eip"

#define  APPEND(x, y, m)  do {                                          \
          strncpy(x+strlen(x), y, m-strlen(x)); \
        } while(0);

typedef struct pamcap_passwd {
  char   pw_name[MAX_USERNAME];
  char   pw_passwd[MAX_USERNAME];
  uid_t  pw_uid;
  gid_t  pw_gid;
  char   pw_gecos[MAX_LINE];
  char   pw_dir[MAX_LINE];
  char   pw_shell[MAX_LINE];
} pamcap_pwd_t;

// role struct
typedef struct pamcap_role {
  char   rolename[MAX_ROLENAME];
  char   capabilities[MAX_CAPTEXT];
  struct pamcap_role* next;
} pamcap_role_t;

// user struct
typedef struct pamcap_user {
  char   username[MAX_USERNAME];
  char   rolename[MAX_ROLENAME];
  struct pamcap_user* next;
} pamcap_user_t;

// group struct
typedef struct pamcap_group {
  char   groupname[MAX_USERNAME];
  char   rolename[MAX_ROLENAME];
  struct pamcap_group* next;
} pamcap_group_t;

// ctx struct
typedef struct pamcap_ctx {
  int debug;
  const char* conf;
  const char* user;
  pamcap_pwd_t pwd;
  char role[MAX_ROLENAME];
  char captext[MAX_CAPTEXT];
  pamcap_role_t* tbl_r;
  pamcap_user_t* tbl_u;
  pamcap_group_t* tbl_g;
} pamcap_ctx_t;

// pwd routines
void pamcap_pwd_dup(pamcap_pwd_t* pwd, struct passwd* passwd);

// role routines
void pamcap_role_init(pamcap_role_t* role);
void pamcap_role_freelist(pamcap_role_t* roletop);
int pamcap_role_verify(pamcap_ctx_t* ctx, pamcap_role_t* role);


// user routines
void pamcap_user_init(pamcap_user_t* user);
void pamcap_user_freelist(pamcap_user_t* usertop);
int pamcap_user_verify(pamcap_user_t* user);


// group routines
void pamcap_group_init(pamcap_group_t* group);
void pamcap_group_freelist(pamcap_group_t* grouptop);
int pamcap_group_verify(pamcap_group_t* group);


// ctx routines
int pamcap_ctx_set_default(pamcap_ctx_t* ctx);
int pamcap_ctx_parse(pamcap_ctx_t* ctx, int argc, const char** argv);
void pamcap_ctx_freetables(pamcap_ctx_t* ctx);

pamcap_role_t* pamcap_ctx_findrolebyname(pamcap_ctx_t* ctx,
                                         const char* rolename);
int pamcap_ctx_appendrole(pamcap_ctx_t* ctx, pamcap_role_t* new);

pamcap_user_t* pamcap_ctx_finduserbyname(pamcap_ctx_t* ctx,
                                         const char* username);
int pamcap_ctx_appenduser(pamcap_ctx_t* ctx, pamcap_user_t* new);

pamcap_group_t* pamcap_ctx_findgroupbyname(pamcap_ctx_t* ctx,
                                           const char* groupname);
int pamcap_ctx_appendgroup(pamcap_ctx_t* ctx, pamcap_group_t* new);
pamcap_group_t* pamcap_ctx_findgroupbyuser(pamcap_ctx_t* ctx);

int pamcap_set_by_user(pamcap_ctx_t* ctx);
void pamcap_set_default(pamcap_ctx_t* ctx);
int pamcap_set(pamcap_ctx_t* ctx);

int pamcap_conf_check(pamcap_ctx_t* ctx);
int pamcap_conf_parse(pamcap_ctx_t* ctx);

///////////////////////////////////////////////////////////////////////////
// PAM external calls /////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags,
                                   int argc, const char** argv) {
  int rval = PAM_SESSION_ERR;
  cap_t caps = NULL;
  char* captext = NULL;
  struct passwd* pwd;
  pamcap_ctx_t ctx;

  openlog("pam_capability", LOG_PID, LOG_AUTHPRIV);
  pamcap_ctx_set_default(&ctx);

  if (pamcap_ctx_parse(&ctx, argc, argv) != 0) {
    syslog(LOG_ERR, "couldn't parse module options");
    goto __out;
  }

  if ((rval = pam_get_user(pamh, &(ctx.user), NULL))
       != PAM_SUCCESS) {
    syslog(LOG_ERR, "can't get username: %s",
            pam_strerror(pamh, rval));
    goto __out;
  }

  if (ctx.user == NULL || *(ctx.user) == '\0') {
    syslog(LOG_ERR, "invalid (null) username");
    goto __out;
  }

  if ((pwd = getpwnam(ctx.user)) == NULL) {
    syslog(LOG_ERR, "invalid system username");
    goto __out;
  }

  pamcap_pwd_dup(&(ctx.pwd), pwd);

  // if we can't find anything useful in the user and role
  // configuration files we should apply the default policy
  if (pamcap_set_by_user(&ctx) != 0) {
    if (ctx.debug) {
      syslog(LOG_INFO, "using default policy for user %s", ctx.user);
    }
    pamcap_set_default(&ctx);
  }

  if (ctx.debug) {
    syslog(LOG_INFO, "session open");
  }

  rval = PAM_SUCCESS;
__out:
  pwd = getpwnam(ctx.user);

  if (rval != PAM_SUCCESS) {
    pamcap_set_default(&ctx);
  }

  if (caps != NULL) {
    cap_free((void*)caps);
  }

  if (ctx.debug) {
    caps = cap_get_proc();
    captext = cap_to_text(caps, NULL);
    syslog(LOG_INFO, "session capabilities: %s", captext);
    cap_free((void*)captext);
    cap_free((void*)caps);

    syslog(LOG_INFO, "returning %s",
           rval == PAM_SUCCESS ? "SUCCESS" : "FAILURE");
  }

  pamcap_ctx_freetables(&ctx);
  closelog();
  return rval;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags,
                                    int argc, const char** argv) {
  pamcap_ctx_t ctx;

  openlog("pam_capability", LOG_PID, LOG_AUTHPRIV);
  pamcap_ctx_set_default(&ctx);

  if (pamcap_ctx_parse(&ctx, argc, argv) != 0) {
    syslog(LOG_ERR, "couldn't parse module options");
  }

  pam_get_user(pamh, &(ctx.user), NULL);

  if (ctx.debug) {
    syslog(LOG_INFO, "session closed for user %s", ctx.user);
  }

  closelog();
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/*
 * static module data
 */

struct pam_module _pam_capability_modstruct = {
  "pam_capability",
  NULL,
  NULL,
  pam_sm_acct_mgmt,
  NULL,
  NULL,
  NULL
};

#endif

///////////////////////////////////////////////////////////////////////////
// local routines /////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

// "pamcap_ctx_t" routines ////////////////////////////////////////////////
int pamcap_ctx_set_default(pamcap_ctx_t* ctx) {
  if (ctx == NULL) {
    return -1;
  }

  ctx->debug   = 0;
  ctx->conf    = CAP_CONF;
  ctx->user    = NULL;
  ctx->tbl_r   = NULL;
  ctx->tbl_u   = NULL;
  ctx->tbl_g   = NULL;

  memset(&(ctx->pwd), 0, sizeof(pamcap_pwd_t));
  memset(ctx->role, 0, MAX_ROLENAME);
  memset(ctx->captext, 0, MAX_CAPTEXT);

  return 0;
}

int pamcap_ctx_parse(pamcap_ctx_t* ctx, int argc, const char** argv) {
  int i;

  if (ctx == NULL) {
    return -1;
  }

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "debug") == 0) {
      ctx->debug = 1;
    } else if (strncmp(argv[i], "conf=", 5) == 0) {
      ctx->conf = argv[i] + 5;
    } else {
      syslog(LOG_INFO, "ignoring unknown option <%s>", argv[i]);
    }
  }

  if (ctx->debug) {
    syslog(LOG_NOTICE, "[pamcap_vers=%s] conf=%s", PAMCAP_VERS, ctx->conf);
  }

  return 0;
}

void pamcap_ctx_freetables(pamcap_ctx_t* ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->tbl_r != NULL) {
    pamcap_role_freelist(ctx->tbl_r);
  }

  if (ctx->tbl_u != NULL) {
    pamcap_user_freelist(ctx->tbl_u);
  }

  if (ctx->tbl_g != NULL) {
    pamcap_group_freelist(ctx->tbl_g);
  }

  return;
}

pamcap_role_t* pamcap_ctx_findrolebyname(pamcap_ctx_t* ctx,
                                         const char* rolename) {
  pamcap_role_t* tmp = NULL;

  for (tmp = ctx->tbl_r; tmp != NULL; tmp = tmp->next) {
    if (strcmp(tmp->rolename, rolename) == 0) {
      break;
    }
  }

  return tmp;
}

pamcap_group_t* pamcap_ctx_findgroupbyuser(pamcap_ctx_t* ctx) {
  pamcap_group_t* tmp = NULL;
  struct group* gp = NULL;
  char** gmem = NULL;

  for (tmp = ctx->tbl_g; tmp != NULL; tmp = tmp->next) {
    if ((gp = getgrnam(tmp->groupname)) != NULL) {
      syslog(LOG_INFO, "%d %d", gp->gr_gid, ctx->pwd.pw_gid);
      if (gp->gr_gid == ctx->pwd.pw_gid) {
        break;
      }

      for (gmem = gp->gr_mem; gmem != NULL &&
           *gmem != NULL && **gmem != '\0'; gmem++) {
        if (strncmp(ctx->user, *gmem, MAX_USERNAME) == 0) {
          break;
        }
      }

      if (gmem != NULL && *gmem != NULL && **gmem != '\0') {
        break;
      }
    }
  }

  return tmp;
}

// "pamcap_pwd_t" routines ////////////////////////////////////////////////
void pamcap_pwd_dup(pamcap_pwd_t* pwd, struct passwd* passwd) {
  if (pwd == NULL || passwd == NULL) {
    return;
  }

  memset(pwd, 0, sizeof(pamcap_pwd_t));

  strncpy(pwd->pw_name, passwd->pw_name, MAX_USERNAME-1);
  strncpy(pwd->pw_passwd, passwd->pw_passwd, MAX_USERNAME-1);
  pwd->pw_uid = passwd->pw_uid;
  pwd->pw_gid = passwd->pw_gid;
  strncpy(pwd->pw_gecos, passwd->pw_gecos, MAX_LINE-1);
  strncpy(pwd->pw_dir, passwd->pw_dir, MAX_LINE-1);
  strncpy(pwd->pw_shell, passwd->pw_shell, MAX_LINE-1);
}

// "pamcap_role_t" routines ///////////////////////////////////////////////
void pamcap_role_init(pamcap_role_t* role) {
  if (role == NULL) {
    return;
  }

  memset(role->rolename, 0, MAX_ROLENAME);
  memset(role->capabilities, 0, MAX_CAPTEXT);
  role->next = NULL;
}

void pamcap_role_freelist(pamcap_role_t* roletop) {
  pamcap_role_t* ptr1;
  pamcap_role_t* ptr2;

  for (ptr1 = roletop; ptr1 != NULL; ptr1 = ptr2) {
    ptr2 = ptr1->next;
    free(ptr1);
  }
}

int pamcap_ctx_appendrole(pamcap_ctx_t* ctx, pamcap_role_t* new) {
  pamcap_role_t* rp;
  cap_t caps = NULL;

  if (new == NULL) {
    return 0;
  }

  // enforce uniqueness
  if (pamcap_ctx_findrolebyname(ctx, new->rolename) != NULL) {
    syslog(LOG_ERR, "duplicate role (%s) ignored", new->rolename);
    return -1;
  }

  // verify capabilities compiles
  if ((caps = cap_from_text(new->capabilities)) == NULL) {
    syslog(LOG_ERR, "invalid capability listing (%s) ignored",
      new->capabilities);
    return -1;
  }

  cap_free(caps);

  // TODO: this needs to be simplified.
  if (ctx->tbl_r == NULL) {
    ctx->tbl_r = new;
  } else {
    for (rp = ctx->tbl_r; rp->next != NULL; rp = rp->next) {
      ;;
    }

    rp->next = new;
  }

  return 0;
}

int pamcap_role_verify(pamcap_ctx_t* ctx, pamcap_role_t* role) {
  char tmpcaptext[MAX_CAPTEXT];
  char* cp = NULL;
  pamcap_role_t* tmp_role = NULL;
  cap_t caps = NULL;

  if (ctx == NULL || role == NULL) {
    return -1;
  }

  if (strlen(role->rolename) == 0 || strlen(role->rolename) > MAX_ROLENAME) {
    return -1;
  }

  memset(tmpcaptext, 0, MAX_CAPTEXT);

  // go through the capabilities field and do a bit of parsing
  // and general munging, since we've tried to simplify the format
  cp = strtok(role->capabilities, WHITESPACE);
  while (cp != NULL && *cp != '\0') {
    if (index(cp, '-') != NULL ||
        index(cp, '+') != NULL ||
        index(cp, '=') != NULL) {
      syslog(LOG_ERR, "only use bare capability words!");
      return -1;
    }

    if (strncasecmp(cp, "cap_", 4) == 0 ||
        strncasecmp(cp, "none", 4) == 0 ||
        strncasecmp(cp, "all", 3)  == 0) {
      if (strncasecmp(cp, "cap_fs_mask", 11) == 0) {
        // cap_fs_mask isn't valid, but we can fake it here.
        APPEND(tmpcaptext, PAMCAP_FS_MASK, MAX_CAPTEXT-1);
      } else if (strncasecmp(cp, "none", 4) == 0) {
        // "none" is an internal keyword for no capabilities.
        APPEND(tmpcaptext, PAMCAP_NONE, MAX_CAPTEXT-1);
      } else {
        // it's probably a capability name
        APPEND(tmpcaptext, cp, MAX_CAPTEXT-1);
        APPEND(tmpcaptext, "+i ", MAX_CAPTEXT-1);
      }
    } else {
      // it's probably a role name
      tmp_role = pamcap_ctx_findrolebyname(ctx, cp);
      if (tmp_role == NULL) {
        syslog(LOG_ERR, "unknown role: %s", cp);
        return -1;
      }

      APPEND(tmpcaptext, tmp_role->capabilities, MAX_CAPTEXT-1);
      APPEND(tmpcaptext, " ", MAX_CAPTEXT-1);
    }

    cp = strtok(NULL, WHITESPACE);
  }

  memcpy(role->capabilities, tmpcaptext, MAX_CAPTEXT);
  role->capabilities[MAX_CAPTEXT-1] = '\0';

  if ((caps = cap_from_text(role->capabilities)) == NULL) {
    return -1;
  }

  cap_free(caps);

  return 0;
}

// "pamcap_user_t" routines ///////////////////////////////////////////////
void pamcap_user_init(pamcap_user_t* user) {
  if (user == NULL)
    return;

  memset(user->username, 0, MAX_USERNAME);
  memset(user->rolename, 0, MAX_ROLENAME);
  user->next = NULL;
}

void pamcap_user_freelist(pamcap_user_t* usertop) {
  pamcap_user_t* ptr1;
  pamcap_user_t* ptr2;

  for (ptr1 = usertop; ptr1 != NULL; ptr1 = ptr2) {
    ptr2 = ptr1->next;
    free(ptr1);
  }
}

pamcap_user_t* pamcap_ctx_finduserbyname(pamcap_ctx_t* ctx,
                                         const char* username) {
  pamcap_user_t* tmp = NULL;

  for (tmp = ctx->tbl_u; tmp != NULL; tmp = tmp->next) {
    if (strcmp(tmp->username, username) == 0) {
      break;
    }
  }

  return tmp;
}

int pamcap_ctx_appenduser(pamcap_ctx_t* ctx, pamcap_user_t* new) {
  pamcap_user_t* up;

  if (new == NULL) {
    return 0;
  }

  // enforce uniqueness
  if (pamcap_ctx_finduserbyname(ctx, new->username) != NULL) {
    syslog(LOG_ERR, "duplicate user (%s) ignored", new->username);
    return -1;
  }

  if (ctx->tbl_u == NULL) {
    ctx->tbl_u = new;
  } else {
    for (up = ctx->tbl_u; up->next != NULL; up = up->next) {
      ;;
    }

    up->next = new;
  }

  return 0;
}

int pamcap_user_verify(pamcap_user_t* user) {
  struct passwd* pp = NULL;

  if (user == NULL) {
    return -1;
  }

  if (strlen(user->username) == 0            ||
      strlen(user->username) > MAX_USERNAME  ||
      strlen(user->rolename) == 0            ||
      strlen(user->rolename) > MAX_ROLENAME) {
    return -1;
  }

  if (strncmp(user->username, "*", 1) == 0) {
    return 0;
  }

  if ((pp = getpwnam(user->username)) == NULL) {
    return -1;
  }

  return 0;
}

// "pamcap_group_t" routines //////////////////////////////////////////////
void pamcap_group_init(pamcap_group_t* group) {
  if (group == NULL) {
    return;
  }

  memset(group->groupname, 0, MAX_GROUPNAME);
  memset(group->rolename, 0, MAX_ROLENAME);
  group->next = NULL;
}

void pamcap_group_freelist(pamcap_group_t* grouptop) {
  pamcap_group_t* ptr1;
  pamcap_group_t* ptr2;

  for (ptr1 = grouptop; ptr1 != NULL; ptr1 = ptr2) {
    ptr2 = ptr1->next;
    free(ptr1);
  }
}

pamcap_group_t* pamcap_ctx_findgroupbyname(pamcap_ctx_t* ctx,
                                           const char* groupname) {
  pamcap_group_t* tmp = NULL;

  for (tmp = ctx->tbl_g; tmp != NULL; tmp = tmp->next) {
    if (strcmp(tmp->groupname, groupname) == 0) {
      break;
    }
  }

  return tmp;
}

int pamcap_ctx_appendgroup(pamcap_ctx_t* ctx, pamcap_group_t* new) {
  pamcap_group_t* up;

  if (new == NULL) {
    return 0;
  }

  // enforce uniqueness
  if (pamcap_ctx_findgroupbyname(ctx, new->groupname) != NULL) {
    syslog(LOG_ERR, "duplicate group (%s) ignored", new->groupname);
    return -1;
  }

  if (ctx->tbl_g == NULL) {
    ctx->tbl_g = new;
  } else {
    for (up = ctx->tbl_g; up->next != NULL; up = up->next) {
      ;;
    }

    up->next = new;
  }

  return 0;
}

int pamcap_group_verify(pamcap_group_t* group) {
  struct group* gp = NULL;

  if (group == NULL) {
    return -1;
  }

  if (strlen(group->groupname) == 0             ||
      strlen(group->groupname) > MAX_GROUPNAME  ||
      strlen(group->rolename)  == 0             ||
      strlen(group->rolename)  > MAX_ROLENAME) {
    return -1;
  }

  if ((gp = getgrnam(group->groupname)) == NULL) {
    return -1;
  }

  return 0;
}

/*
 * [ pamcap_set_by_user ]
 *
 * steps:
 *   1 - if uid == 0, bail out with success. root has privilidges already.
 *   2 - parse the conf file
 *   3 - find rolename by
 *       1 - username,
 *       2 - group membership,
 *       3 - then user '*'
 *   4 - attempt to set capabilities based on the role
 */
int pamcap_set_by_user(pamcap_ctx_t* ctx) {
  pamcap_role_t* rptr = NULL;
  pamcap_user_t* uptr = NULL;
  pamcap_group_t* gptr = NULL;
  int rval = -1;

  if (ctx == NULL || ctx->user == NULL || ctx->conf == NULL) {
    goto __out;
  }

  memset(ctx->captext, 0, MAX_CAPTEXT);

  // [1]
  if (ctx->pwd.pw_uid == 0) {
    rval = 0;
    goto __out;
  }

  // [2]
  if (pamcap_conf_parse(ctx) != 0) {
    syslog(LOG_ERR, "error parsing conf file <%s>", ctx->conf);
    goto __out;
  }

  // [3]
  // [3.1]
  uptr = pamcap_ctx_finduserbyname(ctx, ctx->user);
  if (uptr != NULL) {
    strncpy(ctx->role, uptr->rolename, MAX_ROLENAME-1);
  }

  if (ctx->debug) {
    syslog(LOG_INFO, "user declaration for %s %s", ctx->user,
           uptr == NULL ? "not found" : "found");
  }

  // [3.2]
  if (strlen(ctx->role) == 0) {
    if ((gptr = pamcap_ctx_findgroupbyuser(ctx)) != NULL) {
      strncpy(ctx->role, gptr->rolename, MAX_ROLENAME-1);
    }

    if (ctx->debug) {
      syslog(LOG_INFO,
             "group declaration with member %s %s %s%s%s",
             ctx->user,
             gptr == NULL ? "not found" : "found",
             gptr == NULL ? "" : "(",
             gptr == NULL ? "" : gptr->groupname,
             gptr == NULL ? "" : ")");
    }
  }

  // [3.3]
  if (strlen(ctx->role) == 0) {
    if ((uptr = pamcap_ctx_finduserbyname(ctx, "*")) != NULL) {
      strncpy(ctx->role, uptr->rolename, MAX_ROLENAME-1);
    }

    if (ctx->debug) {
      syslog(LOG_INFO, "user declaration for '*' %s",
             uptr == NULL ? "not found" : "found");
    }
  }

  if (strlen(ctx->role) == 0) {
    if (ctx->debug) {
      syslog(LOG_INFO, "couldn't find config for user %s", ctx->user);
    }

    goto __out;
  }

  rptr = pamcap_ctx_findrolebyname(ctx, ctx->role);
  if (rptr == NULL) {
    syslog(LOG_ERR, "couldn't find config for role %s", uptr->rolename);
    goto __out;
  }

  if (strncmp(ctx->role, rptr->rolename, MAX_ROLENAME) != 0) {
    syslog(LOG_ERR, "failed paranoid check");
    goto __out;
  }

  strncpy(ctx->captext, rptr->capabilities, MAX_CAPTEXT-1);

  // [4]
  rval = pamcap_set(ctx);
__out:
  return rval;
}

void pamcap_set_default(pamcap_ctx_t* ctx) {
  if (ctx != NULL && ctx->debug)
    syslog(LOG_INFO, "clearing all capabilities");

  memset(ctx->captext, 0, MAX_CAPTEXT);

  pamcap_set(ctx);
  return;
}

int pamcap_set(pamcap_ctx_t* ctx) {
  char tmpcaptext[MAX_CAPTEXT];
  cap_t caps = NULL;
  int rval;

  if (ctx == NULL) {
    return -1;
  }

  memset(tmpcaptext, 0, MAX_CAPTEXT);
  strncpy(tmpcaptext, PAMCAP_DEFAULT_PRE, strlen(PAMCAP_DEFAULT_PRE));
  APPEND(tmpcaptext, ctx->captext, MAX_CAPTEXT-1);
  APPEND(tmpcaptext, PAMCAP_DEFAULT_POST, MAX_CAPTEXT-1);
  tmpcaptext[MAX_CAPTEXT-1] = '\0';

  caps = cap_from_text(tmpcaptext);

  errno = 0;
  rval = cap_set_proc(caps);

  if (ctx->debug) {
    syslog(LOG_INFO, "cap_set_proc: user <%s>/role <%s> to <%s> %s (%s)",
           ctx->user, ctx->role, tmpcaptext,
           rval == 0 ? "SUCCEEDED" : "FAILED", strerror(errno));
  }

  cap_free(caps);
  return rval;
}

// config file routines ///////////////////////////////////////////////////
int pamcap_conf_check(pamcap_ctx_t* ctx) {
  struct stat buf;

  if (ctx == NULL || ctx->conf == NULL) {
    return -1;
  }

  memset(&buf, 0, sizeof(buf));
  if (stat(ctx->conf, &buf) != 0) {
    syslog(LOG_ERR, "error stat'ing conf file <%s>: %s", ctx->conf,
           strerror(errno));
    return -1;
  }

  if (buf.st_uid != 0) {
    return -1;
  }

  if (!S_ISREG(buf.st_mode)) {
    return -1;
  }

  if (buf.st_mode & CONF_BAD_PERMS) {
    return -1;
  }

  return 0;
}

/*
 * the attempted format of the capability.conf file is:
 *
 * role    <rolename>      <cap_list>
 * group   <groupname>     <rolename>
 * user    <username>      <rolename>
 *
 * where <cap_list> conforms to cap_from_text(3) syntax.
 *
 * '#' are comments and \'s can be used to continue lines.
 *
 * also: roles must be declared before they are used in a 'user'
 * or 'group' declaration, otherwise 'role', 'user', and 'group'
 * declarations can be intermingled, though it's probably cleaner
 * not to do so.
 */
int pamcap_conf_parse(pamcap_ctx_t* ctx) {
  int rval = -1;
  FILE* conf = NULL;
  int i;
  char line[MAX_LINE];
  pamcap_role_t* rptr = NULL;
  pamcap_user_t* uptr = NULL;
  pamcap_group_t* gptr = NULL;
  int ps_cmd; // parser state variable
#define  PS_CMD_ROLE_KEY   1
#define  PS_CMD_ROLE_VAL   2
#define  PS_CMD_USER_KEY   3
#define  PS_CMD_USER_VAL   4
#define  PS_CMD_GROUP_KEY  5
#define  PS_CMD_GROUP_VAL  6

  if (ctx == NULL) {
    goto __out;
  }

  if (ctx->tbl_r != NULL) {
    pamcap_role_freelist(ctx->tbl_r);
  }

  if (ctx->tbl_u != NULL) {
    pamcap_user_freelist(ctx->tbl_u);
  }

  if (ctx->tbl_g != NULL) {
    pamcap_group_freelist(ctx->tbl_g);
  }

  if (pamcap_conf_check(ctx) != 0) {
    syslog(LOG_ERR, "error validating conf file <%s>", ctx->conf);
    goto __out;
  }

  if ((conf = fopen(ctx->conf, "r")) == NULL) {
    syslog(LOG_ERR, "error fopen'ing conf file <%s>: %s", ctx->conf,
           strerror(errno));
    goto __out;
  }

  i = 1;
  ps_cmd = 0;
  while(fgets(line, MAX_LINE, conf)) {
    char* cp;
    int len = 0;

    line[MAX_LINE - 1] = '\0';

    if ((len = strlen(line)) == 0) {
      goto __continue;
    }

    if (line[0] == '\0' || line[0] == '#') {
      goto __continue;
    }

    cp = strtok(line, WHITESPACE);
    if (cp == NULL || *cp == '\0') {
      goto __continue;
    }

/*
{
  pamcap_role_t  * rp;
  pamcap_user_t  * up;
  pamcap_group_t * gp;

  for (rp = ctx->tbl_r; rp != NULL; rp = rp->next)
    syslog(LOG_INFO, "role %s:%s", rp->rolename,
      rp->capabilities);

  for (up = ctx->tbl_u; up != NULL; up = up->next)
    syslog(LOG_INFO, "user %s:%s", up->username,
      up->rolename);

  for (gp = ctx->tbl_g; gp != NULL; gp = gp->next)
    syslog(LOG_INFO, "group %s:%s", gp->groupname,
      gp->rolename);
} while(0);
*/

    if (!ps_cmd && strcmp(cp, "role") == 0) {
      ps_cmd = PS_CMD_ROLE_KEY;
      if ((rptr = malloc(sizeof(pamcap_role_t))) == NULL) {
        syslog(LOG_ERR, "malloc role problem");
        goto __out;
      }

      pamcap_role_init(rptr);
      cp = strtok(NULL, WHITESPACE);
      if (cp == NULL || *cp == '\0') {
        goto __out;
      }
    } else if (! ps_cmd && strcmp(cp, "user") == 0) {
      ps_cmd = PS_CMD_USER_KEY;
      if ((uptr = malloc(sizeof(pamcap_user_t))) == NULL) {
        syslog(LOG_ERR, "malloc user problem");
        goto __out;
      }

      pamcap_user_init(uptr);
      cp = strtok(NULL, WHITESPACE);
      if (cp == NULL || *cp == '\0') {
        goto __out;
      }
    } else if (! ps_cmd && strcmp(cp, "group") == 0) {
      ps_cmd = PS_CMD_GROUP_KEY;
      if ((gptr = malloc(sizeof(pamcap_group_t))) == NULL) {
        syslog(LOG_ERR, "malloc group problem");
        goto __out;
      }

      pamcap_group_init(gptr);
      cp = strtok(NULL, WHITESPACE);
      if (cp == NULL || *cp == '\0') {
        goto __out;
      }
    }

    if (ps_cmd == PS_CMD_ROLE_KEY) {
      if (cp == NULL || (! isalnum(*cp) && *cp != '\\')) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp)) {
        strncpy(rptr->rolename, cp, MAX_ROLENAME - 1);
        ps_cmd = PS_CMD_ROLE_VAL;
        cp = strtok(NULL, WHITESPACE);
        if (cp == NULL || *cp == '\0') {
          goto __out;
        }
      } else if (*cp == '\\') {
        goto __continue;
      }
    }

    if (ps_cmd == PS_CMD_ROLE_VAL) {
__role_val:
      if (cp == NULL || (! isalnum(*cp) && strcmp(cp, "\\") != 0)) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp)) {
        APPEND(rptr->capabilities, cp, MAX_CAPTEXT-1);
        APPEND(rptr->capabilities, " ", MAX_CAPTEXT-1);

        cp = strtok(NULL, WHITESPACE);
        if (cp == NULL || *cp == '\0') {
          ps_cmd = 0;
          if (pamcap_role_verify(ctx, rptr) == 0) {
            if (ctx->debug) {
              syslog(LOG_INFO, "<roledef> %s: %s", rptr->rolename,
                     rptr->capabilities);
            }
            pamcap_ctx_appendrole(ctx, rptr);
          } else {
            syslog(LOG_ERR, "could not verify role %s: ignored",
                   rptr->rolename);
            free(rptr);
          }
          rptr = NULL;
        } else
          goto __role_val;
      }
        goto __continue;
    }

    if (ps_cmd == PS_CMD_USER_KEY) {
      if (cp == NULL || (! isalnum(*cp) && strcmp(cp, "\\") != 0 &&
          strcmp(cp, "*") != 0)) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp) || strcmp(cp, "*") == 0) {
        strncpy(uptr->username, cp, MAX_USERNAME - 1);
        ps_cmd = PS_CMD_USER_VAL;
        cp = strtok(NULL, WHITESPACE);
        if (cp == NULL || *cp == '\0') {
          goto __out;
        }
      } else if (strcmp(cp, "\\") == 0) {
          goto __continue;
      }
    }

    if (ps_cmd == PS_CMD_USER_VAL) {
      if (cp == NULL || (! isalnum(*cp) && strcmp(cp, "\\") != 0)) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp)) {
        if (pamcap_ctx_findrolebyname(ctx, cp) == NULL) {
          syslog(LOG_ERR, "undefined role: %s. ignoring.", cp);
          ps_cmd = 0;
          free(uptr);
          uptr = NULL;
          goto __continue;
        }
        strncpy(uptr->rolename, cp, MAX_ROLENAME - 1);
        ps_cmd = 0;
        if (pamcap_user_verify(uptr) == 0) {
          pamcap_ctx_appenduser(ctx, uptr);
        } else {
          syslog(LOG_ERR, "could not verify user %s: ignored", uptr->username);
          free(uptr);
        }
        uptr = NULL;
      }
      goto __continue;
    }

    if (ps_cmd == PS_CMD_GROUP_KEY) {
      if (cp == NULL || (! isalnum(*cp) && strcmp(cp, "\\") != 0 &&
          strcmp(cp, "*") != 0)) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp) || strcmp(cp, "*") == 0) {
        strncpy(gptr->groupname, cp, MAX_GROUPNAME - 1);
        ps_cmd = PS_CMD_GROUP_VAL;
        cp = strtok(NULL, WHITESPACE);
        if (cp == NULL || *cp == '\0') {
          goto __out;
        }
      } else if (strcmp(cp, "\\") == 0) {
        goto __continue;
      }
    }

    if (ps_cmd == PS_CMD_GROUP_VAL) {
      if (cp == NULL || (! isalnum(*cp) && strcmp(cp, "\\") != 0)) {
        syslog(LOG_ERR, "bad line: %d", i);
        goto __out;
      } else if (isalnum(*cp)) {
        if (pamcap_ctx_findrolebyname(ctx, cp) == NULL) {
          syslog(LOG_ERR, "undefined role: %s. ignoring.", cp);
          ps_cmd = 0;
          free(gptr);
          gptr = NULL;
          goto __continue;
        }

        strncpy(gptr->rolename, cp, MAX_ROLENAME - 1);
        ps_cmd = 0;

        if (pamcap_group_verify(gptr) == 0) {
          pamcap_ctx_appendgroup(ctx, gptr);
        } else {
          syslog(LOG_ERR, "could not verify group %s: ignored",
                 gptr->groupname);
          free(gptr);
        }

        gptr = NULL;
      }

      goto __continue;
    }

__continue:
    i++;
    memset(line, 0, MAX_LINE);
  }

  rval = 0;
__out:
  if (rptr != NULL) {
      free(rptr);
  }

  if (uptr != NULL) {
      free(uptr);
  }

  if (gptr != NULL) {
      free(gptr);
  }

  if (conf != NULL) {
    fclose(conf);
    conf = NULL;
  }

  if (rval != 0) {
    pamcap_ctx_freetables(ctx);
  }

  return rval;
}
