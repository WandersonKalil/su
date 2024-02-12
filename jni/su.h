/*
** Copyright 2010, Adam Shanks (@ChainsDD)
** Copyright 2008, Zinx Verituse (@zinxv)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef SU_h 
#define SU_h 1

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "su"

#define REQUESTOR "wkroot.superpower"
#define REQUESTOR_DATA_PATH "/data/data/" REQUESTOR
#define REQUESTOR_CACHE_PATH "/dev/" REQUESTOR

#define REQUESTOR_DAEMON_PATH REQUESTOR_CACHE_PATH ".daemon"

#define REQUESTOR_STORED_PATH REQUESTOR_DATA_PATH "/files/stored"
#define REQUESTOR_STORED_DEFAULT REQUESTOR_STORED_PATH "/default"
#define REQUESTOR_OPTIONS REQUESTOR_STORED_PATH "/options"
#define REQUESTOR_LOGS_PATH REQUESTOR_DATA_PATH "/files/logs"
/* intent actions */
#define ACTION_REQUEST REQUESTOR ".REQUEST"
#define ACTION_RESULT  REQUESTOR ".RESULT"

#define SU_REQUEST_ACTIVITY REQUESTOR "/.SuRequestActivity"
#define SU_RESULT_RECEIVER  REQUESTOR "/.SuResultReceiver"

#define REQUESTOR_PREMIUM "wkroot.manager.premium"
#define REQUESTOR_PREMIUM_DATA_PATH "/data/data/" REQUESTOR_PREMIUM
#define REQUESTOR_PREMIUM_STORED_PATH REQUESTOR_PREMIUM_DATA_PATH "/files/stored"
#define REQUESTOR_PREMIUM_STORED_DEFAULT REQUESTOR_PREMIUM_STORED_PATH "/default"
#define REQUESTOR_PREMIUM_OPTIONS REQUESTOR_PREMIUM_STORED_PATH "/options"
#define REQUESTOR_PREMIUM_LOGS_PATH REQUESTOR_PREMIUM_DATA_PATH "/files/logs"

/* intent actions */
#define ACTION_REQUEST_PREMIUM REQUESTOR_PREMIUM ".REQUEST"
#define ACTION_RESULT_PREMIUM  REQUESTOR_PREMIUM ".RESULT"

#define SU_REQUEST_ACTIVITY_PREMIUM REQUESTOR_PREMIUM "/.SuRequestActivity"
#define SU_RESULT_RECEIVER_PREMIUM  REQUESTOR_PREMIUM "/.SuResultReceiver"


#define DEFAULT_SHELL "/system/bin/sh"

#ifdef SU_LEGACY_BUILD
#define VERSION_EXTRA	"l"
#else
#define VERSION_EXTRA	":SUPERPOWER:SUPERSU:MAGISK"
#endif

#define VERSION "30.5.1997" VERSION_EXTRA
#define VERSION_CODE 3051997

#define DATABASE_VERSION 8
#define PROTO_VERSION 0

#define PROPERTY_VALUE_MAX  92

#define CLONE_NEWNS	0x00020000 /*New mount namespace group */

// CyanogenMod-specific behavior
#define CM_ROOT_ACCESS_DISABLED      0
#define CM_ROOT_ACCESS_APPS_ONLY     1
#define CM_ROOT_ACCESS_ADB_ONLY      2
#define CM_ROOT_ACCESS_APPS_AND_ADB  3

struct su_initiator {
    pid_t pid;
    unsigned uid;
    unsigned user;
    char bin[PATH_MAX];
    char args[4096];
	int pref_root;
	char env[ARG_MAX];
    char *envp[512];
};

struct su_request {
    unsigned uid;
    int login;
    int keepenv;
    char *shell;
    char *command;
    char **argv;
    int argc;
    int optind;
    int appId;
    int all;
	char log_path[PATH_MAX];
	// WK, line added on 16/02/2023:
	int pref_switch_superuser;
	char fifo[PATH_MAX];
};

struct su_user_info {
    unsigned userid;
    int owner_mode;
    char data_path[PATH_MAX];
    char store_path[PATH_MAX];
    char store_default[PATH_MAX];
	char logs_path[PATH_MAX];
};


struct su_context {
    struct su_initiator from;
    struct su_request to;
    struct su_user_info user;
    mode_t umask;
    volatile pid_t child;
    char sock_path[PATH_MAX];
	int pref_full_command_logging;
	
	// WK, line added on 16/02/2023: SuperSU support:
	int notify;
	int access;
	int log_data_and_time_only;
	int enablemountnamespaceseparation;
	int requestor_uid;
        int is_premium;
};

typedef enum {
    INTERACTIVE = -1,
    DENY = 0,
    ALLOW = 1,
} allow_t;

typedef enum {
    SUPERPOWER = 1,
    SUPERSU = 2,
    MAGISK = 3,
} superuser_t;

extern allow_t database_check(struct su_context *ctx);
extern void set_identity(unsigned int uid);
extern int send_intent(struct su_context *ctx,
                       allow_t allow, const char *action);
extern void sigchld_handler(int sig);

static inline char *get_command(const struct su_request *to)
{
	return (to->command) ? to->command : to->shell;
}

int run_daemon();
int connect_daemon(int argc, char *argv[]/*, int ppid*/, char** env);
int su_main(int argc, char *argv[], int need_client,char** env );
// for when you give zero fucks about the state of the child process.
// this version of fork understands you don't care about the child.
// deadbeat dad fork.
int fork_zero_fucks();

extern void switch_mnt_ns(int pid);

#include <android/log.h>
#ifndef LOGE
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)//ALOGE(__VA_ARGS__)
#endif
#ifndef LOGD
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)//ALOGD(__VA_ARGS__)
#endif
#ifndef LOGI
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)//ALOGD(__VA_ARGS__)
#endif

#ifndef LOGW
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)//ALOGW(__VA_ARGS__)
#endif

#if 0
#undef LOGE
#define LOGE(fmt,args...) fprintf(stderr, fmt, ##args)
#undef LOGD
#define LOGD(fmt,args...) fprintf(stderr, fmt, ##args)
#undef LOGW
#define LOGW(fmt,args...) fprintf(stderr, fmt, ##args)
#endif

#include <errno.h>
#include <string.h>
#define PLOGE(fmt,args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#define PLOGEV(fmt,err,args...) LOGE(fmt " failed with %d: %s", ##args, err, strerror(err))


#define ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))

#endif
