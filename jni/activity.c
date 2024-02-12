/*
Copyright 2016-2023 Wanderson Kalil (@WKSuperPower)
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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <paths.h>
#include <strings.h>

#include <stdio.h>

#include "su.h"

static void kill_child(pid_t pid)
{
    LOGD("killing child %d", pid);
    if (pid) {
        sigset_t set, old;

        sigemptyset(&set);
        sigaddset(&set, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &set, &old)) {
            PLOGE("sigprocmask(SIG_BLOCK)");
            return;
        }
        if (kill(pid, SIGKILL))
            PLOGE("kill (%d)", pid);
        else if (sigsuspend(&old) && errno != EINTR)
            PLOGE("sigsuspend");
        if (sigprocmask(SIG_SETMASK, &old, NULL))
            PLOGE("sigprocmask(SIG_BLOCK)");
    }
}

static void setup_sigchld_handler(__sighandler_t handler)
{
    struct sigaction act;

    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &act, NULL)) {
        PLOGE("sigaction(SIGCHLD)");
        exit(EXIT_FAILURE);
    }
}

int send_intent(struct su_context *ctx, allow_t allow, const char *action)
{
    //const char *socket_path;
    unsigned int uid = ctx->from.uid;
	unsigned int su_code = getpid();
    __sighandler_t handler;
    pid_t pid;
	
	char * const* envp = environ;
	if (ctx->from.envp[0]) {
        envp = ctx->from.envp;
    }
	/*
    pid = ctx->child;
    if (pid) {
		LOGD("killing child %d", pid);
		 if (kill(pid, SIGKILL)) {
            PLOGE("kill (%d)", pid);
		 } else {
			  ctx->child = 0;
			  pid = ctx->child;
		 }*/
        /*kill_child(pid);
        pid = ctx->child;
        if (pid) {
            LOGE("child %d is still running", pid);
            return -1;
        }*/
    //}
    /*if (allow == INTERACTIVE) {
        //socket_path = ctx->sock_path;
        handler = sigchld_handler;
    } else {
       // socket_path = "";
	   // WK, line disabled on 17/02/2023: SIG_IGN will interferir on the child exit code (ignoring it), preventing FlashFire from working:
       // handler = SIG_IGN;
    }*/
	
    //setup_sigchld_handler(handler);
	//if  (allow =! INTERACTIVE) {
	// WK: disabled on 12/03/2023: As SuperPower is using enqueueWork() instead of startService(), we no longer suffer from the startService()'s restriction. Thus, this workaround/hack is no longer needed.
	// WK, on17/02/2023: the finish() call in SuperPower will finish SuperSU when we changing any settings that need root access or tap on "Clear Logs"
	//if ((strcmp(ctx->from.bin, "eu.chainfire.supersu") != 0) && /*(strcmp(ctx->from.bin, "com.topjohnwu.magisk") != 0) &&*/ (allow != INTERACTIVE)/*|| strcmp(ctx->from.bin, "eu.chainfire.supersu.flash") != 0*/) {
		// WK, on 17/02/2023: this prevents zombies processes and garante that FlashFire continue its work:
		//if (fork_zero_fucks() == 0) {
	//pid = fork();
    /* Child */
    //if (!pid) {
		// WK: don't inherite (detach ourselvers from) the daemon's setsid() syscall so the denied requests notifications are sent:
		//setsid();
       // char command[ARG_MAX];
		/*WK, on 01/11/2022: prior to sending the ACTION_RESULT broadcast we must awake the app fist: this fixes the following error on Android 11: 
		11-01 10:09:57.037 W/ActivityManager(834): Background start not allowed: service Intent { cmp=wkroot.superpower/.service.ResultService (has extras) } to wkroot.superpower/.service.ResultService from pid=8318 uid=10253 pkg=wkroot.superpower startFg?=false

        11-01 10:09:57.038 E/wkroot.superpower(8318): SuResultReceiver error:java.lang.IllegalStateException: Not allowed to start service Intent { cmp=wkroot.superpower/.service.ResultService (has extras) }: app is in background uid UidRecord{6fd5ce8 u0a253 RCVR idle change:uncached procs:1 seq(0,0,0)}

        Background Service Limitations: While an app is idle, there are limits to its use of background services. This does not apply to foreground services, which are more noticeable to the user.*/
        // WK, on 20/10/22: the Android 10/11 have restrictions against SuRequestActivity being launched indirectly via a broadcast receiver (SuRequestReceiver). we need to start the activity directly using "am start" command.
		/*snprintf(command, sizeof(command),
            "/system/bin/am '%s' --user %d -a '%s' -n '%s' --include-stopped-packages --receiver-replace-pending",
            "start", ctx->user.userid, ACTION_REQUEST, SU_REQUEST_ACTIVITY);
        char *args[] = { "sh", "-c", command, NULL, };
*/
        /*
         * before sending the intent, make sure the effective uid/gid match
         * the real uid/gid, otherwise LD_LIBRARY_PATH is wiped
         * in Android 4.0+.
         */
       /* set_identity(0);
        int zero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
        dup2(zero, 0);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        dup2(null, 1);
        dup2(null, 2);
        LOGD("Executing %s\n", command);
        execve(_PATH_BSHELL, args, envp);
        PLOGE("exec am");
        _exit(EXIT_FAILURE);
    }
}*/
	//}
	//if (allow == INTERACTIVE) {
	    // WK: wait a bit until we launch the next ACTION_REQUEST/SU_REQUEST_ACTIVITY to prevent a race contition. This also guaranties that the broadcast is sent.
	    //sleep(1);
	//}
	// WK, on 17/02/2023: this prevents zombies processes and garante that FlashFire continue its work:
 if (fork_zero_fucks() == 0) {
	 
	 
    //result = (su_ctx->access == ALLOW) ? "GRANTED" : "DENIED";
	
	
	//LOGD("su_ctx->from.bin: %s", su_ctx->from.bin);
	
	
	//LOGD("%d %d %s log_path: %s",(int)s1, (int)s2, ctime(&t), ctx.to.log_path);

	
    //pid = fork();
    /* Child */
    //if (!pid) {
		// WK: don't inherite (detach ourselvers from) the daemon's setsid() syscall so the denied requests notifications are sent:
		setsid();
        char command[ARG_MAX];
		
		if (ctx->to.pref_switch_superuser == SUPERPOWER) {
			//snprintf(ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", ctx->user.logs_path, ctx->from.uid, ctx->from.bin, ctx->to.uid, getpid() );
	
			// WK: wait the first SuRequestActivity terminates awaking the app
			//if (allow == INTERACTIVE) {
				// WK: disabled on 12/03/2023: This no longer needed.
				//sleep(1);
			//}
			// SuperPower support
		 if (ctx->is_premium == 1) {
			// SuperPower support
		    // WK, on 20/10/22: the Android 10/11 have restrictions against SuRequestActivity being launched indirectly via a broadcast  (SuRequestReceiver). we need to start the activity directly using "am start" command.
		    snprintf(command, sizeof(command),
            "/system/bin/am '%s' --user %d -a '%s' "
            "--ei caller_uid '%d' --es caller_bin '%s' --ei allow '%d' --ei desired_uid '%d' --es desired_cmd '%s' "
            "--ei version_code '%d' -n '%s' --include-stopped-packages --receiver-replace-pending",
           (allow == INTERACTIVE) ? "start" : "broadcast", ctx->user.userid, action, /*socket_path,*/ uid, ctx->from.bin, allow, ctx->to.uid, ctx->to.log_path/*get_command(&ctx->to)*/,
            /*ctx->to.all,*/ VERSION_CODE, (allow == INTERACTIVE) ? SU_REQUEST_ACTIVITY_PREMIUM: SU_RESULT_RECEIVER_PREMIUM);
			} else {
		// WK, on 20/10/22: the Android 10/11 have restrictions against SuRequestActivity being launched indirectly via a broadcast  (SuRequestReceiver). we need to start the activity directly using "am start" command.
		snprintf(command, sizeof(command),
            "/system/bin/am '%s' --user %d -a '%s' "
            "--ei caller_uid '%d' --es caller_bin '%s' --ei allow '%d' --ei desired_uid '%d' --es desired_cmd '%s' "
            "--ei version_code '%d' -n '%s' --include-stopped-packages --receiver-replace-pending",
           (allow == INTERACTIVE) ? "start" : "broadcast", ctx->user.userid, action, /*socket_path,*/ uid, ctx->from.bin, allow, ctx->to.uid, ctx->to.log_path/*get_command(&ctx->to)*/,
            /*ctx->to.all,*/ VERSION_CODE, (allow == INTERACTIVE) ? SU_REQUEST_ACTIVITY: SU_RESULT_RECEIVER);
       } 
}
	    // SuperSU support
	   else if (ctx->to.pref_switch_superuser == SUPERSU) {
		
		  // WK, on 20/10/22: the Android 10/11 have restrictions against SuRequestActivity being launched indirectly via a broadcast. we need to start the activity directly using "am start" command.
		snprintf(command, sizeof(command),
            "/system/bin/am '%s' --user %d -a 'eu.chainfire.supersu.NativeAccess' "
            "--ei su_fromuid '%d' --es su_appname '%s' --ei su_access '%d' --ei su_touid '%d' --es su_cmd '%s' "
            "--ei su_code '%d' --ei su_uid_mismatch '0' -n '%s' --include-stopped-packages --receiver-replace-pending",
           /*(allow == INTERACTIVE) ? "start" :*/ "broadcast", ctx->user.userid, /*action,*/ /*socket_path,*/ uid, ctx->from.bin, (allow == INTERACTIVE) ? 2 : allow, ctx->to.uid, ctx->to.log_path/*get_command(&ctx->to)*/,
            /*ctx->to.all,*/ su_code, /*(allow == INTERACTIVE) ? "eu.chainfire.supersu/.PromptActivity" :*/ "eu.chainfire.supersu/.NativeAccessReceiver");
   	   } 
	   // Magisk Support
	   else if (ctx->to.pref_switch_superuser == MAGISK){
		   //snprintf(ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", ctx->user.logs_path, ctx->from.uid, ctx->from.bin, ctx->to.uid, getpid() );
	
		   if (allow == INTERACTIVE) {
		       snprintf(command, sizeof(command), "/system/bin/am start -p 'com.topjohnwu.magisk' --user %d -a 'android.intent.action.VIEW'  -f '0x58800020' --es action 'request' --es fifo '%s' --ei uid '%d' --ei pid '%d' -n 'com.topjohnwu.magisk/com.topjohnwu.magisk.ui.surequest.SuRequestActivity'", ctx->user.userid, ctx->to.fifo, uid, ctx->from.pid);
		   } else {
			    snprintf(command, sizeof(command), "/system/bin/am start -p 'com.topjohnwu.magisk' --user %d -a 'android.intent.action.VIEW'  -f '0x58800020' --es action 'log' --ei from.uid '%d' --ei to.uid '%d' --ei pid '%d' --ei policy '%d' --es command '%s' --ez notify '%s' -n 'com.topjohnwu.magisk/com.topjohnwu.magisk.ui.surequest.SuRequestActivity'", ctx->user.userid, uid, ctx->to.uid, ctx->from.pid, (allow == ALLOW) ? 2: 1, ctx->to.log_path, (ctx->notify == 1) ? "true" : "false");
		       // WK: line disabled on 25/02/2023: Magisk will refuse to send notifications from non Magisk apps throug this method on android 12. Fall back to using "am start" instead.
			   //snprintf(command, sizeof(command), "/system/bin/content call --uri content://com.topjohnwu.magisk.provider --user %d --method 'log' --extra from.uid:i:'%d' --extra to.uid:i:'%d' --extra pid:i:'%d' --extra policy:i:'%d' --extra command:s:'%s' --extra notify:b:'%s'", ctx->user.userid, uid, ctx->to.uid, ctx->from.pid, (allow == ALLOW) ? 2: 1, ctx->to.log_path, (ctx->notify == 1) ? "true" : "false");
		   }
	   }
	   
	   char *args[] = { "sh", "-c", command, NULL, };

	   //char *my_env[] = {"LD_LIBRARY_PATH=/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib", "CLASSPATH=/system/framework/am.jar",  NULL};

        /*
         * before sending the intent, make sure the effective uid/gid match
         * the real uid/gid, otherwise LD_LIBRARY_PATH is wiped
         * in Android 4.0+.
         */
        set_identity(0);
        int zero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
        dup2(zero, 0);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        dup2(null, 1);
        dup2(null, 2);
        LOGD("Executing %s\n", command);
        execve(_PATH_BSHELL, args, envp);
        PLOGE("exec am");
        _exit(EXIT_FAILURE);
    }
    /* Parent */
    /* WK: on 17/02/2023: replaced fork() by fork_zero_fucks()  that prevents zombies processes and garante that FlashFire continue its work
	  fully eliminated the chances of an error in send_intent()
	if (pid < 0) {
        PLOGE("fork");
        return -1;
    }
    ctx->child = pid;*/
    return 0;
}
