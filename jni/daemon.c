/*
** Copyright 2010, Adam Shanks (@ChainsDD)
** Copyright 2008, Zinx Verituse (@zinxv)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0pl ĺllnlll  
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define _GNU_SOURCE /* for unshare() */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
//#include <sys/mount.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <termios.h>
#include <signal.h>
#include <string.h>
//#include <log/log.h>
#include <linux/fs.h>
#include <cutils/multiuser.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <paths.h>
#include <strings.h>

#include <stdio.h>


#include "su.h"
#include "utils.h"
#include "pts.h"

int is_daemon = 0;
int daemon_from_uid = 0;
int daemon_from_pid = 0;

// Constants for the atty bitfield
#define ATTY_IN     1
#define ATTY_OUT    2
#define ATTY_ERR    4

/*
 * Receive a file descriptor from a Unix socket.
 * Contributed by @mkasick
 *
 * Returns the file descriptor on success, or -1 if a file
 * descriptor was not actually included in the message
 *
 * On error the function terminates by calling exit(-1)
 */
static int recv_fd(int sockfd) {
    // Need to receive data from the message, otherwise don't care about it.
    char iovbuf;

    struct iovec iov = {
        .iov_base = &iovbuf,
        .iov_len  = 1,
    };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    if (recvmsg(sockfd, &msg, MSG_WAITALL) != 1) {
        goto error;
    }

    // Was a control message actually sent?
    switch (msg.msg_controllen) {
    case 0:
        // No, so the file descriptor was closed and won't be used.
        return -1;
    case sizeof(cmsgbuf):
        // Yes, grab the file descriptor from it.
        break;
    default:
        goto error;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg             == NULL                  ||
        cmsg->cmsg_len   != CMSG_LEN(sizeof(int)) ||
        cmsg->cmsg_level != SOL_SOCKET            ||
        cmsg->cmsg_type  != SCM_RIGHTS) {
error:
        LOGE("unable to read fd");
        exit(-1);
    }

    return *(int *)CMSG_DATA(cmsg);
}

/*
 * Send a file descriptor through a Unix socket.
 * Contributed by @mkasick
 *
 * On error the function terminates by calling exit(-1)
 *
 * fd may be -1, in which case the dummy data is sent,
 * but no control message with the FD is sent.
 */
static void send_fd(int sockfd, int fd) {
    // Need to send some data in the message, this will do.
    struct iovec iov = {
        .iov_base = "",
        .iov_len  = 1,
    };

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
    };

    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    if (fd != -1) {
        // Is the file descriptor actually open?
        if (fcntl(fd, F_GETFD) == -1) {
            if (errno != EBADF) {
                goto error;
            }
            // It's closed, don't send a control message or sendmsg will EBADF.
        } else {
            // It's open, send the file descriptor in a control message.
            msg.msg_control    = cmsgbuf;
            msg.msg_controllen = sizeof(cmsgbuf);

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

            cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type  = SCM_RIGHTS;

            *(int *)CMSG_DATA(cmsg) = fd;
        }
    }

    if (sendmsg(sockfd, &msg, 0) != 1) {
error:
        PLOGE("unable to send fd");
        exit(-1);
    }
}

static int read_int(int fd) {
    int val;
    int len = read(fd, &val, sizeof(int));
    if (len != sizeof(int)) {
        LOGE("unable to read int: %d", len);
        exit(-1);
    }
    return val;
}

static void write_int(int fd, int val) {
    int written = write(fd, &val, sizeof(int));
    if (written != sizeof(int)) {
        PLOGE("unable to write int");
        exit(-1);
    }
}

static char* read_string(int fd) {
    int len = read_int(fd);
    if (len > PATH_MAX || len < 0) {
        LOGE("invalid string length %d", len);
        exit(-1);
    }
    char* val = malloc(sizeof(char) * (len + 1));
    if (val == NULL) {
        LOGE("unable to malloc string");
        exit(-1);
    }
    val[len] = '\0';
    int amount = read(fd, val, len);
    if (amount != len) {
        LOGE("unable to read string");
        exit(-1);
    }
    return val;
}

static void write_string(int fd, char* val) {
    int len = strlen(val);
    write_int(fd, len);
    int written = write(fd, val, len);
    if (written != len) {
        PLOGE("unable to write string");
        exit(-1);
    }
}
/*
static void mount_emulated_storage(int user_id) {
    const char *emulated_source = getenv("EMULATED_STORAGE_SOURCE");
    const char *emulated_target = getenv("EMULATED_STORAGE_TARGET");
    const char* legacy = getenv("EXTERNAL_STORAGE");

    if (!emulated_source || !emulated_target) {
        // No emulated storage is present
        return;
    }

    // Create a second private mount namespace for our process
    if (unshare(CLONE_NEWNS) < 0) {
        PLOGE("unshare");
        return;
    }

    if (mount("rootfs", "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
        PLOGE("mount rootfs as slave");
        return;
    }

    // /mnt/shell/emulated -> /storage/emulated
    if (mount(emulated_source, emulated_target, NULL, MS_BIND, NULL) < 0) {
        PLOGE("mount emulated storage");
    }

    char target_user[PATH_MAX];
    snprintf(target_user, PATH_MAX, "%s/%d", emulated_target, user_id);

    // /mnt/shell/emulated/<user> -> /storage/emulated/legacy
    if (mount(target_user, legacy, NULL, MS_BIND | MS_REC, NULL) < 0) {
        PLOGE("mount legacy path");
    }
}*/

static int run_daemon_child(int infd, int outfd, int errfd, int argc, char** argv) {
    if (-1 == dup2(outfd, STDOUT_FILENO)) {
        PLOGE("dup2 child outfd");
        exit(-1);
    }

    if (-1 == dup2(errfd, STDERR_FILENO)) {
        PLOGE("dup2 child errfd");
        exit(-1);
    }

    if (-1 == dup2(infd, STDIN_FILENO)) {
        PLOGE("dup2 child infd");
        exit(-1);
    }

    close(infd);
    close(outfd);
    close(errfd);

	/* WK: on 13/03/2023: this was being called on the wrong side of the wire: pump_stdin_async() on the client's side:
    * The Terminal stdin is already set, but we try to set it again, leaving it into an unexpected state after using pipe commands like 
	* su -c ps | grep su.
    * Thus, moved to daemon.c -> run_daemon_child(): set the new attibutes on the pty not the TTY stdin.
	*/
	// Put the PTY's stdin into raw mode
	//set_stdin_raw();
	
    return su_main(argc, argv, 0, NULL);
}
extern userid_t multiuser_get_user_id(uid_t uid);

static int daemon_accept(int fd) {
    is_daemon = 1;
    int pid = read_int(fd);
    int child_result;
    LOGD("remote pid: %d", pid);
    char *pts_slave = read_string(fd);
    LOGD("remote pts_slave: %s", pts_slave);
    daemon_from_pid = read_int(fd);
    LOGD("remote req pid: %d", daemon_from_pid);

    struct ucred credentials;
    socklen_t ucred_length = sizeof(credentials);
    /* fill in the user data structure */
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &ucred_length)) {
        LOGE("could obtain credentials from unix domain socket");
        exit(-1);
    }

    daemon_from_uid = credentials.uid;

    //int mount_storage = read_int(fd);
    // The the FDs for each of the streams
    int infd  = recv_fd(fd);
    int outfd = recv_fd(fd);
    int errfd = recv_fd(fd);

    int argc = read_int(fd);
    if (argc < 0 || argc > 512) {
        LOGE("unable to allocate args: %d", argc);
        exit(-1);
    }
    LOGD("remote args: %d", argc);
    char** argv = (char**)malloc(sizeof(char*) * (argc + 1));
    argv[argc] = NULL;
    int i;
    for (i = 0; i < argc; i++) {
        argv[i] = read_string(fd);
    }

	int environ_size = read_int(fd);
    if (environ_size < 0 || environ_size > 512) {
        LOGE("unable to allocate environ: %d", environ_size);
        exit(-1);
    }
	
	char** client_environment = (char**)malloc(sizeof(char*) * (environ_size + 1));
    LOGD("environ_size = %d", environ_size);
	
	
	int j;
    for (j = 0; j < environ_size; j++) {
        client_environment[j] = read_string(fd);
		putenv(client_environment[j]);
		LOGD("client_environment[%d]=%s", j, client_environment[j]);
		if (client_environment[j] == NULL) {
			break;
		}
    }
	
	int len = read_int(fd);
    char *cwd = read_string(fd);
	LOGD("cwd: %s", cwd);
	// ack
    write_int(fd, 1);

    // Fork the child process. The fork has to happen before calling
    // setsid() and opening the pseudo-terminal so that the parent
    // is not affected
    int child = fork();
    if (child < 0) {
        for (i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);

        // fork failed, send a return code and bail out
        PLOGE("unable to fork");
        write(fd, &child, sizeof(int));
        close(fd);
        return child;
    }

    if (child != 0) {
        for (i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);

        // In parent, wait for the child to exit, and send the exit code
        // across the wire.
        int status, code;

        free(pts_slave);

        LOGD("waiting for child [%d] exit", child);
        if (waitpid(child, &status, 0) > 0) {
        if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
            LOGD("Process terminated with status WEXITSTATUS[%d] and code[%d].", WEXITSTATUS(status), code);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
	    LOGD("Process terminated with signal status WTERMSIG[%d] and code[%d].", WTERMSIG(status), code);
        } else {
            code = -1;
        }
    }
    else {
        code = -1;
    }

        // Is the file descriptor actually open?
        if (fcntl(fd, F_GETFD) == -1) {
            if (errno != EBADF) {
                goto error;
            }
        }

        // Pass the return code back to the client
        LOGD("sending code %d", code);
        if (write(fd, &code, sizeof(int)) != sizeof(int)) {
            PLOGE("unable to write exit code");
        }

        close(fd);
error:
        LOGD("child exited");
        return code;
    }

    // We are in the child now
    // Close the unix socket file descriptor
    close (fd);

    // Become session leader
    if (setsid() == (pid_t) -1) {
        PLOGE("setsid");
    }

    int ptsfd;
    if (pts_slave[0]) {
        // Opening the TTY has to occur after the
        // fork() and setsid() so that it becomes
        // our controlling TTY and not the daemon's
        ptsfd = open(pts_slave, O_RDWR);
        if (ptsfd == -1) {
            PLOGE("open(pts_slave) daemon");
            exit(-1);
        }

        struct stat st;
        if (fstat(ptsfd, &st)) {
            PLOGE("failed to stat pts_slave");
            exit(-1);
        }

        if (st.st_uid != credentials.uid) {
            PLOGE("caller doesn't own proposed PTY");
            exit(-1);
        }

        if (!S_ISCHR(st.st_mode)) {
            PLOGE("proposed PTY isn't a chardev");
            exit(-1);
        }

        if (infd < 0)  {
            LOGD("daemon: stdin using PTY");
            infd  = ptsfd;
        }
        if (outfd < 0) {
            LOGD("daemon: stdout using PTY");
            outfd = ptsfd;
        }
        if (errfd < 0) {
            LOGD("daemon: stderr using PTY");
            errfd = ptsfd;
        }
    } else {
        // TODO: Check system property, if PTYs are disabled,
        // made infd the CTTY using:
        // ioctl(infd, TIOCSCTTY, 1);
    }
    free(pts_slave);
/*
    if (mount_storage) {
        mount_emulated_storage(multiuser_get_user_id(daemon_from_uid));
    }*/
    chdir(cwd);
    child_result = run_daemon_child(infd, outfd, errfd, argc, argv);
    for (i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    return child_result;
}

//WK taken from su-hide on github on 07/11/2022:
// find pid for process, returns 0 on error
static pid_t find_process(char* name) {
    char buf[PATH_MAX], path[PATH_MAX];
    pid_t ret = 0;
    DIR* dir;
    struct dirent *ent;
    if ((dir = opendir("/proc/")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            pid_t pid = atoi(ent->d_name);
            if (pid > 0) {
                memset(path, 0, 64);
                snprintf(path, 64, "/proc/%d/exe", pid);
                int len = readlink(path, buf, PATH_MAX);
                if ((len >= 0) && (len < PATH_MAX)) {
                    buf[len] = '\0';
                    if (strstr(buf, "app_process") != NULL) {
                        memset(path, 0, 64);
                        snprintf(path, 64, "/proc/%d/cmdline", pid);
                        int fd = open(path, O_RDONLY);
                        if (fd >= 0) {
                            if (read(fd, buf, PATH_MAX) > strlen(name)) {
                                if ((strncmp(buf, name, strlen(name)) == 0) && ((buf[strlen(name)] == '\0') || (buf[strlen(name)] == ' '))) {
                                    ret = pid;
                                }
                            }
                            close(fd);
                        }
                    }
                }
            }
            if (ret > 0) break;
        }
        closedir(dir);
    }
    return ret;
}

int run_daemon() {
    if (getuid() != 0 || getgid() != 0) {
        PLOGE("daemon requires root. uid/gid not root");
        return -1;
    }

	//if (fork_zero_fucks() == 0) {
		switch (fork()) {
			case 0:
		    setsid();
			switch_mnt_ns(1);
			break;
			default:
			exit(0);
		}
     // WK, on 19/10/2022: suadded for Android 11:
	char *args[] = { "/sbin/supolicy", "/sbin/supersu/bin/supolicy_wrapped", "/su/bin/supolicy_wrapped", "/system/xbin/supolicy", "/system/bin/supolicy", NULL, };
    char * supolicy = NULL;
	int i= 0;
	
	for (i =0; i < 5;i++) {
		  if (access (args [i], X_OK) == 0) {
			  supolicy = args[i];
			  break;
		  }
	}
    char run_supolicy [ARG_MAX];
	snprintf (run_supolicy, ARG_MAX, "%s --live \'allow untrusted_app_all magisk unix_stream_socket connectto\'", supolicy);
	char *command_args[] = { "sh", "-c", run_supolicy, NULL, };

	/*char *my_env[] = {"LD_LIBRARY_PATH=/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib", NULL};
	char *envp[512];
	envp[0] = "LD_LIBRARY_PATH=/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib";
	envp[1] = NULL;
	*/
	pid_t zygote_pid = find_process("zygote");
	LOGI("zygote_pid %d", zygote_pid);
	
	char path[PATH_MAX];
	int err;
	int fd;
    ssize_t len;
	//int i;
	size_t j;
	char env[ARG_MAX];
    char *envp[512];
	char * const* zygote_env = environ;
	
	 /* Get the environment of the zygote process */
    snprintf(path, sizeof(path), "/proc/%u/environ", zygote_pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        PLOGE("Opening environment");
        //goto out;
    }
    len = read(fd, env, sizeof(env));
    err = errno;
    close(fd);
    if (len < 0 || len == sizeof(env)) {
        PLOGEV("Reading environment", err);
        //goto out;
    }
    env[len] = '\0';

    envp[0] = &env[0];
	
    for (i = 0, j = 0; i < len && j < ARRAY_SIZE(envp); i++) {
	putenv(envp[j]);
        if (env[i] == '\0') {
            envp[++j] = &env[i + 1];
        }
    }
	/* WK, on 10/02/2023: on Android 12, /system/lib64 comes first instead of /system/lib in order to load the correct libc.so and prevent executable linkage error due to the device is arm64-v8a:
	 * CANNOT LINK EXECUTABLE "sh" libc.so needed or dlopended is not accessible by namespace "default"
	 */
	envp[j] = "LD_LIBRARY_PATH=/system/lib64:/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib";
	LOGI("envp[%d]=%s", j, envp[j]);
    //envp[j++] = NULL;
	putenv(envp[j]);
	if (envp[0]) {
		LOGI("envp[0]=%s",envp[0]);
        zygote_env = envp;
	}
	
	int  pid = fork ();
	   if (!pid) {
		   char *lb_library_path = getenv("LD_LIBRARY_PATH");
	LOGI("LD_LIBRARY_PATH is set: %s", lb_library_path);
	
		  /* if(putenv("LD_LIBRARY_PATH=/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib")) {
			   PLOGE("putenv()");
		   }*/
		   //unsetenv("LB_PRELOAD");
		   LOGI("executing supolicy --live %s", run_supolicy);
		  // WK, on 10/11/2022: this will not work on Android 12 because it removes LD_LIBRARY_PATH from execve(). Fixed on SuperPower: prior to calling the daemon start we now fixes the run_supolicy by calling supolicy in SuperPower. 
		   execve(_PATH_BSHELL, command_args, zygote_env);
		   // execv(supolicy, run_supolicy/*, zygote_env*/);
		  // execle(supolicy, supolicy, "--live", run_supolicy/*(char*)run_supolicy*//*, my_env*/, NULL,/* my_env*//*envp*/zygote_env);
		  PLOGE("execve");
		   exit (1);
		   //execv (supolicy, run_supolicy); //"allow untrusted_app init unix_stream_socket connectto");
		  // execl(supolicy, supolicy, "--live \\'allow untrusted_app init unix_stream_socket connectto\\'", NULL);
	   } else {
        int status, code;

        LOGI("Waiting for pid %d.", pid);
        waitpid(pid, &status, 0);
        /*if (packageName) {
            appops_finish_op_su(ctx->from.uid, packageName);
        }*/
		code = WEXITSTATUS(status);
        // exit(code/*status*/);
	}
   // int fd;
    struct sockaddr_un sun;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        PLOGE("socket");
        return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        PLOGE("fcntl FD_CLOEXEC");
        goto err;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
   // sprintf(sun.sun_path, "%s/su-daemon", REQUESTOR_DAEMON_PATH/*DAEMON_SOCKET_PATH*/);

    /*
     * Delete the socket to protect from situations when
     * something bad occured previously and the kernel reused pid from that process.
     * Small probability, isn't it.
     */
    /*unlink(sun.sun_path);
    unlink(REQUESTOR_DAEMON_PATH);

    int previous_umask = umask(027);
    mkdir(REQUESTOR_DAEMON_PATH, DAEMON_SOCKET_PATH, 0711);
*/
	memset(sun.sun_path, 0, sizeof(sun.sun_path));
    memcpy(sun.sun_path, "\0" "SUPERPOWER", strlen("SUPERPOWER") + 1);
	
    if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
        PLOGE("daemon bind");
        goto err;
    }
/*
    chmod(REQUESTOR_DAEMON_PATH, 0711);
    chmod(sun.sun_path, 0666);

    umask(previous_umask);
*/
    if (listen(fd, 10) < 0) {
        PLOGE("daemon listen");
        goto err;
    }

    int client;
    while ((client = accept(fd, NULL, NULL)) > 0) {
        if (fork_zero_fucks() == 0) {
            close(fd);
            return daemon_accept(client);
        }
        else {
            close(client);
        }
    }

    LOGE("daemon exiting");
err:
    close(fd);
	
    return -1;
	//}
}

// List of signals which cause process termination
static int quit_signals[] = { SIGALRM, SIGHUP, SIGPIPE, SIGQUIT, SIGTERM, SIGINT, 0 };

static void sighandler(__attribute__ ((unused)) int sig) {
    restore_stdin();

    // Assume we'll only be called before death
    // See note before sigaction() in set_stdin_raw()
    //
    // Now, close all standard I/O to cause the pumps
    // to exit so we can continue and retrieve the exit
    // code
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Put back all the default handlers
    struct sigaction act;
    int i;

    memset(&act, '\0', sizeof(act));
    act.sa_handler = SIG_DFL;
    for (i = 0; quit_signals[i]; i++) {
        if (sigaction(quit_signals[i], &act, NULL) < 0) {
            PLOGE("Error removing signal handler");
            continue;
        }
    }
}

/**
 * Setup signal handlers trap signals which should result in program termination
 * so that we can restore the terminal to its normal state and retrieve the 
 * return code.
 */
static void setup_sighandlers(void) {
    struct sigaction act;
    int i;

    // Install the termination handlers
    // Note: we're assuming that none of these signal handlers are already trapped.
    // If they are, we'll need to modify this code to save the previous handler and
    // call it after we restore stdin to its previous state.
    memset(&act, '\0', sizeof(act));
    act.sa_handler = &sighandler;
    for (i = 0; quit_signals[i]; i++) {
        if (sigaction(quit_signals[i], &act, NULL) < 0) {
            PLOGE("Error installing signal handler");
            continue;
        }
    }
}

int connect_daemon(int argc, char *argv[]/*, int ppid*/, char** env) {
    int ptmx = -1;
    char pts_slave[PATH_MAX];
    int outfd[2];
	
    struct sockaddr_un sun;
    
	char path[PATH_MAX];
	char cwd[4096];
	ssize_t len;
	
    // Open a socket to the daemon
    int socketfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (socketfd < 0) {
        PLOGE("socket");
        exit(-1);
    }
    if (fcntl(socketfd, F_SETFD, FD_CLOEXEC)) {
        PLOGE("fcntl FD_CLOEXEC");
        exit(-1);
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    //sprintf(sun.sun_path, "%s/su-daemon", REQUESTOR_DAEMON_PATH/*DAEMON_SOCKET_PATH*/);

	memset(sun.sun_path, 0, sizeof(sun.sun_path));
    memcpy(sun.sun_path, "\0" "SUPERPOWER", strlen("SUPERPOWER") + 1);
	
    if (0 != connect(socketfd, (struct sockaddr*)&sun, sizeof(sun))) {
        PLOGE("connect");
        exit(-1);
    }

    LOGD("connecting client %d", getpid());

   // int mount_storage = getenv("MOUNT_EMULATED_STORAGE") != NULL;

    // Determine which one of our streams are attached to a TTY
    int atty = 0;

    // TODO: Check a system property and never use PTYs if
    // the property is set.
    if (isatty(STDIN_FILENO))  atty |= ATTY_IN;
    if (isatty(STDOUT_FILENO)) atty |= ATTY_OUT;
    if (isatty(STDERR_FILENO)) atty |= ATTY_ERR;

    if (atty) {
        // We need a PTY. Get one.
        ptmx = pts_open(pts_slave, sizeof(pts_slave));
        if (ptmx < 0) {
            PLOGE("pts_open");
            exit(-1);
        }
    } else {
        pts_slave[0] = '\0';
    }

    // Send some info to the daemon, starting with our PID
    write_int(socketfd, getpid());
    // Send the slave path to the daemon
    // (This is "" if we're not using PTYs)
    write_string(socketfd, pts_slave);
    // Parent PID
    write_int(socketfd, getppid());
    //write_int(socketfd, mount_storage);

    // Send stdin
    if (atty & ATTY_IN) {
        // Using PTY
        send_fd(socketfd, -1);
    } else {
        send_fd(socketfd, STDIN_FILENO);
    }

    // Send stdout
    if (atty & ATTY_OUT) {
        // Forward SIGWINCH
        watch_sigwinch_async(STDOUT_FILENO, ptmx);

        // Using PTY
        send_fd(socketfd, -1);
    } else {
	    
        if (pipe(outfd) < 0) {
	    PLOGE("pipe(outfd)");
	    exit(-1);
	} else {
            LOGD("outfd pipes are open: [%d][%d]", outfd[0], outfd[1]);
	    // Send stdout
	    send_fd(socketfd, outfd[1]/*STDOUT_FILENO*/);
	}
	    
    }

    // Send stderr
    if (atty & ATTY_ERR) {
        // Using PTY
        send_fd(socketfd, -1);
    } else {
        send_fd(socketfd, STDERR_FILENO);
    }

    // Number of command line arguments
    write_int(socketfd, /*mount_storage ? argc - 1 :*/ argc);

    // Command line arguments
    int i;
    for (i = 0; i < argc; i++) {
        /*if (i == 1 && mount_storage) {
            continue;
        }*/
        write_string(socketfd, argv[i]);
    }

	int j = 0;
	while (env[j] != NULL) {
		//j++;
		LOGD("j[%d]=[%s]", j, env[j]);
		//if (env[j] != NULL) {
		   // write_string(socketfd, env[j]);
			j++;
	    //} 
		/*if (env[j] == NULL) {
			
			write_string(socketfd, '\0');
		}*/
	}
	
	write_int(socketfd, j);
	int h;
	for (h = 0; h < j; h++) {
		
	//while (j != 0) {
		write_string(socketfd, env[h]);
		//j--;
	}
	
    snprintf(path, sizeof(path), "/proc/self/cwd");
	len = readlink(path, cwd, sizeof(cwd));
    if (len < 0) {
        PLOGE("Getting cwd path");
        return -1;
    }
    cwd[len] = '\0';
	
	write_int(socketfd, len);
	write_string(socketfd, cwd);
   // for (; j < /*sizeof(env)/sizeof(env[0])*/; j++) {
        /*if (i == 1 && mount_storage) {
            continue;
        }*/
       // write_string(socketfd, env[j]);
   // }
	
    // Wait for acknowledgement from daemon
    read_int(socketfd);

    if (atty & ATTY_IN) {
        setup_sighandlers();
        pump_stdin_async(ptmx, -1);
    }
    if (atty & ATTY_OUT) {
        pump_stdout_blocking(ptmx, -1);
    }
    
    close(outfd[1]);
    pump_stdout_blocking(outfd[0], -1);
    close(outfd[0]);
	
    // Get the exit code
    int code = read_int(socketfd);
    close(socketfd);
    LOGD("client exited %d", code);

    return code;
}
