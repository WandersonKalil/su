/*
** Copyright 2016-2023 Wanderson Kalil (@WKSuperPower)
   Copyright 2010, Adam Shanks (@ChainsDD)
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
#include <sys/stat.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/syscall.h>
#include <paths.h>
#include <libgen.h>
#include <time.h>
#include <sys/mount.h>
#include <linux/mount.h>
#include <private/android_filesystem_config.h>

#include "su.h"
#include "utils.h"
#include "pts.h"

extern int is_daemon;
extern int daemon_from_uid;
extern int daemon_from_pid;

int fork_zero_fucks() {
    int pid = fork();
    if (pid) {
        int status;
        waitpid(pid, &status, 0);
        return pid;
    }
    else {
        if ((pid = fork()))
            exit(0);
        return 0;
    }
}

static int from_init(struct su_initiator *from)
{
    char path[PATH_MAX], exe[PATH_MAX];
    char args[4096], *argv0, *argv_rest;
    int fd;
    ssize_t len;
    int i;
    int err;
    char *data;
	char status[PATH_MAX];
	char status_data[ARG_MAX];
	pid_t ppid = 0;
	uid_t uid = 0;
	size_t j;
	
    from->uid = getuid();
    from->pid = getppid();

	if (is_daemon) {
        from->uid = daemon_from_uid;
        from->pid = daemon_from_pid;
    }
	
    /* Get the command line */
    snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        //PLOGE("Opening command line");
        return -1;
    }
    len = read(fd, args, sizeof(args));
    //err = errno;
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        //PLOGEV("Reading command line", err);
        return -1;
    } 
    // WK, on 04/03/2023: we may not check for the "." because apps like Termux have the package name as "/data/data/com.termux/files/usr/bin/bash". fallback to using app_process:
	//while (strstr(args, ".") == NULL) {
	snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
	while((len = readlink(path, exe, sizeof(exe))) > 0) {
	    exe[len] = '\0';
		if (strstr(exe, "app_process") != NULL) {
		    break;
		}
		snprintf (status, sizeof(status), "/proc/%u/status", from->pid);
		//data = read_file(status);
		fd = open(status, O_RDONLY);
        if (fd < 0) {
            //PLOGE("Opening status");
           //return -1;
		   
	    from->uid = getuid();
        from->pid = getppid();

	    if (is_daemon) {
            from->uid = daemon_from_uid;
            from->pid = daemon_from_pid;
         }
		   break;
        }
		memset (args,0, sizeof (args));
        len = read(fd, args, sizeof(args));
        err = errno;
        close(fd);
        if (len < 0 || len == sizeof(args)) {
           //PLOGEV("Reading command line", err);
           //return -1;
		   from->uid = getuid();
           from->pid = getppid();

	      if (is_daemon) {
              from->uid = daemon_from_uid;
              from->pid = daemon_from_pid;
          }
		  break;
        } 
        data = args;
		
		//LOGD("data: %s", data);
		
		char *property_found =  strstr(data, "PPid:");//check_property(data, "PPid");
		char *value, *eol;
		value = strchr(property_found, ':');
		eol = strchr(property_found, '\n');
       // key = sol;
        *eol++ = 0;
       // sol = eol;
        // key = eol;
       // value = strchr(key, ':');
       // if(value == 0) continue;
        *value++ = 0;
		ppid = atoi (value);
		from->pid = ppid;
		/* if (ppid == 1)
		     break;*/
		//LOGD ("value=%d", atoi(value)/*value*/);
        property_found = strstr(eol, "Uid:");//check_property(data, "PPid");
		//LOGD ("property_found=%s", property_found);
     
		value = strchr(property_found, ':');
		//eol = strchr(property_found, '\n');
       // key = sol;
        //*eol++ = 0;
       // sol = eol;
        // key = eol;
       // value = strchr(keyo, ':');
       // if(value == 0) continue;
        *value++ = 0;
		uid = atoi (value);//get_prop(data, "PPid:");
		from->uid = uid;
		
		/* Get the command line */
    snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        //PLOGE("Opening command line");
        //return -1;
		from->uid = getuid();
           from->pid = getppid();

	      if (is_daemon) {
              from->uid = daemon_from_uid;
              from->pid = daemon_from_pid;
          }
		  break;
    }
    len = read(fd, args, sizeof(args));
    //err = errno;
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        //PLOGEV("Reading command line", err);
        //return -1;
		from->uid = getuid();
           from->pid = getppid();

	      if (is_daemon) {
              from->uid = daemon_from_uid;
              from->pid = daemon_from_pid;
          }
		  break;
    } 
 
	snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
	
 }

		//uid  = //get_prop(data, "Uid:");
		
		
		//get_property(data, uid, "Uid", "");
		
		//LOGD ("PPid=%d Uid=%d",ppid, uid);
	   /* from->pid = atoi(ppid);
		from->uid = atoi (uid);
		*/
	snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        //PLOGE("Opening command line");
        return -1;
    }
	memset (args,0, sizeof (args));
    len = read(fd, args, sizeof(args));
    //err = errno;
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        //PLOGEV("Reading command line", err);
        return -1;
    } 
	//LOGD ("args: %s", args);
	/*if (strstr(args, ".")) {
		break;
	}*/
 //}
   /* if (check_property(data, "ro.cm.version")) {
        get_property(data, build_type, "ro.build.type", "");
	}*/
	
    argv0 = args;
    argv_rest = NULL;
    for (i = 0; i < len; i++) {
        if (args[i] == '\0') {
            if (!argv_rest) {
                argv_rest = &args[i+1];
            } else {
                args[i] = ' ';
            }
        }
    }
    args[len] = '\0';

    if (argv_rest) {
        strncpy(from->args, argv_rest, sizeof(from->args));
        from->args[sizeof(from->args)-1] = '\0';
    } else {
        from->args[0] = '\0';
    }

	// WK: if this is not an app package name, use the binary name instead of the real path
	//if (strstr(args, ".") == NULL) {
    /* If this isn't app_process, use the real path instead of argv[0] */
    snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
    len = readlink(path, exe, sizeof(exe));
    if (len < 0) {
        PLOGE("Getting exe path");
        return -1;
    }
    exe[len] = '\0';
	
    if (strcmp(exe, "/system/bin/app_process") != 0) {
		if (strcmp(exe, "/system/bin/app_process32") != 0) {
			if (strcmp(exe, "/system/bin/app_process64") != 0) {
                argv0 = exe;
				argv0 = strrchr (argv0, '/');
                argv0 = (argv0) ? argv0 + 1 : args;
				memset(args, 0, sizeof(args));
				snprintf(args, sizeof(args), "%s_%d", argv0, from->uid);
				argv0 = args;
			}
		}
    }
//}

    strncpy(from->bin, argv0, sizeof(from->bin));
    from->bin[sizeof(from->bin)-1] = '\0';

	/* Get the environment of the calling process */
    snprintf(path, sizeof(path), "/proc/%u/environ", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        //PLOGE("Opening environment");
        goto out;
    }
    len = read(fd, from->env, sizeof(from->env));
    err = errno;
    close(fd);
    if (len < 0 || len == sizeof(from->env)) {
        //PLOGEV("Reading environment", err);
        goto out;
    }
    from->env[len] = '\0';

    from->envp[0] = &from->env[0];
    for (i = 0, j = 0; i < len && j < ARRAY_SIZE(from->envp); i++) {
        if (from->env[i] == '\0') {
                 from->envp[++j] = &from->env[i + 1];
        }
    }
    from->envp[j] = NULL;

out:
	
	
    return 0;
}

static void read_options(struct su_context *ctx)
{
	char pref_multiuser_mode[PROPERTY_VALUE_MAX];
	char pref_full_command_logging[PROPERTY_VALUE_MAX];
	char pref_root[PROPERTY_VALUE_MAX];
	char pref_switch_superuser[PROPERTY_VALUE_MAX];
	char defaul_access[PROPERTY_VALUE_MAX];
	char *caller_bin_access = NULL;
	char app_access[PROPERTY_VALUE_MAX];
	char notify[PROPERTY_VALUE_MAX];
	char pref_mount_namespace_separation[PROPERTY_VALUE_MAX];
	char supersu_prefences[PATH_MAX];
	
	struct stat st;
	char *data = NULL;
	
        if (stat(REQUESTOR_PREMIUM_DATA_PATH, &st) < 0) {
            PLOGE("stat %s", REQUESTOR_PREMIUM_DATA_PATH);
	    // WK: on 07/02/2024: use SuperPower's settings:
	    data = read_file(REQUESTOR_OPTIONS);
 	    snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
            ctx->user.userid, REQUESTOR);
	    snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
	    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path);	
        } else {
	  // WK: on 07/02/2024: use SuperPower Premium's settings:
	   ctx->is_premium = 1;
	   data = read_file(REQUESTOR_PREMIUM_OPTIONS);
	   snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
           ctx->user.userid, REQUESTOR_PREMIUM);
	   snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
	   LOGD("ctx->user.logs_path: %s", ctx->user.logs_path);	
	   snprintf(ctx->user.store_path, PATH_MAX, "%s", REQUESTOR_PREMIUM_STORED_PATH);
	   snprintf(ctx->user.store_default, PATH_MAX, "%s", REQUESTOR_PREMIUM_STORED_DEFAULT);
	}
	
	
	get_property(data, pref_switch_superuser, "pref_switch_superuser" , "1");
	
	if (atoi(pref_switch_superuser) == SUPERPOWER) {
	    ctx->to.pref_switch_superuser = SUPERPOWER;
		
	get_property(data, pref_multiuser_mode, "pref_multiuser_mode", "-1");
	get_property(data, pref_full_command_logging, "pref_full_command_logging", "0");
	get_property(data, pref_root, "pref_root", "3");
	//LOGD("REQUESTOR_OPTIONS: %s %d", data, atoi( pref_root));
	
	ctx->from.pref_root = atoi(pref_root);
	if (atoi(pref_multiuser_mode) == 0) {
		ctx->user.owner_mode = 0;
	} else if (atoi(pref_multiuser_mode) == 1) {
		ctx->user.owner_mode = 1;
	}
	get_property(data, pref_mount_namespace_separation, "pref_mount_namespace_separation", "1");
	
	if (ctx->enablemountnamespaceseparation != 0) {
        ctx->enablemountnamespaceseparation = atoi(pref_mount_namespace_separation);
	}
	ctx->pref_full_command_logging = atoi(pref_full_command_logging);

	}
	else if (atoi(pref_switch_superuser) == SUPERSU) {
		ctx->to.pref_switch_superuser = SUPERSU;
	
		if (access("/data/user_de", F_OK) == 0) {
	        snprintf(ctx->user.data_path, PATH_MAX, "/data/user_de/%d/eu.chainfire.supersu", ctx->user.userid);
	    } else {
		   snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
                ctx->user.userid, "eu.chainfire.supersu");
		}
		
			
		snprintf(supersu_prefences, PATH_MAX, "%s/shared_prefs/eu.chainfire.supersu_preferences.xml", ctx->user.data_path);
				
		//const char *supersu = "/data/data/eu.chainfire.supersu/files/supersu.cfg";
		//const char *
		char supersu_cfg[PATH_MAX];
		snprintf(supersu_cfg, sizeof(supersu_cfg), "%s/files/supersu.cfg", ctx->user.data_path);
		
		char requests[PATH_MAX];
		snprintf(requests, sizeof(requests), "%s/requests", ctx->user.data_path);
		
		mkdir(requests/*REQUESTOR_CACHE_PATH*/, 0770);
        if (chown(requests/*REQUESTOR_CACHE_PATH*/, AID_ROOT, AID_ROOT)) {
            PLOGE("chown (%s, %d, %d)", requests/*REQUESTOR_CACHE_PATH*/, AID_ROOT, AID_ROOT);
           // deny(&ctx);
        }
		
		//#define SUPERSU_CFG ctx->user.data_path "/files/supersu.cfg"
		data = read_file((char*)supersu_cfg);
	
	if (data != NULL) {
    get_property(data, pref_multiuser_mode, "enablemultiuser", "-1");
	if (atoi(pref_multiuser_mode) == 1) {
		ctx->user.owner_mode = 0;
	} 
	get_property(data, pref_full_command_logging, "log", "0");
	if (atoi(pref_full_command_logging) == 2) {
	    ctx->pref_full_command_logging = 1;//atoi(pref_full_command_logging);
	}
	get_property(data, pref_root, "enabled", "3");
	ctx->from.pref_root = atoi(pref_root);
	
	get_property(data, defaul_access, "access", "-1");
	ctx->access = atoi(defaul_access);
	
	if ((caller_bin_access = strstr(data, ctx->from.bin)) != NULL){
		get_property(caller_bin_access, app_access, "access", "-1");
	    ctx->access = atoi(app_access);
	}
	
		get_property(data, notify, "notify", "1");
	    ctx->notify = atoi(notify);

	
	get_property(data, pref_mount_namespace_separation, "enablemountnamespaceseparation", "1");
	if (ctx->enablemountnamespaceseparation != 0) {
        ctx->enablemountnamespaceseparation = atoi(pref_mount_namespace_separation);
	}
	} else {
		// WK, on 25/02/2023: SuperSU will not create supersu.cfg due to "toolbox id" returning "id: no suck tool" on Android 12. Also, the toybox id will not show its output for SuperSU. So, we need to read the settings stored in 
		// "/data/data/eu.chainfire.supersu/shared_prefs/eu.chainfire.supersu_prefences.xml
		
		//#define SUPERSU_CFG ctx->user.data_path "/files/supersu.cfg"
		// for some unknown reason this file is unable to open. just prompt to SuperSU and it will give the request/result response in the ctx->user.data_path/requests
		/*
		// WK,disabled on 28/02/2023: this method will read only the half of data stored in file
		data = read_file(supersu_prefences);
	     
		LOGD("data: %s", data);
		*/
		/*if (data == NULL) {
			LOGE("supersu_prefences");
			data = malloc(4096);
			FILE *fp = fopen(supersu_prefences, "r");
			if (fp == NULL) {
				PLOGE("fopen()");
			} else {
				while(!feof(fp)) {
					fgets(data, 4096, fp);
					LOGD("%s", data);
				}
			}
		}*/
		/*
		char buffer[4096];
		int supersu_prefencesfd[2];
		pipe(supersu_prefencesfd);
		
		char command[ARG_MAX];
	    snprintf(command, sizeof(command), "/system/bin/cat %s", supersu_prefences);
	    char *args[] = { "sh", "-c", command, NULL, };
           
		
		//if (data == NULL)  {
			if (fork_zero_fucks() == 0) {
			 
			if (-1 == dup2(supersu_prefencesfd[1], STDOUT_FILENO)) {
                PLOGE("dup2 child outfd");
                exit(-1);
            }
			close(supersu_prefencesfd[0]);
			close(supersu_prefencesfd[1]);
			execv(_PATH_BSHELL, args);
             PLOGE("exec cat");
            _exit(EXIT_FAILURE);
		} else {
			close(supersu_prefencesfd[1]);
			int len = read(supersu_prefencesfd[0], buffer, 4096);
			LOGD("len: %d", len);
			if (len > 0) {
				data = buffer;
			} else {
				PLOGE("read(supersu_prefencesfd)");
			}
			//wait(NULL);
			//data = read_file(supersu_cfg);
		}*/
		//}
		//if (data != NULL) {
		char *mns_mnt = NULL; 
	    char *multiuser_mode = NULL;
	    char *root_access = NULL;
		//LOGD("root_access: %s", root_access);
	    char *config_notify = NULL;
		char *config_log = NULL;
		char *config_access = NULL;
		char *value = NULL;
		
			//get_property(multiuser_mode, pref_multiuser_mode, "value", "-1");
	        
			//pref_multiuser_mode[7] = '\0';
			//LOGD("pref_multiuser_mode: %s", pref_multiuser_mode);
			
			/*if (strstr(pref_multiuser_mode, "true") != NULL) {
		        ctx->user.owner_mode = 0;
	        }*/
			
			
			//get_property(root_access, pref_root, "value", "3");
			
			//ctx->from.pref_root = atoi(pref_root);
			/*get_property(mns_mnt, pref_mount_namespace_separation, "value", "1");
	        
			pref_mount_namespace_separation[7] = '\0';
			
			if (strstr(pref_mount_namespace_separation, "false") != NULL) {
		        ctx->enablemountnamespaceseparation = 0;
	        }*/
			
			
			/*
			get_property(config_notify, notify, "value", "1");
			notify[7] = '\0';
		    if (strstr(notify, "false") != NULL) {
		        ctx->notify = 0;
            }*/
			
			
			  
	char app_config_access[PATH_MAX];
	
	snprintf(app_config_access, sizeof(app_config_access), "config_%s_access", ctx->from.bin);
	/*strcat(app_config_access, ctx->from.bin);
	strcat(app_config_access, "_access");
	*/
	LOGD("app_config_access: %s", app_config_access);
	/*
	int len;
	char buffer[4096];
	while ((len = read(supersu_prefences, buffer, 4096)) > 0) {
		LOGD("buffer %s", buffer);
		if ((caller_bin_access = strstr(buffer, app_config_access)) != NULL) {
			break;
		}
	}*/
	// WK,added on 28/02/2023:
	char buffer[ARG_MAX];
	char buf[ARG_MAX];
	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	//char *caller_bin_access_stored = NULL;
	FILE *fp;
	int last = 0;
	int length = 0;
	int len = 0;
	//int supersu_prefencesfd[2];
	//pipe(supersu_prefencesfd);
	
	if ((fp = fopen(supersu_prefences, "r"))) {
        LOGD("Found file %s", supersu_prefences);
       // if (fork() == 0) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			last = strlen(buffer) - 1;
            if (last >= 0)
        	    buffer[last] = 0;
				data = buffer;
				LOGD("buffer: %s", buffer);
				/*if (strstr(app_config_access, buffer) != NULL) {
					LOGD("breaking");
					break;
				}*/
		 if (mns_mnt == NULL) {
		 if (strstr(data, "config_default_enablemountnamespaceseparation") != NULL) {
		 if ((mns_mnt = strstr(data, "config_default_enablemountnamespaceseparation")) != NULL) {
			 value = strstr(mns_mnt, "value");
			//pref_root[7] = '\0';
			value[13] = '\0';
			
			LOGD("mns_mnt: %s", value);
			
			if (strstr(value, "false") != NULL) {
		        ctx->enablemountnamespaceseparation = 0;
	        }
			value = NULL;
		 }
		 }}
		 
		 if (multiuser_mode == NULL) {
		 if (strstr(data, "config_default_enablemultiuser") != NULL) {
	     if ((multiuser_mode = strstr(data, "config_default_enablemultiuser")) != NULL) {
			 value = strstr(multiuser_mode, "value");
			//pref_root[7] = '\0';
			value[13] = '\0';
			
			LOGD("multiuser_mode: %s", value/*pref_root*/);
			
			if (strstr(value, "true") != NULL) {
		        ctx->user.owner_mode = 0;
	        }
			
			value = NULL;
		 }
		 }}
		 
		 if (root_access == NULL) {
	     if (strstr(data, "superuser") != NULL){
		 if ((root_access = strstr(data, "superuser")) != NULL) {
	         value = strstr(root_access, "value");
			//pref_root[7] = '\0';
			value[13] = '\0';
			
			LOGD("pref_root: %s", value/*pref_root*/);
			if (strstr(value/*pref_root*/, "false") != NULL) {
				ctx->from.pref_root = 0;
			}
			
			value = NULL;
		 }
		 }}
		 
		//LOGD("root_access: %s", root_access);
	     if (config_notify == NULL) {
		 if (strstr(data, "config_default_notify") != NULL){
		 if ((config_notify = strstr(data, "config_default_notify")) != NULL) {
			 value = strstr(config_notify, "value");
			//pref_root[7] = '\0';
			value[13] = '\0';
			
			LOGD("config_notify: %s", value);
			
			if (strstr(value, "false") != NULL) {
		        ctx->notify = 0;
	        }
			value = NULL;
			
		 }
		 }}
		 
		 if (config_log == NULL) {
		 if (strstr(data, "config_default_log") != NULL){
		 //if ((config_log = strstr(data, "config_default_log")) != NULL) {
			 /*value = strchr(config_log, '>');
		     value[8] = '\0';
			*/
			LOGD("config_log: %s", data/*config_log *//*value*/);
			
			//get_property(config_log, pref_full_command_logging, "value", "0");
		    if (strstr(data/*config_log*//*value*/, "content") != NULL) {
				ctx->pref_full_command_logging = 1;
			}
			
			value = NULL;
			
		 //}
		}
	}
		 
		 if (config_access == NULL){
		 if (strstr(data, "config_default_access") != NULL) {
		 if ((config_access = strstr(data, "config_default_access")) != NULL) {
			 value = strchr(config_access, '>');
		    value[6] = '\0';
			LOGD("config_default_access: %s", value);
			
			//get_property(config_access, defaul_access, "value", "-1");
		      if (strstr(value, "grant") != NULL) {
			      ctx->access = ALLOW;
	          } else if (strstr(value, "deny") != NULL) {
			      ctx->access = DENY;
	          }
			  value = NULL;
		 }
			}}
	fclose(fp);
	}
 }}
	} else if (atoi(pref_switch_superuser) == MAGISK) {
		ctx->to.pref_switch_superuser = MAGISK;
		memset(ctx->user.data_path,0, sizeof(ctx->user.data_path));
		snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
        	        ctx->user.userid, "com.topjohnwu.magisk");
			
		snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
	    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
		
		char *magisk_path[] = {"/sbin/magisk", "/sbin/magisk64",  "/sbin/magisk32", "/system/bin/magisk",  "/system/bin/magisk64",  "/system/bin/magisk32", NULL, };
		
		char * magisk = NULL;
	    int i= 0;
	
	    for (i =0; i < 6;i++) {
		     if (access (magisk_path[i], X_OK) == 0) {
			     magisk = magisk_path[i];
				 break;
		     }
	    }
		char buffer[ARG_MAX];
		char command[ARG_MAX];
		snprintf(command, sizeof(command), "%s --sqlite 'SELECT * FROM settings'", magisk);
		char *args [4] = {"sh", "-c", command, NULL,};
        int settingsfd[2];
		int multiuserfd[2];
		int resultfd[2];
		int status;
		struct timeval tv;
        fd_set fds;
        int fd, rc = 1;
		int val;
        int len;
        pipe(settingsfd);
		//pipe(multiuserfd);
		pipe(resultfd);
		
		if (fork_zero_fucks() == 0/*pid == 0*/) {
			if (-1 == dup2(settingsfd[1], STDOUT_FILENO)) {
            PLOGE("dup2 child outfd");
            }
			close(settingsfd[0]);
			close(settingsfd[1]);
			
			execv(_PATH_BSHELL/*magisk*/, args);
			exit(1);
		} else {
			close(settingsfd[1]);
		
			len = read(settingsfd[0], buffer, ARG_MAX);
			if (len < 1 /*!= sizeof(int)*/) {
                LOGE("unable to read int from settingsfd: %d", len);
                      //return INTERACTIVE;
						//exit(-1);
            } else {
			char *data = buffer;
			//memset(allow, 0, ARG_MAX);
			char *root_access = strstr(data, "key=root_access");
			char *multiuser_mode = strstr(data, "key=multiuser_mode");
			char *mnt_ns = strstr(data, "key=mnt_ns");
			
			//LOGD("len: %d root_access: %s multiuser_mode: %s mnt_ns: %s",len, root_access, multiuser_mode, mnt_ns);
			
			if (root_access != NULL) {
				LOGD("len: %d root_access: %s", len, root_access);
				if (strstr(root_access, "1") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_APPS_ONLY;
			} else if (strstr(root_access, "2") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_ADB_ONLY;
			} else if (strstr(root_access, "3") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_APPS_AND_ADB;
			} else
			if (strstr(root_access, "0") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_DISABLED;
			} else if (strstr(root_access, "1") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_APPS_ONLY;
			} else if (strstr(root_access, "2") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_ADB_ONLY;
			} else if (strstr(root_access, "3") != NULL) {
			    ctx->from.pref_root = CM_ROOT_ACCESS_APPS_AND_ADB;
			} 
			}
			
			if (multiuser_mode != NULL) {
			if (strstr(multiuser_mode, "2") != NULL) {
		        ctx->user.owner_mode = 0;
	        } else if (strstr(multiuser_mode, "1") != NULL) {
		      ctx->user.owner_mode = 1;
	        }
			}
			if (mnt_ns != NULL) {
			if (strstr(mnt_ns, "0")) {
			    ctx->enablemountnamespaceseparation = 0;
			}
		   }
			
			close(settingsfd[0]);
		}
		}
		}
					
	
	LOGD("options read.");
	/*
    char mode[12];
    FILE *fp;
    if ((fp = fopen(REQUESTOR_OPTIONS, "r"))) {
        fgets(mode, sizeof(mode), fp);
        if (strcmp(mode, "user\n") == 0) {
            ctx->user.owner_mode = 0;
        } else if (strcmp(mode, "owner\n") == 0) {
            ctx->user.owner_mode = 1;
        }
    }*/
}

static void user_init(struct su_context *ctx)
{
	        
			if (ctx->to.pref_switch_superuser == SUPERPOWER) {
			    if (ctx->is_premium == 1) {
				snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
                                ctx->user.userid, REQUESTOR_PREMIUM);
			     } else {
        	                snprintf(ctx->user.data_path, PATH_MAX, "/data/data/%s",
        	                REQUESTOR);
			    }
			    snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
			    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} else if (ctx->to.pref_switch_superuser == SUPERSU) {
        	            snprintf(ctx->user.data_path, PATH_MAX, "/data/data/%s",
        	            "eu.chainfire.supersu");
			    snprintf(ctx->user.logs_path, PATH_MAX, "%s/logs", ctx->user.data_path);
			    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} else if (ctx->to.pref_switch_superuser == MAGISK) {
        	            snprintf(ctx->user.data_path, PATH_MAX, "/data/data/%s",
        	            "com.topjohnwu.magisk");
			    snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
			    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} 
		
	
    if (ctx->from.uid > 99999) {
    	ctx->user.userid = ctx->from.uid / 100000;
    	if (!ctx->user.owner_mode) {
			if (ctx->to.pref_switch_superuser == SUPERPOWER) {
			    if (ctx->is_premium == 1) {
				snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
                                ctx->user.userid, REQUESTOR_PREMIUM);
			     } else {
        	               snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
        	               ctx->user.userid, REQUESTOR);
			     }
			     snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
			     LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} else if (ctx->to.pref_switch_superuser == SUPERSU) {
        	            snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
        	            ctx->user.userid, "eu.chainfire.supersu");
			    snprintf(ctx->user.logs_path, PATH_MAX, "%s/logs", ctx->user.data_path);
			    LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} else if (ctx->to.pref_switch_superuser == MAGISK) {
        	           snprintf(ctx->user.data_path, PATH_MAX, "/data/user/%d/%s",
        	           ctx->user.userid,  "com.topjohnwu.magisk");
			   snprintf(ctx->user.logs_path, PATH_MAX, "%s/files/logs", ctx->user.data_path);
			   LOGD("ctx->user.logs_path: %s", ctx->user.logs_path );	
			} 
				
		if (ctx->is_premium == 1)  {
		    snprintf(ctx->user.store_path, PATH_MAX, "/data/user/%d/%s/files/stored",
    	            ctx->user.userid, REQUESTOR_PREMIUM);
        	    snprintf(ctx->user.store_default, PATH_MAX, "/data/user/%d/%s/files/stored/default",
        	    ctx->user.userid, REQUESTOR_PREMIUM);
		} else {	
    	           snprintf(ctx->user.store_path, PATH_MAX, "/data/user/%d/%s/files/stored",
    	           ctx->user.userid, REQUESTOR);
        	   snprintf(ctx->user.store_default, PATH_MAX, "/data/user/%d/%s/files/stored/default",
        	   ctx->user.userid, REQUESTOR);
		}
    	} 
    }
	
	if (ctx->to.pref_switch_superuser == SUPERSU) {
	    if (access("/data/user_de", F_OK) == 0) {
	        snprintf(ctx->user.logs_path, PATH_MAX, "/data/user_de/%d/eu.chainfire.supersu/logs", ctx->user.userid);
	    }
	}
}

static void populate_environment(const struct su_context *ctx)
{
    struct passwd *pw;

    if (ctx->to.keepenv)
        return;

    pw = getpwuid(ctx->to.uid);
    if (pw) {
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", ctx->to.shell, 1);
        //if (ctx->to.login || ctx->to.uid) {
            setenv("USER", pw->pw_name, 1);
            setenv("LOGNAME", pw->pw_name, 1);
       // }
    }
}

void set_identity(unsigned int uid)
{
    /*
     * Set effective uid back to root, otherwise setres[ug]id will fail
     * if uid isn't root.
     */
    /*if (seteuid(0)) {
        //PLOGE("seteuid (root)");
        //exit(EXIT_FAILURE);
    }*/
    if (setresgid(uid, uid, uid)) {
        //PLOGE("setresgid (%u)", uid);
        //exit(EXIT_FAILURE);
    }
    if (setresuid(uid, uid, uid)) {
        //PLOGE("setresuid (%u)", uid);
        //exit(EXIT_FAILURE);
    }
}

/*
 * For use in signal handlers/atexit-function
 * NOTE: su_ctx points to main's local variable.
 *       It's OK due to the program uses exit(3), not return from main()
 */
static struct su_context *su_ctx = NULL;

					\

static void usage(int status) {
    FILE *stream = (status == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(stream,
	"2016-2024 - WK\n"
    "Usage: su [options] [--] [-] [LOGIN] [--] [args...]\n\n"
    "Options:\n"
	"--auto-daemon, --daemon start the su daemon\n"
    "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
    "  -h, --help                    display this help message and exit\n"
    "  -, -l, --login                pretend the shell to be a login shell\n"
    "  -M, -mm, --mount-master          do not apply separation of mount namespace\n"
	"  -m, -p,\n"
    "  --preserve-environment        do not change environment variables\n"
    "  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n"
    "  -v, --version                 display version number and exit\n"
    "  -V                            display version code and exit\n\n"
	"Usage#2: su LOGIN COMMAND ARGS...\n");
	exit(status);
}

static __attribute__ ((noreturn)) void deny(struct su_context *ctx) {
    char *cmd = get_command(&ctx->to);
    //if (ctx->from.uid!= AID_ROOT) {
    int log_fd = -1;
	
	time_t t;
	time(&t);
	
	struct timeval tm;
	gettimeofday(&tm, NULL);
	unsigned int s1 = (unsigned int)(tm.tv_sec) /** 1000*/;
	unsigned int s2 = (tm.tv_sec / 1000);
	
	// WK: moved to here on 01/03/2023
	if (ctx->to.pref_switch_superuser == SUPERPOWER || ctx->to.pref_switch_superuser == MAGISK) {
	    snprintf(ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", ctx->user.logs_path, ctx->from.uid, ctx->from.bin, ctx->to.uid, getpid() );
	} else if (ctx->to.pref_switch_superuser == SUPERSU) {
		   // WK, added on 26/02/2023: support SuperSU's logging
		if (/*allow*/ctx->access == ALLOW) {
			char granted[PATH_MAX];
			snprintf(granted/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.", ctx->user.logs_path, s1);
		    memset(ctx->to.log_path , 0, sizeof(ctx->to.log_path ));
			strcat(granted, ctx->from.bin);
			//result = granted;
			//result += (su_ctx->from.bin)//su_ctx->from.bin;
			strncpy(ctx->to.log_path, granted, sizeof(ctx->to.log_path ));
		    //snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.%s", su_ctx->user.logs_path, s1, su_ctx->from.bin);
		} else if (/*allow*/ctx->access == DENY)  {
			char denied[PATH_MAX];
			snprintf(denied/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.", su_ctx->user.logs_path, s1);
		    memset(su_ctx->to.log_path , 0, sizeof(su_ctx->to.log_path ));
			strcat(denied, ctx->from.bin);
			//result = denied;
			//result+= sizeof(su_ctx->from.bin);
			strncpy(su_ctx->to.log_path, denied, sizeof(su_ctx->to.log_path ));
			//snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.%s", su_ctx->user.logs_path, s1, ctx.from.bin);
	   }
	  }
	
		switch (ctx->notify) {
			case 0: break;
		    case 1:
				 default:
			     switch(ctx->from.uid) {
				   case AID_ROOT:
				   break;
				   default:
		            send_intent(ctx, DENY, (ctx->is_premium == 1) ? ACTION_RESULT_PREMIUM : ACTION_RESULT);
			    }
	  }
	 if (ctx->to.pref_switch_superuser == SUPERSU) {
	     log_fd = open(ctx->to.log_path, O_CREAT | O_RDWR, 0666);
     if (log_fd < 0) {
         PLOGE("Opening log_fd");
       // return -1;
     }
	 chmod(ctx->to.log_path, 0666);
    }
	LOGW("request rejected (%u->%u %s)", ctx->from.uid, ctx->to.uid, cmd);
    fprintf(stderr, "%s\n", strerror(EACCES));
    exit(EXIT_FAILURE);
}

// WK, added on 02/11/2022: support mount namespace:
// Missing system call wrappers

int setns(int fd, int nstype) {
    return syscall(__NR_setns, fd, nstype);
}

int unshare(int flags) {
    return syscall(__NR_unshare, flags);
}

/*static*/ void switch_mnt_ns(int pid) {
    char mnt[PATH_MAX];
	if (su_ctx && su_ctx->enablemountnamespaceseparation == 0) {
		return;
	} else {
        snprintf(mnt, sizeof(mnt), "/proc/%d/ns/mnt", pid);
	}
	//} else {
	 // WK added on 07/03/2023: if the daemon is started from SuperPower or Terminal Emulator, it will inherit the mount namespace of SuperPower or Terminal Emulator (even if we kill and start the daemon) when using --mount-master, breaking file managers apps which expect the whole view of files(/data/data/*).
     // to fix this unexpected behavior without rebooting the phone, we need to switch to init's mount namespace.
	 //snprintf(mnt, sizeof(mnt), "/proc/1/ns/mnt");
    //}
	
	LOGD("mnt_ns: %s", mnt);

    int fd, ret;
    fd = open(mnt, O_RDONLY);
    if (fd < 0) {//return 1;
	PLOGE("open()");
        // Create a second private mount namespace for our process
        if (unshare(CLONE_NEWNS) < 0) {
            PLOGE("unshare");
            return;
        }

        if (mount(NULL/*"rootfs"*/, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
            PLOGE("mount rootfs as slave");
            return;
        }
    } else {
       // Switch to its namespace
       ret = setns(fd, 0);
       if (ret < 0) {   
	   PLOGE("setns(): %d", ret);
	}
        close(fd);
    }
    //return ret;
}

// WK: added on 23/10/2022:
static __attribute__ ((noreturn)) void allow(struct su_context *ctx) {
    char *arg0;
    int argc, err;
    char * const* envp = environ;
	int log_fd = -1;
	
    umask(ctx->umask);
	
	time_t t;
	time(&t);
	
	struct timeval tm;
	gettimeofday(&tm, NULL);
	unsigned int s1 = (unsigned int)(tm.tv_sec) /** 1000*/;
	unsigned int s2 = (tm.tv_sec / 1000);
	
	// WK: moved to here on 01/03/2023
	if (su_ctx->to.pref_switch_superuser == SUPERPOWER || su_ctx->to.pref_switch_superuser == MAGISK) {
	    snprintf(su_ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", su_ctx->user.logs_path, su_ctx->from.uid, su_ctx->from.bin, su_ctx->to.uid, getpid() );
	} else if (su_ctx->to.pref_switch_superuser == SUPERSU) {
		   // WK, added on 26/02/2023: support SuperSU's logging
		if (/*allow*/ctx->access == ALLOW) {
			char granted[PATH_MAX];
			snprintf(granted/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.", ctx->user.logs_path, s1);
		    memset(su_ctx->to.log_path , 0, sizeof(su_ctx->to.log_path ));
			strcat(granted, su_ctx->from.bin);
			//result = granted;
			//result += (su_ctx->from.bin)//su_ctx->from.bin;
			strncpy(su_ctx->to.log_path, granted, sizeof(su_ctx->to.log_path ));
		    //snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.%s", su_ctx->user.logs_path, s1, su_ctx->from.bin);
		} else if (/*allow*/ctx->access == DENY)  {
			char denied[PATH_MAX];
			snprintf(denied/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.", su_ctx->user.logs_path, s1);
		    memset(su_ctx->to.log_path , 0, sizeof(su_ctx->to.log_path ));
			strcat(denied, ctx->from.bin);
			//result = denied;
			//result+= sizeof(su_ctx->from.bin);
			strncpy(su_ctx->to.log_path, denied, sizeof(su_ctx->to.log_path ));
			//snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.%s", su_ctx->user.logs_path, s1, ctx.from.bin);
	   }
	  }
	  
	switch (ctx->notify) {
		case 0: break;
		case 1:
		default:
		   switch(ctx->from.uid) {
			  case AID_ROOT:
			       break;
			       default:
		                  send_intent(ctx, ALLOW, (ctx->is_premium == 1) ? ACTION_RESULT_PREMIUM :  ACTION_RESULT);
		 }
	  }
   /* if ((ctx->from.uid != AID_ROOT) || (strcmp(ctx->from.bin, REQUESTOR) != 0) ) {
        send_intent(ctx, ALLOW, ACTION_RESULT);
    }*/
	
    arg0 = strrchr (ctx->to.shell, '/');
    arg0 = (arg0) ? arg0 + 1 : ctx->to.shell;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);

        if (!p)
            exit(EXIT_FAILURE);

        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

    if (ctx->from.envp[0]) {
        envp = ctx->from.envp;
    }
	
    log_fd = open(ctx->to.log_path, O_CREAT | O_RDWR, 0666);
    if (log_fd < 0) {
        PLOGE("Opening log_fd");
       // return -1;
    }
    chmod(ctx->to.log_path, 0666);

#define PARG(arg)									\
    (ctx->to.optind + (arg) < ctx->to.argc) ? " " : "",					\
    (ctx->to.optind + (arg) < ctx->to.argc) ? ctx->to.argv[ctx->to.optind + (arg)] : ""

    LOGD("%u %s executing %u %s using shell %s : %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            ctx->from.uid, ctx->from.bin,
            ctx->to.uid, get_command(&ctx->to), ctx->to.shell,
            arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
            (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");

    argc = ctx->to.optind;
    if (ctx->to.command) {
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
    } /*else {
		ctx->to.argv[--argc] = "-";
	}*/
	
    ctx->to.argv[--argc] = arg0;
   int pid = fork();
    if (!pid) {
	//if (ctx->enablemountnamespaceseparation) {
	switch_mnt_ns(ctx->from.pid);
	//}
	populate_environment(ctx);
	set_identity(ctx->to.uid);
		
	execv(ctx->to.shell, ctx->to.argv + argc/*, envp*/);
    err = errno;
    //PLOGE("exec");
    fprintf(stderr, "Cannot execute %s: %s\n", ctx->to.shell, strerror(err));
    exit(EXIT_FAILURE);
    } else {
	int status, code;

        //LOGD("Waiting for pid %d.", pid);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
			LOGD("Process terminated with status WEXITSTATUS[%d] and code[%d].", WEXITSTATUS(status), code);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
			LOGD("Process terminated with signal status WTERMSIG[%d] and code[%d].", WTERMSIG(status), code);
        } else {
            code = -1;
        }
        exit(code);
    }
}


// WK: added on 21/01/2024:
static void multiplexing(int infd, int outfd, int errfd, int log_fd)
{
    struct timeval tv;
    fd_set fds;
    int rin;
    int rout;
    int rerr;
    
    tv.tv_sec = 0;
    tv.tv_usec = 0;
	
	ssize_t inlen;
        ssize_t outlen;
	ssize_t errlen;
	int written;
	
	char input[ARG_MAX];
	char output[ARG_MAX];
	char err[ARG_MAX];

        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
	FD_SET(outfd, &fds);
	FD_SET(errfd, &fds);
   
	while (1) {
			
	  FD_ZERO(&fds);
          FD_SET(STDIN_FILENO, &fds);

	  rin = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
		
	  if (rin >= 1) {
	      LOGD("select(STDIN_FILENO) returned: %d", rin);
	      memset(input, 0, sizeof(input));
		        
	     if ((inlen = read(STDIN_FILENO, input, 4096)) > 0) {
		  input[inlen] = '\0';
		  LOGD("input:%s", input);
	          written =  write(infd, input, inlen);
	          LOGD("written to infd %d", written);
		  write(log_fd, input, inlen);
	     } else {
		 LOGW("There is no data available on read(STDIN_FILENO) (Ctrl+D was sent! Terminating program)!");
		 // WK, on 05/07/2024: C^D (control + D) signal was sent to us. Close "infd" to cause the child process to exit 
                 // so we can continue and retrieve the exit code and give the Terminal's control back to the user.
		 close(infd);
		 break;
	     }
	  } 
		
	  FD_ZERO(&fds);
	  FD_SET(outfd, &fds);

 	  rout = select(outfd + 1, &fds, NULL, NULL, &tv);
  	 
	  if (rout >= 1) {
	     LOGD("select(outfd) returned: %d", rout);
	     memset(output, 0, sizeof(output));
			
             if ((outlen = read(outfd, output, 4096)) > 0) {
	          output[outlen] = '\0';
		  written = write(STDOUT_FILENO, output, outlen);
	          LOGD(" written to STDOUT_FILENO: %d", written);

                  write(log_fd, "{", strlen("{"));
                  write(log_fd, output, outlen); 
		  write(log_fd, "\n", strlen("\n"));
                  write(log_fd, "}", strlen("}"));
                  write(log_fd, "\n", strlen("\n"));
		  // WK: added on 24/01/2024: this fixes the "exit" command issue:
		  continue;				
              } else {
		  LOGW("There is no data available on read(outfd)!");
	      }
	  } 
		
	  FD_ZERO(&fds);
          FD_SET(errfd, &fds);
		
	  rerr = select(errfd + 1, &fds, NULL, NULL, &tv); 
		
	  if (rerr >= 1) {
	      LOGD("select(errfd) returned: %d", rerr);
		        
	      memset(err, 0, sizeof(err));
		        
	      if ((errlen = read(errfd, err, 4096)) > 0) {
		    err[errlen] = '\0';
		    LOGD("error:%s", err);
		    written = write(STDERR_FILENO, err, errlen);
		    LOGD("written to STDERR_FILENO: %d", written);

                    write(log_fd, "!", strlen("!"));
		    write(log_fd, err, errlen);
                    write(log_fd, "\n", strlen("\n"));
                    write(log_fd, "!", strlen("!"));
		    write(log_fd, "\n", strlen("\n"));
	  	    // WK: added on 24/01/2024: this fixes the "exit" command issue:
		    continue;
	     } else {
		 LOGW("There is no data available on read(errfd): [%d]! The 'exit/kill' command was called! Calling 'break' so we go out of the 'while' loop and do not get stuck into the prompt command line!", errlen);
		 // WK: added on 24/01/2024: this fixes the "exit" command issue: if there is no data on STDIN_FILENO, break out of the loop so the process continue its normal flow and call waitpid().
		 break;
	     }
	  }
    }
}

static __attribute__ ((noreturn)) void select_allow(struct su_context *ctx) {
    char *arg0;
    int argc, err;
    char * const* envp = environ;
	int log_fd = -1;
	
    umask(ctx->umask);
	
	time_t t;
	time(&t);
	
	struct timeval tm;
	gettimeofday(&tm, NULL);
	unsigned int s1 = (unsigned int)(tm.tv_sec) /** 1000*/;
	unsigned int s2 = (tm.tv_sec / 1000);
	
	// WK: moved to here on 01/03/2023
	if (su_ctx->to.pref_switch_superuser == SUPERPOWER || su_ctx->to.pref_switch_superuser == MAGISK) {
	    snprintf(su_ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", su_ctx->user.logs_path, su_ctx->from.uid, su_ctx->from.bin, su_ctx->to.uid, getpid() );
	} else if (su_ctx->to.pref_switch_superuser == SUPERSU) {
		   // WK, added on 26/02/2023: support SuperSU's logging
		if (/*allow*/ctx->access == ALLOW) {
			char granted[PATH_MAX];
			snprintf(granted/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.", ctx->user.logs_path, s1);
		    memset(su_ctx->to.log_path , 0, sizeof(su_ctx->to.log_path ));
			strcat(granted, su_ctx->from.bin);
			//result = granted;
			//result += (su_ctx->from.bin)//su_ctx->from.bin;
			strncpy(su_ctx->to.log_path, granted, sizeof(su_ctx->to.log_path ));
		    //snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.%s", su_ctx->user.logs_path, s1, su_ctx->from.bin);
		} else if (/*allow*/ctx->access == DENY)  {
			char denied[PATH_MAX];
			snprintf(denied/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.", su_ctx->user.logs_path, s1);
		    memset(su_ctx->to.log_path , 0, sizeof(su_ctx->to.log_path ));
			strcat(denied, ctx->from.bin);
			//result = denied;
			//result+= sizeof(su_ctx->from.bin);
			strncpy(su_ctx->to.log_path, denied, sizeof(su_ctx->to.log_path ));
			//snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.%s", su_ctx->user.logs_path, s1, ctx.from.bin);
	   }
	  }
	  
	switch (ctx->notify) {
			case 0: break;
		    case 1:
				 default:
			     switch(ctx->from.uid) {
				   case AID_ROOT:
				   break;
				   default:
		            send_intent(ctx, ALLOW, (ctx->is_premium == 1) ? ACTION_RESULT_PREMIUM :   ACTION_RESULT);
			    }
	  }
   /* if ((ctx->from.uid != AID_ROOT) || (strcmp(ctx->from.bin, REQUESTOR) != 0) ) {
        send_intent(ctx, ALLOW, ACTION_RESULT);
    }*/
	
    arg0 = strrchr (ctx->to.shell, '/');
    arg0 = (arg0) ? arg0 + 1 : ctx->to.shell;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);

        if (!p)
            exit(EXIT_FAILURE);

        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

    if (ctx->from.envp[0]) {
        envp = ctx->from.envp;
    }
	
    log_fd = open(ctx->to.log_path, O_CREAT | O_APPEND | O_RDWR, 0666);
    if (log_fd < 0) {
        PLOGE("Opening log_fd");
       // return -1;
    }
    chmod(ctx->to.log_path, 0666);

#define PARG(arg)									\
    (ctx->to.optind + (arg) < ctx->to.argc) ? " " : "",					\
    (ctx->to.optind + (arg) < ctx->to.argc) ? ctx->to.argv[ctx->to.optind + (arg)] : ""

    LOGD("%u %s executing %u %s using shell %s : %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            ctx->from.uid, ctx->from.bin,
            ctx->to.uid, get_command(&ctx->to), ctx->to.shell,
            arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
            (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");

    argc = ctx->to.optind;
    if (ctx->to.command) {
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
    } /*else {
		ctx->to.argv[--argc] = "-";
	}*/
	
    ctx->to.argv[--argc] = arg0;
	
	int infd[2];
	int outfd[2];
	int errfd[2];
	
	pipe(infd);
	pipe(outfd);
	pipe(errfd);

   int pid = fork();
    if (!pid) {
		//if (ctx->enablemountnamespaceseparation) {
	    switch_mnt_ns(ctx->from.pid);
		//}
	    populate_environment(ctx);
	    set_identity(ctx->to.uid);
		
	    if (-1 == dup2(infd[0], STDIN_FILENO)) {
		// PLOGE("dup2 child infd");
		exit(-1);
            }
		
	    if (-1 == dup2(outfd[1], STDOUT_FILENO)) {
               // PLOGE("dup2 child outfd");
               exit(-1);
	    }
		
	    if (-1 == dup2(errfd[1], STDERR_FILENO)) {
                //PLOGE("dup2 child errfd");
                exit(-1);
            }
		
	    close(infd[0]);
	    close(infd[1]);
	    close(outfd[0]);
	    close(outfd[1]);
	    close(errfd[0]);
	    close(errfd[1]);
	execv(ctx->to.shell, ctx->to.argv + argc/*, envp*/);
   
	err = errno;
    //PLOGE("exec");
    fprintf(stderr, "Cannot execute %s: %s\n", ctx->to.shell, strerror(err));
    exit(EXIT_FAILURE);
	}
	else {
	    int status, code;
                close(infd[0]);
		close(outfd[1]);
		close(errfd[1]);
		multiplexing(infd[1], outfd[0], errfd[0], log_fd);
        
		LOGD("Waiting for pid %d.", pid);
        waitpid(pid, &status, 0);

	if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
			LOGD("Process terminated with status WEXITSTATUS[%d] and code[%d].", WEXITSTATUS(status), code);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
			LOGD("Process terminated with signal status WTERMSIG[%d] and code[%d].", WTERMSIG(status), code);
        } else {
            code = -1;
        }
        close(infd[1]);
        close(outfd[0]);
        close(errfd[0]);
        close(log_fd);
		
        exit(code);
    }
}

static __attribute__ ((noreturn)) void terminal_allow(struct su_context *ctx){
    char *arg0;
    int argc, err;
    
	int log_fd = -1;
	char * const* envp = environ;
	
	
    umask(ctx->umask);
	
	time_t t;
	time(&t);
	
	struct timeval tm;
	gettimeofday(&tm, NULL);
unsigned 	int s1 = (unsigned int)(tm.tv_sec) /** 1000*/;
	unsigned int s2 = (tm.tv_sec / 1000);
	// WK: moved to here on 01/03/2023
	if (ctx->to.pref_switch_superuser == SUPERPOWER || ctx->to.pref_switch_superuser == MAGISK) {
	    snprintf(ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", ctx->user.logs_path, ctx->from.uid, ctx->from.bin, ctx->to.uid, getpid() );
	} else if (ctx->to.pref_switch_superuser == SUPERSU) {
		   // WK, added on 26/02/2023: support SuperSU's logging
		if (/*allow*/ctx->access == ALLOW) {
			char granted[PATH_MAX];
			snprintf(granted/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.", ctx->user.logs_path, s1);
		    memset(ctx->to.log_path , 0, sizeof(ctx->to.log_path ));
			strcat(granted, ctx->from.bin);
			//result = granted;
			//result += (su_ctx->from.bin)//su_ctx->from.bin;
			strncpy(ctx->to.log_path, granted, sizeof(ctx->to.log_path ));
		    //snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.%s", su_ctx->user.logs_path, s1, su_ctx->from.bin);
		} else if (/*allow*/ctx->access == DENY)  {
			char denied[PATH_MAX];
			snprintf(denied/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.", ctx->user.logs_path, s1);
		    memset(ctx->to.log_path , 0, sizeof(ctx->to.log_path ));
			strcat(denied, ctx->from.bin);
			//result = denied;
			//result+= sizeof(su_ctx->from.bin);
			strncpy(ctx->to.log_path, denied, sizeof(ctx->to.log_path ));
			//snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.%s", su_ctx->user.logs_path, s1, ctx.from.bin);
	   }
	  }
	
	switch (ctx->notify) {
			case 0: break;
		    case 1:
				 default:
			     switch(ctx->from.uid) {
				   case AID_ROOT:
				   break;
				   default:
		            send_intent(ctx, ALLOW, (ctx->is_premium == 1) ? ACTION_RESULT_PREMIUM : ACTION_RESULT);
			    }
	  }
	/*if (ctx->from.uid!= AID_ROOT) {
        send_intent(ctx, ALLOW, ACTION_RESULT);
    }*/

    arg0 = strrchr (ctx->to.shell, '/');
    arg0 = (arg0) ? arg0 + 1 : ctx->to.shell;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);

        if (!p)
            exit(EXIT_FAILURE);

        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

	if (ctx->from.envp[0]) {
            envp = ctx->from.envp;
        }
	
	log_fd = open(ctx->to.log_path, O_CREAT | O_APPEND |  O_RDWR, 0666);
    if (log_fd < 0) {
        PLOGE("Opening log_fd");
       // return -1;
    }
    chmod(ctx->to.log_path, 0666);

#define PARG(arg)									\
    (ctx->to.optind + (arg) < ctx->to.argc) ? " " : "",					\
    (ctx->to.optind + (arg) < ctx->to.argc) ? ctx->to.argv[ctx->to.optind + (arg)] : ""

    LOGD("%u %s executing %u %s using shell %s : %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            ctx->from.uid, ctx->from.bin,
            ctx->to.uid, get_command(&ctx->to), ctx->to.shell,
            arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
            (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");


    size_t cmd_size;
    char *cmd;
    argc = ctx->to.optind;
	
    if (ctx->to.command) {
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
		cmd = get_command(&ctx->to);
        cmd_size = strlen(cmd) + 1;
		cmd[cmd_size] = '\n';
		write(log_fd, cmd, cmd_size/*strlen(ctx->to.command +1)*/);
		write(log_fd, "\n", 2);
		//write(log_fd, ctx->to.command, strlen(ctx->to.command) + 1);
    } /*else {
		ctx->to.argv[--argc] = "-";
	}*/
    ctx->to.argv[--argc] = arg0;
    
	
	int infd;
	int outfd;
	int errfd;
	int ptmx = -1;
        char pts_slave[PATH_MAX];
	int ptsfd;

	ptmx = pts_open(pts_slave, sizeof(pts_slave));
    if (ptmx < 0) {
        PLOGE("pts_open");
        exit(-1);
    }
	
	int pid = fork();
    if (!pid) {
	switch_mnt_ns(ctx->from.pid);
	populate_environment(ctx);
        set_identity(ctx->to.uid);
		
	setsid();
	//if (pts_slave[0]) {
        // Opening the TTY has to occur after the
        // fork() and setsid() so that it becomes
        // our controlling TTY and not the daemon's
        ptsfd = open(pts_slave, O_RDWR);
        if (ptsfd == -1) {
            //PLOGE("open(pts_slave) daemon");
            exit(-1);
        }

        struct stat st;
        if (fstat(ptsfd, &st)) {
            //PLOGE("failed to stat pts_slave");
            exit(-1);
        }
        /*
        if (st.st_uid != credentials.uid) {
            PLOGE("caller doesn't own proposed PTY");
            exit(-1);
        }*/

        if (!S_ISCHR(st.st_mode)) {
            //PLOGE("proposed PTY isn't a chardev");
            exit(-1);
        }

        //if (infd < 0)  {
            //LOGD("daemon: stdin using PTY");
            infd  = ptsfd;
        //}
        //if (outfd < 0) {
            //LOGD("daemon: stdout using PTY");
            outfd = ptsfd;
       // }
        //if (errfd < 0) {
            //LOGD("daemon: stderr using PTY");
            errfd = ptsfd;
        //}
    //} else {
        // TODO: Check system property, if PTYs are disabled,
        // made infd the CTTY using:
        // ioctl(infd, TIOCSCTTY, 1);
    //}
   // free(pts_slave);
		
		
	if (-1 == dup2(infd, STDIN_FILENO)) {
            PLOGE("dup2 child infd");
            exit(-1);
        }
	if (-1 == dup2(outfd, STDOUT_FILENO)) {
            PLOGE("dup2 child outfd");
            exit(-1);
        }
	if (-1 == dup2(errfd, STDERR_FILENO)) {
            PLOGE("dup2 child errfd");
            exit(-1);
        }

		close(infd);
		close(outfd);
		close(errfd);
		
		//set_stdin_raw();
		
	    execv(ctx->to.shell, ctx->to.argv + argc/*, envp*/);
        err = errno;
        PLOGE("exec");
        fprintf(stderr, "Cannot execute %s: %s\n", ctx->to.shell, strerror(err));
        exit(EXIT_FAILURE);
	 } else {
		
		 memset(input, 0, 4096);
		 memset(output, 0, 4096);
		 memset(error, 0, 4096);
		 input[sizeof(input)-1] = '\0';
		
		 watch_sigwinch_async(STDOUT_FILENO, ptmx);
		//setup_sighandlers();
        pump_stdin_async(ptmx, -1 /*log_fd*/);
        pump_stdout_blocking(ptmx, log_fd);
        int status, code;

        LOGD("Waiting for pid %d.", pid);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
			LOGD("Process terminated with status WEXITSTATUS[%d] and code[%d].", WEXITSTATUS(status), code);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
			LOGD("Process terminated with signal status WTERMSIG[%d] and code[%d].", WTERMSIG(status), code);
        } else {
            code = -1;
        }
        close(ptmx);
        close(log_fd);
        exit(code);
    }
}

// WK: added on 23/10/2022:
static __attribute__ ((noreturn)) void fork_allow(struct su_context *ctx) {
    char *arg0;
    int argc, err;
    char input[4096];
	char output[4096];
	char error[4096];
	int log_fd = -1;
	int inlen = 0;
	int outlen = 0;
	int errlen = 0;
	char * const* envp = environ;
	pid_t inpid = 0;
	pid_t outpid = 0;
	pid_t errpid = 0;
	
    umask(ctx->umask);
	
	time_t t;
	time(&t);
	
	struct timeval tm;
	gettimeofday(&tm, NULL);
	unsigned int s1 = (unsigned int)(tm.tv_sec) /** 1000*/;
	unsigned int s2 = (tm.tv_sec / 1000);
	
	// WK: moved to here on 01/03/2023
	if (ctx->to.pref_switch_superuser == SUPERPOWER || ctx->to.pref_switch_superuser == MAGISK) {
	    snprintf(ctx->to.log_path, PATH_MAX, "%s/%u.%s-%u.%u", ctx->user.logs_path, ctx->from.uid, ctx->from.bin, ctx->to.uid, getpid() );
	} else if (ctx->to.pref_switch_superuser == SUPERSU) {
		   // WK, added on 26/02/2023: support SuperSU's logging
		if (/*allow*/ctx->access == ALLOW) {
			char granted[PATH_MAX];
			snprintf(granted/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.", ctx->user.logs_path, s1);
		    memset(ctx->to.log_path , 0, sizeof(ctx->to.log_path ));
			strcat(granted, ctx->from.bin);
			//result = granted;
			//result += (su_ctx->from.bin)//su_ctx->from.bin;
			strncpy(ctx->to.log_path, granted, sizeof(ctx->to.log_path ));
		    //snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.GRANTED.%s", su_ctx->user.logs_path, s1, su_ctx->from.bin);
		} else if (/*allow*/ctx->access == DENY)  {
			char denied[PATH_MAX];
			snprintf(denied/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.", ctx->user.logs_path, s1);
		    memset(ctx->to.log_path , 0, sizeof(ctx->to.log_path ));
			strcat(denied, ctx->from.bin);
			//result = denied;
			//result+= sizeof(su_ctx->from.bin);
			strncpy(ctx->to.log_path, denied, sizeof(ctx->to.log_path ));
			//snprintf(su_ctx->to.log_path/*ctx.to.log_path*/, PATH_MAX, "%s/L%u0000.DENIED.%s", su_ctx->user.logs_path, s1, ctx.from.bin);
	   }
	  }
	  
	switch (ctx->notify) {
			case 0: break;
		    case 1:
				 default:
			     switch(ctx->from.uid) {
				   case AID_ROOT:
				   break;
				   default:
		            send_intent(ctx, ALLOW, (ctx->is_premium == 1) ? ACTION_RESULT_PREMIUM : ACTION_RESULT);
			    }
	  }
	
	/*if (ctx->from.uid!= AID_ROOT) {
        send_intent(ctx, ALLOW, ACTION_RESULT);
    }*/

    arg0 = strrchr (ctx->to.shell, '/');
    arg0 = (arg0) ? arg0 + 1 : ctx->to.shell;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);

        if (!p)
            exit(EXIT_FAILURE);

        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

	if (ctx->from.envp[0]) {
        envp = ctx->from.envp;
    }
	
	log_fd = open(ctx->to.log_path, O_CREAT | O_APPEND | O_RDWR, 0666);
    if (log_fd < 0) {
        PLOGE("Opening log_fd");
       // return -1;
    }
    chmod(ctx->to.log_path, 0666);

#define PARG(arg)									\
    (ctx->to.optind + (arg) < ctx->to.argc) ? " " : "",					\
    (ctx->to.optind + (arg) < ctx->to.argc) ? ctx->to.argv[ctx->to.optind + (arg)] : ""

    LOGD("%u %s executing %u %s using shell %s : %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            ctx->from.uid, ctx->from.bin,
            ctx->to.uid, get_command(&ctx->to), ctx->to.shell,
            arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
            (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");


    size_t cmd_size;
    char *cmd;
	
    argc = ctx->to.optind;
    if (ctx->to.command) {
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
		cmd = get_command(&ctx->to);
        cmd_size = strlen(cmd) + 1;
		cmd[cmd_size] = '\n';
		write(log_fd, cmd, cmd_size/*strlen(ctx->to.command +1)*/);
		write(log_fd, "\n", 2);
		//write(log_fd, ctx->to.command, strlen(ctx->to.command) + 1);
    } /*else {
		ctx->to.argv[--argc] = "-";
	}*/
    ctx->to.argv[--argc] = arg0;
    
	// WK: the benefits of using pipes instead of fifos is that we do not need to set permissions on it and open it to perform read/write
	int infd[2];
	int outfd[2];
	int errfd[2];
	pipe(infd);
	pipe(outfd);
	pipe(errfd);
	
	int pid = fork();
        
	if (!pid) {
	
	      switch_mnt_ns(ctx->from.pid);
	      populate_environment(ctx);
	      set_identity(ctx->to.uid);
	if (-1 == dup2(infd[0], STDIN_FILENO)) {
            PLOGE("dup2 child infd");
            exit(-1);
        }
	if (-1 == dup2(outfd[1], STDOUT_FILENO)) {
            PLOGE("dup2 child outfd");
            exit(-1);
        }
	if (-1 == dup2(errfd[1], STDERR_FILENO)) {
            PLOGE("dup2 child errfd");
            exit(-1);
        }
        close(infd[0]); 
	close(infd[1]);
	close(outfd[0]);
	close(outfd[1]);
	close(errfd[0]);
	close(errfd[1]);
		
	execv(ctx->to.shell, ctx->to.argv + argc/*, envp*/);
        err = errno;
        PLOGE("exec");
        fprintf(stderr, "Cannot execute %s: %s\n", ctx->to.shell, strerror(err));
        exit(EXIT_FAILURE);
     } else {
		 
	        close(infd[0]);
		close(outfd[1]);
		close(errfd[1]);
			
		 memset(input, 0, 4096);
		 memset(output, 0, 4096);
		 memset(error, 0, 4096);
		
		// WK, on 25/02/2023: using fork() will cause several ploblems in root apps like SuperSU and Magisk. fall back to using thread instead:
		pump_stdin_async(infd[1], log_fd);
		/*
	       if (fork() == 0) {
		   
		   close(infd[0]);
		   close(outfd[0]);
		   close(outfd[1]);
		   close(errfd[0]);
		   close(errfd[1]);
		 
		while ((inlen = read(STDIN_FILENO,input, 4096)) > 0 ) {
			 if (write(infd[1], input,inlen) == -1) {
				 PLOGE("WRITE()");
				 break;
			 }
			 
			 write(log_fd, input, inlen);
			 // WK, disabled on 25/02/2023: this will break the Magisk due to the Magisk itself has scripts that have the exit command. so that all apps work as expeceted, fall back to using thread intead of fork for STDIN.
			 // WK, on 20/02/2023: prevent blocking on the next read() if the whole data was fully read: this happens on instant exit apps like SuperSU, not on interactive apps like Link2SD:
			 //if (strstr(input, "exit") != NULL) {
				// LOGD("found exit command");
				// break;
		        // kill(pid, SIGKILL);
			//}
		 }
		 LOGD("closing infd[1]");
		 close(infd[1]);
		 exit(0);
	    }*/
	
	// WK: each stream must have its own process so that we have consistent results with the non-FCL mode and act as if we don't had stealing the STDS data and the parent process can continue its work and call waipid().
	if (fork() == 0) {
	        
		close(infd[0]);
		close(infd[1]);
		close(outfd[1]);
		close(errfd[0]);
		close(errfd[1]);
		
               while ((outlen = read(outfd[0],output, 4096)) > 0 ) {
			 write(STDOUT_FILENO, output, outlen);
			 write(log_fd, "{", strlen("{"));
			 write(log_fd, output, outlen);
			 write(log_fd, "\n", strlen("\n"));
			 write(log_fd, "}", strlen("}"));
			 write(log_fd, "\n", strlen("\n"));
		}
		close(outfd[0]);
		/*if (strstr(input, "exit") != NULL) {
		     kill(pid, SIGKILL);
		 }*/
		exit(0);
	}
	
	
	if (fork() == 0) {
		close(infd[0]);
		close(infd[1]);
		close(outfd[0]);
		close(outfd[1]);
		close(errfd[1]);
		
		 while ((errlen = read(errfd[0], error, 4096)) > 0 ) {
			 write(STDERR_FILENO, error, errlen);
			 write(log_fd, "!", strlen("!"));
			 write(log_fd, error, errlen);
			 write(log_fd, "\n", strlen("\n"));
			 write(log_fd, "!", strlen("!"));
			 write(log_fd, "\n", strlen("\n"));
		 }
		 close(errfd[0]);
		 
		 /*if (strstr(input, "exit") != NULL) {
		     kill(pid, SIGKILL);
		 }*/
		 exit(0);
	  }
	
	
	//pump_stdout_blocking(outfd[0], log_fd);
		 
        int status, code;

        LOGD("Waiting for pid %d.", pid);
			
        waitpid(pid, &status, 0);

       if (WIFEXITED(status)) {
            code = WEXITSTATUS(status);
	    LOGD("Process terminated with status WEXITSTATUS[%d] and code[%d].", WEXITSTATUS(status), code);
        } else if (WIFSIGNALED(status)) {
            code = 128 + WTERMSIG(status);
            LOGD("Process terminated with signal status WTERMSIG[%d] and code[%d].", WTERMSIG(status), code);
        } else {
            code = -1;
        }
	close(infd[1]);
	close(outfd[0]);
	close(errfd[0]);
	close(log_fd);
		
        exit(code);
    }
}

/*
 * CyanogenMod-specific behavior
 *
 * we can't simply use the property service, since we aren't launched from init
 * and can't trust the location of the property workspace.
 * Find the properties ourselves.
 */
int access_disabled(const struct su_initiator *from){
    char *data;
    char build_type[PROPERTY_VALUE_MAX];
    char debuggable[PROPERTY_VALUE_MAX], enabled[PROPERTY_VALUE_MAX];
    size_t len;
/*
    data = read_file("/system/build.prop");
    if (check_property(data, "ro.cm.version")) {
        get_property(data, build_type, "ro.build.type", "");
        free(data);

        data = read_file("/default.prop");
        get_property(data, debuggable, "ro.debuggable", "0");
        free(data);
        // only allow su on debuggable builds 
        if (strcmp("1", debuggable) != 0) {
            LOGE("Root access is disabled on non-debug builds");
            return 1;
        }

        data = read_file("/data/property/persist.sys.root_access");
        if (data != NULL) {
            len = strlen(data);
            if (len >= PROPERTY_VALUE_MAX)
                memcpy(enabled, "1", 2);
            else
                memcpy(enabled, data, len + 1);
            free(data);
        } else
            memcpy(enabled, "1", 2);
*/
       
        /* enforce persist.sys.root_access on non-eng builds for apps */
        if (/*strcmp("eng", build_type) != 0 &&*/
                from->uid != AID_SHELL && from->uid != AID_ROOT &&
                (from->pref_root/*atoi(enabled)*/ & CM_ROOT_ACCESS_APPS_ONLY) != CM_ROOT_ACCESS_APPS_ONLY ) {
            //LOGE("Apps root access is disabled by system setting - "
              //   "enable it under settings -> developer options");
            return 1;
        }

        /* disallow su in a shell if appropriate */
        if (from->uid == AID_SHELL &&
                (from->pref_root/*atoi(enabled)*/ & CM_ROOT_ACCESS_ADB_ONLY) != CM_ROOT_ACCESS_ADB_ONLY ) {
            //LOGE("Shell root access is disabled by a system setting - "
               //  "enable it under settings -> developer options");
            return 1;
        }
        
    //}
    return 0;
}

static int get_api_version() {
  char sdk_ver[PROPERTY_VALUE_MAX];
  char *data = read_file("/system/build.prop");
  get_property(data, sdk_ver, "ro.build.version.sdk", "0");
  int ver = atoi(sdk_ver);
  free(data);
  return ver;
}


int main(int argc, char *argv[], char** env) {
    /*if (getuid() != geteuid()) {
        ALOGE("must not be a setuid binary");
        return 1;
    }*/

    return su_main(argc, argv, 1, env);
}

int su_main(int argc, char *argv[], int need_client, char** env) {

	    // Sanitize all secure environment variables (from linker_environ.c in AOSP linker).
    /* The same list than GLibc at this point */
    static const char* const unsec_vars[] = {
        "GCONV_PATH",
        "GETCONF_DIR",
        "HOSTALIASES",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_LIBRARY_PATH",
        "LD_ORIGIN_PATH",
        "LD_PRELOAD",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS",
        "LOCALDOMAIN",
        "LOCPATH",
        "MALLOC_TRACE",
        "MALLOC_CHECK_",
        "NIS_PATH",
        "NLSPATH",
        "RESOLV_HOST_CONF",
        "RES_OPTIONS",
        "TMPDIR",
        "TZDIR",
        "LD_AOUT_LIBRARY_PATH",
        "LD_AOUT_PRELOAD",
        // not listed in linker, used due to system() call
        "IFS",
    };
    const char* const* cp   = unsec_vars;
    const char* const* endp = cp + sizeof(unsec_vars)/sizeof(unsec_vars[0]);
    while (cp < endp) {
        unsetenv(*cp);
        cp++;
    }
	
	
    /*
     * set LD_LIBRARY_PATH if the linker has wiped out it due to we're suid.
     * This occurs on Android 4.0+
	 * WK, on 10/02/2023: On Android 12,  /system/lib64 comes first in the list search so the linker open the correct /system/lib64/lib.so instead of /system/lib/libc.so. this
	 * prevents executable linkage error due to the cpu is arm64-v8a.
     */
    setenv("LD_LIBRARY_PATH", "/system/lib64:/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib", 0);


	 char *supolicy_path[] = { "/sbin/supolicy", "/sbin/supersu/bin/supolicy_wrapped", "/su/bin/supolicy_wrapped", "/system/xbin/supolicy", "/system/bin/supolicy", NULL, };
   
	if (argc == 2 && strcmp(argv[1], "--daemon") == 0 ||  argc == 2 && (strcmp(argv[1], "-ad") == 0) || argc == 2 && (strcmp(argv[1], "--auto-daemon") == 0)) {
        //char *args[] = { "/sbin/supolicy", "/sbin/supersu/bin/supolicy_wrapped", "/su/bin/supolicy_wrapped", "/system/xbin/supolicy", "/system/bin/supolicy", NULL, };
    char * supolicy = NULL;
	int i= 0;
	
	for (i =0; i < 5;i++) {
		  if (access (supolicy_path[i], X_OK) == 0) {
			  supolicy = supolicy_path[i];
			  break;
		  }
	}
    
	/*char *envp[512];
	envp[0] = "LD_LIBRARY_PATH=/system/lib64:/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib";
	envp[1] = NULL;
	char *my_env[] = {"LD_LIBRARY_PATH=/system/lib64:/vendor/lib:/vendor/lib64:/system/lib:/system/lib64:/su/lib:/sbin/supersu/lib", NULL};
    */
	char run_supolicy [ARG_MAX];
	snprintf (run_supolicy, ARG_MAX, "%s --live", supolicy);
	char *command_args[] = { "sh", "-c", run_supolicy, NULL, };

	
	  int  pid = fork ();
	   if (!pid) {
		   execv(_PATH_BSHELL, command_args/*, envp*//*zygote_env*/);
		
		  // execl (supolicy, supolicy, "--live"/*(char*)run_supolicy*/, NULL);
		  exit (1);
		   //execv (supolicy, run_supolicy); //"allow untrusted_app init unix_stream_socket connectto");
		  // execl(supolicy, supolicy, "--live \\'allow untrusted_app init unix_stream_socket connectto\\'", NULL);
	   } else {
        int status, code;

        //LOGD("Waiting for pid %d.", pid);
        waitpid(pid, &status, 0);
        /*if (packageName) {
            appops_finish_op_su(ctx->from.uid, packageName);
        }*/
		code = WEXITSTATUS(status);
        // exit(code/*status*/);
	}
		return run_daemon();
    }
    
	char *arg0 = (char*) basename(argv[0]);
	if (/*argc > 3 && */strncmp(arg0, "supolicy", sizeof("supolicy")) == 0) {
    char *supolicy = NULL;
	char supolicy_args[ARG_MAX];
	int i= 0;
	int s = 1;
	
	for (i =0; i < 5;i++) {
		  if (access(supolicy_path[i], X_OK) == 0) {
			  supolicy = supolicy_path[i];
			  break;
		  }
	}
	
	if (supolicy == NULL) {
		exit(1);
	}
	
	/*for (; s < argc ; s++) {
		 snprintf(supolicy_args, sizeof(supolicy_args), "%s %s", supolicy_args, argv[s]);
	}*/
	
	//char *exec_args[] = { "sh", "-c", supolicy_args, NULL, };
	
    execv(supolicy, argv/*(char**)supolicy_args*/);
	exit(1);
}
    LOGD("su invoked. %s", argv[1]);
	
    struct su_context ctx = {
        .from = {
            .pid = -1,
            .uid = 0,
            .bin = "",
            .args = "",
	    .pref_root = 3,
	    .env = "",
            .envp = { NULL },
        },
        .to = {
            .uid = AID_ROOT,
            .login = 0,
            .keepenv = 0,
            .shell = NULL,
            .command = NULL,
            .argv = argv,
            .argc = argc,
            .optind = 0,
	    .pref_switch_superuser = 1,
 	    .fifo = "",
        },
        .user = {
            .userid = 0,
            .owner_mode = -1,
            .data_path = REQUESTOR_DATA_PATH,
            .store_path = REQUESTOR_STORED_PATH,
            .store_default = REQUESTOR_STORED_DEFAULT,
	    .logs_path = REQUESTOR_LOGS_PATH,
        },
        .child = 0,
	.pref_full_command_logging = 0,
	.notify = 1,
	.access = 2,
	.log_data_and_time_only = 1,
	.enablemountnamespaceseparation = 1,
	.is_premium = 0,
    };
    struct stat st;
    int c, socket_serv_fd, fd;
    char buf[64], *result;
    allow_t dballow;
    struct option long_opts[] = {
        { "command",			required_argument,	NULL, 'c' },
        { "help",			no_argument,		NULL, 'h' },
        { "login",			no_argument,		NULL, 'l' },
        { "mount-master", no_argument,		NULL, 'M' },
		{ "preserve-environment",	no_argument,		NULL, 'p' },
        { "shell",			required_argument,	NULL, 's' },
        { "version",			no_argument,		NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };
	
	if (argc == 2 && strcmp(argv[1], "-mm") == 0) {
		ctx.enablemountnamespaceseparation = 0;
		argv[1] = "-M";
	}
	
    int i = 1;
	char args[ARG_MAX];
		
    while ((c = getopt_long(argc, argv, "+c:hlmMps:Vv", long_opts, NULL)) != -1) {
		switch(c) {
        case 'c':
			//++i;
			//optind++;
			LOGD("optarg %s arg  %s optind: %d", optarg, argv[optind], optind);
			for (; i < argc ;++i) {
			   if (strcmp(argv[i], "-c") == 0 ||  strcmp(argv[i], "--command") == 0) {
				   i++;
			   }
			   snprintf(args, sizeof(args), "%s %s", args, argv[i]);
            }
			LOGD("-c args: %s", args);
			ctx.to.command = args;
			//optind = argc;
            optind = i;
            //ctx.to.command = optarg;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            ctx.to.login = 1;
			optind++;
		    i++;
            break;
			// WK: this is for FlashFire:
		case 'M':
			ctx.enablemountnamespaceseparation = 0;
			optind++;
			i++;
			break;
        case 'm':
        case 'p':
            ctx.to.keepenv = 1;
			optind++;
			i++;
            break;
        case 's':
            ctx.to.shell = optarg;
            break;
        case 'V':
            printf("%d\n", VERSION_CODE);
            exit(EXIT_SUCCESS);
        case 'v':
            printf("%s\n", VERSION);
            exit(EXIT_SUCCESS);
        default:
            /* Bionic getopt_long doesn't terminate its error output by newline */
            fprintf(stderr, "\n");
            usage(2);
        }
		
    }
	
	
	if (optind < argc && !strcmp(argv[optind], "-")) {
        ctx.to.login = 1;
        optind++;
		i++;
    }
	
	if (optind < argc && !strcmp(argv[optind], "-l")) {
        ctx.to.login = 1;
        optind++;
		i++;
    }
	
	if (optind < argc && !strcmp(argv[optind], "--login")) {
        ctx.to.login = 1;
        optind++;
		i++;
    }
	
    /* username or uid */
    if (optind < argc && strcmp(argv[optind], "--")) {
        struct passwd *pw;
        pw = getpwnam(argv[optind]);
        if (!pw) {
            char *endptr;

            /* It seems we shouldn't do this at all */
            errno = 0;
            //ctx.to.uid = atoi(argv[optind]);
			ctx.to.uid = strtoul(argv[optind], &endptr, 10);
            if (errno || *endptr) {
                LOGE("Unknown id: %s\n", argv[optind]);
               // fprintf(stderr, "Unknown id: %s\n", argv[optind]);
                //exit(EXIT_FAILURE);
            } else {
			//ctx.to.uid = atoi(endptr);
			/*optind++;
			i++;*/
			}
        } else {
            ctx.to.uid = pw->pw_uid;
			/*optind++;
			i++;*/
        }
        optind++;
		i++;
    }
	
	if (optind < argc && !strcmp(argv[optind], "-")) {
        ctx.to.login = 1;
        optind++;
		i++;
    }
	
    if (optind < argc && !strcmp(argv[optind], "--")) {
        optind++;
		i++;
    }
	
	// WK: pass the rest of args to the shell:
	if (ctx.to.command == NULL && ctx.to.shell == NULL) {
	    for (; i < argc ; i++) {
			 if (strcmp(argv[i], "-c") == 0 ||  strcmp(argv[i], "--command") == 0) {
				   
				   if (++i == argc) {
					   /* Bionic getopt_long doesn't terminate its error output by newline */
                        fprintf(stderr, "\n");
                        usage(2);
				   }
		     }
			 snprintf(args, sizeof(args), "%s %s", args, argv[i]);
			 optind++;
        }
    }
     LOGD("argc: %d optind: %d args: %s",argc, optind, args);
	 if (ctx.to.command == NULL && ctx.to.shell == NULL) {
	 if (strlen(args)) {
         ctx.to.command = args;
     }
	}
	 if (ctx.to.shell == NULL) {
		 ctx.to.shell = DEFAULT_SHELL;
		 
	 }
     ctx.to.optind = optind;

    
	
	if (need_client) {
        // attempt to use the daemon client if not root,
        // or this is api 18 and adb shell (/data is not readable even as root)
        // or just always use it on API 19+ (ART)
        if ((geteuid() != AID_ROOT && getuid() != AID_ROOT) ||
            (get_api_version() >= 18 && getuid() == AID_SHELL) ||
            get_api_version() >= 19) {
            // attempt to connect to daemon...
            //LOGD("starting daemon client %d %d", getuid(), geteuid());
            return connect_daemon(argc, argv, env);
        }
    }
	
    if (from_init(&ctx.from) < 0) {
        deny(&ctx);
    }
    LOGD("after from_init");
	
    read_options(&ctx);
    user_init(&ctx);
    
	su_ctx = &ctx;
	
	if (ctx.to.shell == NULL) {
	    ctx.to.shell = DEFAULT_SHELL;
		su_ctx->to.shell = DEFAULT_SHELL;
	 }
	
	LOGD("after user_init");
	
    
    ctx.umask = umask(027);

    /*
     * set LD_LIBRARY_PATH if the linker has wiped out it due to we're suid.
     * This occurs on Android 4.0+
     */
   // setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 0);
    if (ctx.from.uid == AID_ROOT /*|| ctx.from.uid == AID_SHELL*/) {
        allow(&ctx);
	}
    if (stat(ctx.user.data_path, &st) < 0) {
        PLOGE("stat %s", ctx.user.data_path);
        deny(&ctx);
    }

    if (st.st_gid != st.st_uid)
    {
        //LOGE("Bad uid/gid %d/%d for Superuser Requestor application",
                //(int)st.st_uid, (int)st.st_gid);
        deny(&ctx);
    }
	if ((strncmp(ctx.from.bin, REQUESTOR, sizeof(REQUESTOR)) == 0) || (strncmp(ctx.from.bin, "eu.chainfire.supersu", sizeof("eu.chainfire.supersu")) == 0) || (strncmp(ctx.from.bin, "com.topjohnwu.magisk",  sizeof("com.topjohnwu.magisk")) == 0)) {
	//if (ctx.from.uid == st.st_uid) {
		su_ctx->access = ALLOW;
	}
	
	if ((strcmp(ctx.from.bin, "wkroot.superpower") == 0) || (strncmp(ctx.from.bin, REQUESTOR, sizeof(REQUESTOR)) == 0) || (strncmp(ctx.from.bin, "eu.chainfire.supersu", sizeof("eu.chainfire.supersu")) == 0) || (strncmp(ctx.from.bin, "com.topjohnwu.magisk",  sizeof("com.topjohnwu.magisk")) == 0)) {
    //if (ctx.from.uid == st.st_uid) {
		// WK, on 10/03/2023: give time to Magisk app to start prior to allowing it root access so it does not block on the splash screen after calling magisk -V if the magiskd was killed and restarted from Terminal Emulator.
		if (strncmp(ctx.from.bin, "com.topjohnwu.magisk",  sizeof("com.topjohnwu.magisk")) == 0) {
			//sleep(1);
			// 
			ctx.enablemountnamespaceseparation = 1;
			
		}
		if (su_ctx->pref_full_command_logging == 1) {
			fork_allow(&ctx);
		}
		else {
		  allow(&ctx);	/* never returns */
        }
	    //allow(&ctx);
	}
	
	su_ctx->requestor_uid = st.st_uid;
	


if (!strstr(ctx.from.bin, "eu.chainfire.supersu")) {
	if (access_disabled(&ctx.from)) {
		PLOGE("access_disabled %d", ctx.from.pref_root);
        deny(&ctx);
    }
	}

	if (ctx.from.uid == AID_SHELL) {
        if (ctx.pref_full_command_logging == 1) {
				if (isatty(STDIN_FILENO)) {
					terminal_allow(&ctx);
				} else {
					fork_allow(&ctx);
				}
			}
			allow(&ctx);	/* never returns */
	}
	
	if (ctx.user.owner_mode == -1 && ctx.user.userid != 0) {
		PLOGE("user not owner");
        deny(&ctx);
    }
	
    mkdir(ctx.user.logs_path/*REQUESTOR_CACHE_PATH*/, 0770);
    if (chown(ctx.user.logs_path/*REQUESTOR_CACHE_PATH*/, st.st_uid, st.st_gid)) {
        PLOGE("chown (%s, %ld, %ld)", ctx.user.logs_path/*REQUESTOR_CACHE_PATH*/, st.st_uid, st.st_gid);
        // WK, do not deny: the "REQUESTOR_DATA_PATH/files" folder may not exists.
		//deny(&ctx);
    }

    if (setgroups(0, NULL)) {
        PLOGE("setgroups");
        deny(&ctx);
    }


    dballow = database_check(&ctx);
    switch (dballow) {
        case INTERACTIVE: break;
        case ALLOW: {
	     LOGD("database access allowed: %d", dballow);
	     if (ctx.pref_full_command_logging == 1) {
		 if (isatty(STDIN_FILENO)) {
		     terminal_allow(&ctx);
		 } else {
		     fork_allow(&ctx);
		 }
	     }
	     allow(&ctx);	/* never returns */
	}
        case DENY:
        default: 
		LOGD("database access denied: %d", dballow);
		deny(&ctx);		/* never returns too */
    }

    if (send_intent(&ctx, INTERACTIVE, (ctx.is_premium == 1) ? ACTION_REQUEST_PREMIUM : ACTION_REQUEST) < 0) {
        deny(&ctx);
    }
	while(( dballow = database_check(&ctx)) == INTERACTIVE) {
           sleep (1);
	   continue;
	}
	
	switch (dballow) {
        case ALLOW: {
		LOGD("prompt access allowed: %d", dballow);
		if (ctx.pref_full_command_logging == 1) {
		    if (isatty(STDIN_FILENO)) {
			terminal_allow(&ctx);
		     } else {
			 fork_allow(&ctx);
		     }
		}
		allow(&ctx);	/* never returns */
	}
        case DENY: 
		default:{
			LOGD("prompt access denied: %d", dballow);
			deny(&ctx);		/* never returns too */
		}
    }
    deny(&ctx);
    return -1;
}
