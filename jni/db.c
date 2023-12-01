/*
Copyright 2016-2023 Wanderson Kalil (@WKSuperPower)
** Copyright 2010, Adam Shanks (@ChainsDD)
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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

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


#include "su.h"
#include "utils.h"

int database_check(struct su_context *ctx)
{
    FILE *fp;
    char filename[PATH_MAX];
    char allow[ARG_MAX];
    int last = 0;
    int from_uid = ctx->from.uid;
    char *caller_bin_access_stored = NULL;
	char app_config_access[PATH_MAX];
	char supersu_prefences[PATH_MAX];
	
	
    if (ctx->user.owner_mode) {
        from_uid = from_uid % 100000;
    }
	
	if (ctx->to.pref_switch_superuser == SUPERPOWER) {

    snprintf(filename, sizeof(filename),
                "%s/%u.%s-%u", ctx->user.store_path, from_uid, ctx->from.bin, ctx->to.uid);
    if ((fp = fopen(filename, "r"))) {
        LOGD("Found file %s", filename);
        
        if (fgets(allow, sizeof(allow), fp)) {
            last = strlen(allow) - 1;
            if (last >= 0)
        	    allow[last] = 0;
        	/*
            char cmd[ARG_MAX];
            fgets(cmd, sizeof(cmd), fp);
            // skip trailing '\n' 
            last = strlen(cmd) - 1;
            if (last >= 0)
                cmd[last] = 0;

            LOGD("Comparing '%s' to '%s'", cmd, get_command(&ctx->to));
            if (strcmp(cmd, get_command(&ctx->to)) == 0)
                break;
            else if (strcmp(cmd, "any") == 0) {
                ctx->to.all = 1;
                break;
            }
            else
                strcpy(allow, "prompt");*/
        }
        fclose(fp);
    } else if ((fp = fopen(ctx->user.store_default, "r"))) {
        LOGD("Using default file %s", ctx->user.store_default);
        fgets(allow, sizeof(allow), fp);
        last = strlen(allow) - 1;
        if (last >=0)
            allow[last] = 0;
        
        fclose(fp);
    }
    } else if (ctx->to.pref_switch_superuser == SUPERSU) {
		memset(filename, 0, sizeof(filename));
		    memset(allow, 0, sizeof(allow));
		    
			snprintf(filename, sizeof(filename),
                "/data/user/%d/eu.chainfire.supersu/requests/%d", ctx->user.userid,/*ctx->user.data_path,*/ getpid()/*ctx->from.pid*/);
           if ((fp = fopen(filename, "r"))) {
                LOGD("Found file %s", filename);
        
               if (fgets(allow, sizeof(allow), fp)) {
                   last = strlen(allow) - 1;
               if (last >= 0)
        	       allow[last] = 0;
               }  
		   fclose(fp);   
		   unlink(filename);
		   } 
		memset(supersu_prefences, 0, sizeof(supersu_prefences));
		 snprintf(supersu_prefences, PATH_MAX, "%s/shared_prefs/eu.chainfire.supersu_preferences.xml", ctx->user.data_path);
		 
		 snprintf(app_config_access, sizeof(app_config_access), "config_%s_access", ctx->from.bin);
	     if (last <= 0)
		 if (!allow[0])
		 if (strlen(allow) < 1)
		 if ((fp = fopen(supersu_prefences, "r"))) {
             LOGD("Found file %s", supersu_prefences);
        
             while (fgets(allow, sizeof(allow), fp) != NULL) {
                    last = strlen(allow) - 1;
                    if (last >= 0)
        	            allow[last] = 0;
				     LOGD("%s", allow);
					// if (caller_bin_access_stored == NULL)
				    //if ((caller_bin_access_stored = strstr(allow, app_config_access)) != NULL) {
					        caller_bin_access_stored = allow;
						if (strstr(caller_bin_access_stored, app_config_access) != NULL) {
						    LOGD("caller_bin_access: %s", caller_bin_access_stored);
			          
			                 if (strstr(caller_bin_access_stored/*caller_bin_access*/, "grant") != NULL) {
			                     ctx->access = ALLOW;
								 memset(filename, 0, sizeof(filename));
								 snprintf(filename, sizeof(filename),
                                 "/data/user/%d/eu.chainfire.supersu/requests/%d", ctx->user.userid,/*ctx->user.data_path,*/ getpid()/*ctx->from.pid*/);
								 unlink(filename);
			                     break;
		                     } else if (strstr(caller_bin_access_stored/*caller_bin_access*/, "deny") != NULL) {
					                    ctx->access = DENY;
										memset(filename, 0, sizeof(filename));
										snprintf(filename, sizeof(filename),
                                        "/data/user/%d/eu.chainfire.supersu/requests/%d", ctx->user.userid,/*ctx->user.data_path,*/ getpid()/*ctx->from.pid*/);
										unlink(filename);
			                            break;
		                    } 
				        }
						if (feof(fp)) {
							break;
						}
		      }
		     fclose(fp);
		   }
		  
	} else if (ctx->to.pref_switch_superuser == MAGISK) {
		
		char *magisk_path[] = {"/sbin/magisk", "/sbin/magisk64",  "/sbin/magisk32", "/system/bin/magisk",  "/system/bin/magisk64",  "/system/bin/magisk32", NULL, };
		
		char * magisk = NULL;
	    int i= 0;
	
	    for (i =0; i < 6;i++) {
		     if (access (magisk_path[i], X_OK) == 0) {
			     magisk = magisk_path[i];
				 break;
		     }
	    }
		
		char pref_multiuser_mode[PROPERTY_VALUE_MAX];
	char pref_full_command_logging[PROPERTY_VALUE_MAX];
	char pref_root[PROPERTY_VALUE_MAX];
	char pref_switch_superuser[PROPERTY_VALUE_MAX];
	char defaul_access[PROPERTY_VALUE_MAX];
	char *caller_bin_access = NULL;
	//char access[PROPERTY_VALUE_MAX];
	char notify[PROPERTY_VALUE_MAX];
	char pref_mount_namespace_separation[PROPERTY_VALUE_MAX];
	
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
       //Wait 20 seconds for a connection, then give up. 
       tv.tv_sec = 1;
       tv.tv_usec = 0;
	   //socketpair(AF_LOCAL, SOCK_STREAM, 0, mnsfd);
	   /*FD_ZERO(&fds);
       FD_SET(mnsfd[0], &fds);
	   */
		pid_t pid ;// = fork();
		
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
			
			/*do {
             rc = select(mnsfd[0] + 1, &fds, NULL, NULL, &tv);
            } while (rc < 0 && errno == EINTR);
              if (rc < 1) {
                  PLOGE("select 1");
                  //return -1;
            } else {*/
			//sleep(1);
			len = read(settingsfd[0], allow, ARG_MAX);
			if (len < 1 /*!= sizeof(int)*/) {
                LOGE("unable to read int from settingsfd: %d", len);
                      //return INTERACTIVE;
						//exit(-1);
            } else {
			char *data = allow;
			//memset(allow, 0, ARG_MAX);
			char *root_access = strstr(data, "key=root_access");
			char *multiuser_mode = strstr(data, "key=multiuser_mode");
			char *mnt_ns = strstr(data, "key=mnt_ns");
			
			LOGD("len: %d root_access: %s multiuser_mode: %s mnt_ns: %s",len, root_access, multiuser_mode, mnt_ns);
			if (root_access != NULL) {
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
			/*get_property(multiuser_mode, pref_multiuser_mode, "value", "-1");
	        
			LOGD("%s %s", pref_multiuser_mode, data);
			
			if (atoi(pref_multiuser_mode) == 2) {
		        ctx->user.owner_mode = 0;
	        } else if (atoi(pref_multiuser_mode) == 1) {
		      ctx->user.owner_mode = 1;
	        }
			
			get_property(root_access, pref_root, "value", "3");
	        ctx->from.pref_root = atoi(pref_root);
			get_property(mnt_ns, pref_mount_namespace_separation, "value", "1");
	        ctx->enablemountnamespaceseparation = atoi(pref_mount_namespace_separation);
			LOGD("len: %d mnt_ns: %s %s",len, pref_mount_namespace_separation , mnt_ns);
			*/
			memset(allow, 0, ARG_MAX);
	        close(settingsfd[0]);
		}
		}
			//&val, sizeof(int));
                    /*if (len != sizeof(int)) {
                        LOGE("unable to read int mns: %d", len);
                        rc = -1;
						//return INTERACTIVE;
						//exit(-1);
                    }
			
			//, allow, 7);
			
			LOGD("value =%d", val);
			
			if (allow[0]) {
				ctx->enablemountnamespaceseparation = atoi(allow);
				memset(allow, 0, sizeof(allow));
			//}
			}
			//close(mnsfd[0]);
			//kill(pid, SIGKILL);
			//waitpid(pid, &status, 0);
		}
		memset(command, 0, sizeof(command));
		snprintf(command, sizeof(command), "%s --sqlite SELECT value FROM settings WHERE key == multiuser_mode", magisk);
		*/
		//args[0] = "magisk --sqlite SELECT value FROM settings WHERE key == 'multiuser_mode'";
		//socketpair(AF_LOCAL, SOCK_STREAM, 0, multiuserfd);
	   /* FD_ZERO(&fds);
        FD_SET(multiuserfd[0], &fds);
		*/
	    //pid = fork();
		
		//if (fork_zero_fucks() == 0/*pid == 0*/) {
			/*if (-1 == dup2(multiuserfd[1], STDOUT_FILENO)) {
            PLOGE("dup2 child outfd");
            }
			close(multiuserfd[0]);
			close(multiuserfd[1]);
			*/
			//execv(_PATH_BSHELL/*magisk*/, args);
			/*exit(1);
		} else {
			close(multiuserfd[1]);
			*/
			/*do {
             rc = select(multiuserfd[0] + 1, &fds, NULL, NULL, &tv);
            } while (rc < 0 && errno == EINTR);
              if (rc < 1) {
                  PLOGE("select 2");
                  //return -1;
            }
			 else {*/
			 //sleep(1);
			//len = read(multiuserfd[0],  allow, 7);
			/*&val, sizeof(int));*/
                    /*if (len != sizeof(int)) {
                        LOGE("unable to read int multiuser: %d", len);
                        rc = -1;
						//return INTERACTIVE;
						//exit(-1);
                    }*/
			//allow, 7);
			
			/*if (allow[0]) {
				if (atoi(allow) == 1) {
		            ctx->user.owner_mode = 1;
	            } 
				if (atoi(allow) == 2) {
		            ctx->user.owner_mode = 0;
	            } 
				memset(allow, 0, sizeof(allow));
			}
			//}
			close(multiuserfd[0]);
			//kill(pid, SIGKILL);
			//waitpid(pid, &status, 0);
		}*/
		
		char command_args[ARG_MAX];
		snprintf(command_args, sizeof(command_args), "%s --sqlite 'SELECT policy, notification FROM policies WHERE uid=%d'", magisk, from_uid);
		args[0] = "sh";//chcon;
		args[1] = "-c";
	    args[2] = command_args;
		
		//args [0] = command_args;
		//socketpair(AF_LOCAL, SOCK_STREAM, 0, resultfd);
	    /*FD_ZERO(&fds);
        FD_SET(resultfd[0], &fds);
		*/
		char result[ARG_MAX];
	        char notification[ARG_MAX];
			
		// pid = fork();
		
		if (fork_zero_fucks() == 0) {
			if (-1 == dup2(resultfd[1], STDOUT_FILENO)) {
            PLOGE("dup2 child outfd");
            }
			close(resultfd[0]);
			close(resultfd[1]);
			
			execv(_PATH_BSHELL, args);
			exit(1);
		} else {
			close(resultfd[1]);
			
			/*do {
             rc = select(resultfd[0] + 1, &fds, NULL, NULL, &tv);
            } while (rc < 0 && errno == EINTR);
              if (rc < 1) {
                  PLOGE("select 3");
                  //return -1;
            }
			else {*/
			//sleep(1);
			len = read(resultfd[0], result, ARG_MAX);
            if (len < 1/*!= sizeof(int)*/) {
                LOGE("unable to read int result: %d", len);
                rc = -1;
						//return INTERACTIVE;
						//exit(-1);
             } else {
			//result, ARG_MAX);
			LOGD("result: %s", result);
			//get_property(result, allow, "policy", "3");
			
			char *policy = strstr(result, "policy");
			policy[8] = '\0';
			
			//get_property(policy, allow, "policy", "3");
			
			char *value = strrchr(policy, '=');
			
			    LOGD("len %d allow: %s", len, value /*allow*/);
				if (atoi(value) == 2 || strstr(value, "2")) {
					unlink(ctx->to.fifo);
					ctx->to.fifo[0] = '\0';
					ctx->access = ALLOW;
				}
				else if (atoi(value) == 1 || strstr(value, "1")) {
					unlink(ctx->to.fifo);
					ctx->to.fifo[0] = '\0';
					ctx->access = DENY;
				}
				//ctx->access = atoi(allow);
			
			//get_property(result, notification, "notification", "1");
			char *notificar = strstr(result, "notification");
			notification[15] = '\0';
			
			value = strchr(notificar, '=');
			
			//get_property(notificar/*result*/, notification, "notification", "1");
			LOGD("notification: %s", value/*notificar*/);
			
			if (strstr(value, "1"))
			   ctx->notify = 1;// atoi(value[1]);
			else ctx->notify = 0;
			//}
			close(resultfd[0]);
			//kill(pid, SIGKILL);
			//waitpid(pid, &status, 0);
		}
		}
		if (/*!result*/rc < 1) {
            LOGD("prompting");
                  //return -1;
			
			snprintf(/*filename*/ctx->to.fifo, sizeof(/*filename*/ctx->to.fifo), "/dev/socket/%s", ctx->from.bin);
			//unlink(/*filename*/ctx->to.fifo);
			//mkfifo(/*filename*/ctx->to.fifo, 0600);
			fd = open(/*filename*/ctx->to.fifo, O_CREAT | O_RDWR | O_CLOEXEC, 0666);
				
		    if (fd == -1) {
				PLOGE("open()");
			}
			chmod(ctx->to.fifo, 0666);
			if(chown(/*filename*/ctx->to.fifo, ctx->requestor_uid, ctx->requestor_uid))
				PLOGE("chown");
			
			char chcon[ARG_MAX];
			snprintf(chcon, sizeof(chcon), "/system/bin/chcon u:object_r:magisk_file:s0 %s", /*filename*/ctx->to.fifo);
			args[0] = "sh";//chcon;
			args[1] = "-c";
			args[2] = chcon;
			
			
			//args[0] =chcon;
			//pid = fork();
			if(ctx->to.fifo[0])
			if (access(ctx->to.fifo, R_OK) == 0) {
			if (fork_zero_fucks() == 0/*pid == 0*/) {
				//int zero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
                //dup2(zero, 0);
                int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
                dup2(null, 1);
				// WK on27/02/2023: if ctx->to.fifo was unlinked, chcon will fail and show its error output on the screen. redirect its error to /dev/null:
                dup2(null, 2);
				execv(_PATH_BSHELL/*"/system/bin/chcon"*/, args);
				exit(1);
			} else {
				//waitpid(pid, &status, 0);
			
			
				/*FD_ZERO(&fds);
                FD_SET(fd, &fds);
				
				do {
                 rc = select(fd + 1, &fds, NULL, NULL, &tv);
                } while (rc < 0 && errno == EINTR);
                if (rc < 1) {
                    PLOGE("select 4");*/
					//unlink(/*filename*/ctx->to.fifo);
                    //return -1;
                //} else {
					 len = read(fd, &val, sizeof(int));
                    if (len != sizeof(int)) {
                        LOGE("unable to read int from fd: %d", len);
                        //return INTERACTIVE;
						//exit(-1);
                    }
					//kill(pid, SIGKILL);
					
					//read(fd, allow, sizeof(allow));
					LOGD("allow: %d", val/*allow*/);
					if (val/*atoi(allow)*/ == 33554432/*2*/) {
						//allow[0] = 1;
						//close(fd);
						
						unlink(ctx->to.fifo);
						ctx->to.fifo[0] = '\0';
						close(fd);
						return ALLOW;
					}
					if (val/*atoi(allow)*/ == 16777216/*1*/) {
						//close(fd);
						unlink(ctx->to.fifo);
						ctx->to.fifo[0] = '\0';
						close(fd);
						return DENY;
						//allow[0] = 0;
					}
				//}
				
			}
		  }
        }
	}
	
	if (ctx->to.pref_switch_superuser == SUPERSU) {
		memset(filename, 0, sizeof(filename));
		    memset(allow, 0, sizeof(allow));
		    
			snprintf(filename, sizeof(filename),
                "/data/user/%d/eu.chainfire.supersu/requests/%d", ctx->user.userid,/*ctx->user.data_path,*/ getpid()/*ctx->from.pid*/);
           if ((fp = fopen(filename, "r"))) {
                LOGD("Found file %s", filename);
        
               if (fgets(allow, sizeof(allow), fp)) {
                   last = strlen(allow) - 1;
               if (last >= 0)
        	       allow[last] = 0;
               }  
		   fclose(fp);   
		   } 
	  }
	
	if (strcmp(allow, "ALLOW") == 0 || strstr(allow, "1") || allow[0] == '1') {
		ctx->access = ALLOW;
	    unlink(filename);
        return ALLOW;
    } else if(strcmp(allow, "DENY") == 0 || strstr(allow, "0") != NULL ||  allow[0] == '0') {
	    ctx->access = DENY;
	    unlink (filename);
        return DENY;
    } 
    if (strcmp(allow, "allow") == 0 || ctx->access == ALLOW) {
        return ALLOW;
    } else if (strcmp(allow, "deny") == 0 || ctx->access == DENY) {
        return DENY;
    } else {
        if (ctx->user.userid != 0 && ctx->user.owner_mode) {
            return DENY;
        } else {
            return INTERACTIVE;
        }
    }
}
