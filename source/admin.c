/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014 - 2015 ForgeRock AS.
 */

#include "platform.h"
#include "am.h"
#include "utility.h"
#include "net_client.h"
#include "list.h"
#include "version.h"
#include "zip.h"

#ifdef _WIN32
#define LIB_FILE_EXT "dll"
#define APACHE_DEFAULT_CONF_FILE "c:\\Apache\\conf\\httpd.conf"
#else
#define LIB_FILE_EXT "so"
#define APACHE_DEFAULT_CONF_FILE "/opt/apache/conf/httpd.conf"
#endif

#ifdef AM_BINARY_LICENSE
#define LICENSE_FILE ".."FILE_PATH_SEP"legal"FILE_PATH_SEP"license.txt"
#else
#define LICENSE_FILE ".."FILE_PATH_SEP"legal"FILE_PATH_SEP"CDDLv1.0.txt"
#endif

/* configuration template patterns */
#define AM_INSTALL_OPENAMURL "AM_OPENAM_URL"
#define AM_INSTALL_REALM "AM_AGENT_REALM"
#define AM_INSTALL_AGENTURL "AM_AGENT_URL"
#define AM_INSTALL_AGENT "AM_AGENT_NAME"
#define AM_INSTALL_PASSWORD "AM_AGENT_PASSWORD"
#define AM_INSTALL_KEY "AM_AGENT_KEY"
#define AM_INSTALL_DEBUGPATH "AM_DEBUG_FILE_PATH"
#define AM_INSTALL_AUDITPATH "AM_AUDIT_FILE_PATH"
#define AM_INSTALL_AGENT_FQDN "AM_AGENT_FQDN"

typedef void (*param_handler)(int, char **);

struct command_line {
    const char* option;
    param_handler handler;
};

struct am_conf_entry {
    char name[AM_PATH_SIZE];
    char path[AM_PATH_SIZE];
    char web[AM_PATH_SIZE];
    struct am_conf_entry *next;
};

enum {
    AM_I_UNKNOWN = 0,
    AM_I_APACHE,
    AM_I_IIS,
    AM_I_VARNISH
};

/* forward declarations (IIS specific) */
void list_iis_sites(int, char **);
int enable_module(const char *, const char *);
int disable_module(const char *, const char *);
int test_module(const char *);
int install_module(const char *, const char *);
int remove_module();

static const char *am_container_str(int v) {
    switch (v) {
        case AM_I_APACHE: return "Apache";
        case AM_I_IIS: return "IIS";
        case AM_I_VARNISH: return "Varnish";
        default: return "unknown";
    }
}

static int instance_type = AM_I_UNKNOWN;
static char app_path[AM_URI_SIZE];
static char log_path[AM_URI_SIZE];
static char license_tracker_path[AM_URI_SIZE];
static char instance_path[AM_URI_SIZE];
static char instance_config[AM_URI_SIZE];
static char config_template[AM_URI_SIZE];

static void install_log(const char *format, ...) {
    char ts[64];
    struct tm now;
    FILE *f = fopen(log_path, "a+");
#ifdef _WIN32
    time_t tv;
    time(&tv);
    localtime_s(&now, &tv);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &now);
#endif
    strftime(ts, sizeof(ts) - 1, "%Y-%m-%d %H:%M:%S", &now);
    if (f != NULL) {
        va_list args;
        fprintf(f, "%s  ", ts);
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
}

#ifdef _WIN32

static DWORD old_mode;
static HANDLE cons_handle;
static BOOL exit_handler(DWORD s)
#else

static void exit_handler(int s)
#endif
{
    install_log("installation aborted");
    fprintf(stdout, "\n");
#ifdef _WIN32
    switch (s) {
        case CTRL_BREAK_EVENT:
        case CTRL_C_EVENT:
        {
            fflush(stdout);
            SetConsoleMode(cons_handle, old_mode);
            ExitProcess(-1);
        }
        default: break;
    }
    return TRUE;
#else
    exit(1);
#endif
}

static char *prompt_and_read(const char *p) {
    char *r;
    printf("%s ", p);
#define USER_INPUT_BUFFER_SIZE 256 
    if ((r = malloc(USER_INPUT_BUFFER_SIZE + 1)) == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(1);
    }
    if (fgets(r, USER_INPUT_BUFFER_SIZE, stdin) == NULL) {
        free(r);
        return NULL;
    }
    trim(r, '\n');
    trim(r, '\r');
    trim(r, ' ');
    return r;
}

static void password_decrypt(int argc, char **argv) {
    if (argc == 4) {
        char *key = argv[2];
        char *password = strdup(argv[3]);
        if (decrypt_password(key, &password) > 0) {
            fprintf(stdout, "\nPassword value: %s\n\n", password);
        }
        am_free(password);
    }
}

static void password_encrypt(int argc, char **argv) {
    if (argc == 4) {
        char *key = argv[2];
        char *password = strdup(argv[3]);
        if (encrypt_password(key, &password) > 0) {
            fprintf(stdout, "\nEncrypted password value: %s\n\n", password);
        } else {
            fprintf(stdout, "\nError encrypting password - invalid arguments.\n\n");
        }
        am_free(password);
    }
}

static void generate_key(int argc, char **argv) {
    char *encoded = NULL, key[37];
    size_t sz = 16; /* limit the number of random characters in a key */
    uuid(key, sizeof(key));
    encoded = base64_encode(key, &sz);
    fprintf(stdout, "\nEncryption key value: %s\n\n", encoded);
    am_free(encoded);
}

static void show_version(int argc, char **argv) {
    fprintf(stdout, "\n%s\n", DESCRIPTION);
    fprintf(stdout, " Version: %s\n", VERSION);
    fprintf(stdout, " %s\n", VERSION_VCS);
    fprintf(stdout, " Build machine: %s\n", BUILD_MACHINE);
    fprintf(stdout, " Build date: %s %s\n\n", __DATE__, __TIME__);
}

static int am_read_instances(const char *path, struct am_conf_entry **list) {
    int ret = 0;
    char buff[AM_PATH_SIZE * 3];
    char a[AM_PATH_SIZE], b[AM_PATH_SIZE], c[AM_PATH_SIZE];
    FILE *fin = fopen(path, "r");
    if (fin != NULL) {
        while (fgets(buff, (AM_PATH_SIZE * 3), fin)) {
            if (buff[0] == '#' || buff[0] == '\n') {
                continue;
            }
            if (sscanf(buff, "%s %s %s", a, b, c) == 3) {
                struct am_conf_entry *e = malloc(sizeof(struct am_conf_entry));
                strncpy(e->name, a, sizeof(e->name) - 1);
                strncpy(e->path, b, sizeof(e->path) - 1);
                strncpy(e->web, c, sizeof(e->web) - 1);
                e->next = NULL;
                AM_LIST_INSERT(*list, e);
                ret++;
            }
        }
        fclose(fin);
    } else {
        ret = AM_FILE_ERROR;
    }
    return ret;
}

static int am_cleanup_instance(const char *pth, const char *name) {
    int ret = AM_EINVAL;
    char *p1 = NULL;
    char buff[AM_PATH_SIZE * 3];
    char key[AM_PATH_SIZE];

    if (pth != NULL && name != NULL) {
        FILE *fout, *fin = fopen(pth, "r");
        if (fin != NULL) {
            am_asprintf(&p1, "%s_edit", pth);
            if (p1 == NULL) {
                fclose(fin);
                return AM_ENOMEM;
            }
            fout = fopen(p1, "w");
            if (fout != NULL) {
                /* configuration line begins with an instance name followed by a space */
                snprintf(key, sizeof(key),
                        strstr(pth, ".agents") != NULL ? "%s " : "%s", name);
                while (fgets(buff, AM_PATH_SIZE * 3, fin)) {
                    if (strstr(buff, key) == NULL) {
                        fputs(buff, fout);
                    }
                }
                fclose(fout);
            } else {
                ret = AM_FILE_ERROR;
            }
            fclose(fin);
            if (copy_file(p1, pth) == AM_SUCCESS) {
                am_delete_file(p1);
            }
            free(p1);
        } else {
            ret = AM_FILE_ERROR;
        }
    }
    return ret;
}


/**
 * @param status For IIS
 * @param web_conf_path The path of the conf.d file (in the case of Apache)
 * @param openam_url The URL of OpenAM
 * @param agent_realm The realm of the agent
 * @param agent_url The URL of the agent
 * @param agent_user The user the agent runs as
 * @param agent_password The password of the agent
 * @param uid The uid of the user specified by "User" in the conf.d file in the case of Apache
 * @param gid The gid of the group specified by "Group" in the conf.d file in the case of Apache
 */
static int create_agent_instance(int status,
                                 const char* web_conf_path,
                                 const char* openam_url,
                                 const char* agent_realm,
                                 const char* agent_url,
                                 const char* agent_user,
                                 const char* agent_password,
                                 uid_t* uid,
                                 gid_t* gid) {

    FILE* f = NULL;
    int rv = AM_ERROR;
    char* created_name_path = NULL;
    char* created_name_simple = NULL;
    char* agent_conf_template = NULL;
    
    if (am_create_agent_dir(FILE_PATH_SEP, instance_path,
                            &created_name_path, &created_name_simple,
                            uid, gid) != 0) {
        install_log("failed to create agent instance configuration directories");
        AM_FREE(created_name_path, created_name_simple);
        return rv;
    }

    install_log("agent instance configuration directories created");

    size_t agent_conf_template_sz = 0;

    /* create agent configuration file (from a template) */
    agent_conf_template = load_file(config_template, &agent_conf_template_sz);
    if (agent_conf_template != NULL) {
        char* log_path = NULL;
        char* audit_log_path = NULL;
        char* conf_file_path = NULL;

        rv = AM_SUCCESS;

        am_asprintf(&conf_file_path, "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf", created_name_path);
        am_asprintf(&log_path, "%s"FILE_PATH_SEP"logs"FILE_PATH_SEP"debug"FILE_PATH_SEP, created_name_path);
        am_asprintf(&audit_log_path, "%s"FILE_PATH_SEP"logs"FILE_PATH_SEP"audit"FILE_PATH_SEP, created_name_path);

        do {
            struct url u;
            char* encoded;
            char* password;
            char key[37];
            size_t sz = 16;

            if (log_path == NULL || audit_log_path == NULL || conf_file_path == NULL) {
                rv = AM_ENOMEM;
                break;
            }

            /* do a search-n-replace (in memory) */
            install_log("updating %s", AM_INSTALL_OPENAMURL);
            rv = string_replace(&agent_conf_template, AM_INSTALL_OPENAMURL, openam_url, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            rv = parse_url(agent_url, &u);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s %s", AM_INSTALL_AGENT_FQDN, u.host);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENT_FQDN, u.host, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s", AM_INSTALL_REALM);
            rv = string_replace(&agent_conf_template, AM_INSTALL_REALM, agent_realm, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s", AM_INSTALL_AGENTURL);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENTURL, agent_url, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s", AM_INSTALL_AGENTURL);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENT, agent_user, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            uuid(key, sizeof(key));
            encoded = base64_encode(key, &sz);
            install_log("updating %s", AM_INSTALL_KEY);
            rv = string_replace(&agent_conf_template, AM_INSTALL_KEY, encoded, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                am_free(encoded);
                break;
            }

            password = strdup(agent_password);
            if (password == NULL) {
                rv = AM_ENOMEM;
                am_free(encoded);
                break;
            }

            if (encrypt_password(encoded, &password) > 0) {
                install_log("updating %s", AM_INSTALL_PASSWORD);
                rv = string_replace(&agent_conf_template, AM_INSTALL_PASSWORD, password, &agent_conf_template_sz);
            }
            am_free(password);
            am_free(encoded);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s", AM_INSTALL_DEBUGPATH);
            rv = string_replace(&agent_conf_template, AM_INSTALL_DEBUGPATH, log_path, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s", AM_INSTALL_AUDITPATH);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AUDITPATH, audit_log_path, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update agent configuration template file %s (%s)",
                        config_template, am_strerror(rv));
                break;
            }

            /* write an updated template to the agent configuration file */
            install_log("writing configuration to %s", conf_file_path);
            if (write_file(conf_file_path, agent_conf_template, agent_conf_template_sz) > 0) {
                rv = AM_SUCCESS;
            } else {
                install_log("failed to write agent configuration to %s", conf_file_path);
                rv = AM_FILE_ERROR;
            }

        } while (0);

        AM_FREE(agent_conf_template, conf_file_path, log_path, audit_log_path);
    } else {
        install_log("failed to open agent configuration template file %s", config_template);
        rv = AM_ENOMEM;
    }

    if (rv == AM_SUCCESS) {
        /* update installer (instance) configuration */
        f = fopen(instance_config, "a");
        if (f != NULL) {
            fprintf(f, "%s %s %s\n", created_name_simple, created_name_path, web_conf_path);
            fclose(f);
            install_log("agent instance configuration updated");
        } else {
            install_log("failed to update agent instance configuration file %s", instance_config);
            rv = AM_FILE_ERROR;
        }
    }

    /* container specific updates */
    switch (instance_type) {
        case AM_I_APACHE: {
            if (rv == AM_SUCCESS && copy_file(web_conf_path, NULL) == AM_SUCCESS) {
                /* update Apache httpd.conf (global context only) */
                f = fopen(web_conf_path, "a");
                if (f != NULL) {
                    fprintf(f, "\n\nLoadModule amagent_module %s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"mod_openam."LIB_FILE_EXT"\n"
                            "AmAgent On\n"
                            "AmAgentConf %s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf\n\n",
                            app_path, created_name_path);
                    fclose(f);
                    install_log("webserver configuration %s updated", web_conf_path);
                }
            } else {
                install_log("failed to create a backup copy of %s", web_conf_path);
                rv = AM_FILE_ERROR;
            }
            break;
        }
        case AM_I_IIS: {
            if (rv == AM_SUCCESS && status == 0) {
                char schema_file[AM_URI_SIZE];
                char lib_file[AM_URI_SIZE];
                snprintf(schema_file, sizeof(schema_file),
                        "%s.."FILE_PATH_SEP"config"FILE_PATH_SEP"mod_iis_openam_schema.xml",
                        app_path);
                snprintf(lib_file, sizeof(lib_file),
                        "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"mod_iis_openam."LIB_FILE_EXT,
                        app_path);

                /* need to add module to global configuration first */
                if (install_module(lib_file, schema_file) == 0) {
                    rv = AM_ERROR;
                } else {
                    install_log("webserver site global configuration updated");
                }
            }
            if (rv == AM_SUCCESS) {
                char iis_instc_file[AM_URI_SIZE];
                snprintf(iis_instc_file, sizeof(iis_instc_file),
                        "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                        created_name_path);

                /* module is already loaded in global configuration */
                if (enable_module(web_conf_path, iis_instc_file) == 0) {
                    rv = AM_ERROR;
                } else {
                    install_log("webserver site %s configuration updated", web_conf_path);
                }
            }
            break;
        }
        case AM_I_VARNISH: {
            //TODO
            break;
        }
        default: {
            install_log("unknown installation instance type %d", instance_type);
            break;
        }
    }

    /* delete agent configuration directory in case of an error */
    if (rv != AM_SUCCESS) {
        install_log("cleaning up agent configuration and directory %s", created_name_path);
        am_delete_directory(created_name_path);
        am_cleanup_instance(instance_config, created_name_simple);
    }

    AM_FREE(created_name_path, created_name_simple);
    return rv;
}


/**
 * Check if the user wants to quit and if so, let them quit.
 */
static void check_if_quit_wanted(char* input) {
    if (ISVALID(input) && strcasecmp(input, "q") == 0) {
        free(input);
        install_log("installation exit because user typed \"q\" for input");
        exit(1);
    }
}

/**
 * Find the word after the specified text in the httpd conf file, read it into
 * buff and null terminate it.
 *
 * @param httpd_conf_file The entire contents of the conf file, read into a string.
 * @param target The word we're looking for.
 * @param buff The buffer we're writing into.
 * @param size Number of bytes available in buff.
 */
static void find_conf_setting(char* httpd_conf_file, char* target, char* buff, size_t size) {
    char* user = strstr(httpd_conf_file, target);
    int i = 0;
    if (user != NULL) {
        user += strlen(target); /* skip length of string */

        /* Skip initial spacing */
        while(*user != '\0' && *user != '\n' && *user != '#' && isspace(*user)) {
            user++;
        }
        
        /* read into buffer, until space, newline or comment */
        while(*user != '\0' && *user != '\n' && *user != '#' && !isspace(*user) && i < size) {
            buff[i++] = *user++;
        }
    }
    buff[i] = '\0';
}

/**
 * Find the line saying:
 *
 * User daemon
 *
 * (or whatever) in the httpd conf file and return the user id and group id information
 * corresponding to the user specified (if valid).  Note that httpd allows the user to be
 * specified as an integer.
 *
 * @param httpd_conf_file The entirety of the conf file, copied into a null terminated buffer
 * @param uid change where pointer points to NULL if not found, or to dynamic memory if found
 * @param gid change where pointer points to NULL if not found, or dynamic memory if found
 */
static void find_user(char* httpd_conf_file, uid_t** uid, gid_t** gid) {
#ifdef _WIN32

    *uid = NULL;
    *gid = NULL;

#else /* _WIN32 */
    char* p;
    char buff[AM_USER_GROUP_NAME_LIMIT];
    struct passwd* password_entry;
    
    *uid = NULL;
    *gid = NULL;
    
    find_conf_setting(httpd_conf_file, "\nUser", buff, sizeof(buff));
    
    if (*buff == '\0') {
        return;
    }
    
    /* does the buffer contain a number */
    am_bool_t isNumeric = AM_TRUE;
    for (p = buff; *p != '\0'; p++) {
        if (!isdigit(*p)) {
            isNumeric = AM_FALSE;
            break;
        }
    }
    
    if (isNumeric) {
        password_entry = getpwuid((uid_t)atol(buff));
    } else {
        password_entry = getpwnam(buff);
    }

    if (password_entry == NULL) {
        install_log("Warning: Unable to find user \"%s\" specifed by \"User\" in httpd.conf", buff);
        return;
    }

    *uid = malloc(sizeof(uid_t));
    if (*uid == NULL) {
        return;
    }
    **uid = password_entry->pw_uid;
    *gid = malloc(sizeof(gid_t));
    if (*gid == NULL) {
        return;
    }
    **gid = password_entry->pw_gid;
    
    install_log("Found user %s, uid %d, gid %d", buff, **uid, **gid);
#endif /* _WIN32 */
}



/**
 * Find the line saying:
 *
 * Group daemon
 *
 * (or whatever) in the httpd conf file and return the group id information.
 *
 * @param httpd_conf_file The entirety of the conf file, copied into a null terminated buffer
 * @param pointer to gid_t pointer which will change if the user is found and valid
 */
static void find_group(char* httpd_conf_file, gid_t** gid) {
#ifdef _WIN32
#else
    char* p;
    char buff[AM_USER_GROUP_NAME_LIMIT];
    struct group* group_entry;
    
    find_conf_setting(httpd_conf_file, "\nGroup", buff, sizeof(buff));
    
    if (*buff == '\0') {
        install_log("Unable to find the \"Group\" entry in the httpd.conf file");
        return;
    }
    
    /* does the buffer contain a number */
    am_bool_t isNumeric = AM_TRUE;
    for (p = buff; *p != '\0'; p++) {
        if (!isdigit(*p)) {
            isNumeric = AM_FALSE;
            break;
        }
    }
    
    if (!isNumeric) {
        group_entry = getgrgid((gid_t)atol(buff));
    } else {
        group_entry = getgrnam(buff);
    }
    if (group_entry == NULL) {
        install_log("Unable to find group \"%s\" specifed by \"Group\" in httpd.conf", buff);
        return;
    }
    if (*gid == NULL) {
        *gid = malloc(sizeof(gid_t));
        if (*gid == NULL) {
            return;
        }
    }
    **gid = group_entry->gr_gid;
    
    install_log("Found group %s, gid %d", buff, **gid);
#endif /* _WIN32 */
}



static void install_interactive(int argc, char **argv) {
    int rv;
    int iis_status = 0;
    char lic_accepted = AM_FALSE, validated = AM_FALSE;
    char* input = NULL;
    char* agent_token = NULL;
    char lic_file_path[AM_URI_SIZE];
    char apache_conf[AM_URI_SIZE];
    char openam_url[AM_URI_SIZE];
    char agent_realm[AM_URI_SIZE];
    char agent_url[AM_URI_SIZE];
    char agent_user[AM_URI_SIZE];
    char agent_password[AM_URI_SIZE];
    uid_t* uid = NULL;
    gid_t* gid = NULL;

    /* set up console signal handler */
#ifdef _WIN32
    DWORD new_mode;
    cons_handle = GetStdHandle(STD_INPUT_HANDLE);
    if (cons_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to get console handle (%d). Exiting.\n", GetLastError());
        return;
    }
    if (!GetConsoleMode(cons_handle, &old_mode)) {
        fprintf(stderr, "Failed to get console mode (%d). Exiting.\n", GetLastError());
        return;
    }
    new_mode = old_mode;
    new_mode |= (ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    if (!SetConsoleMode(cons_handle, new_mode)) {
        fprintf(stderr, "Failed to set console mode (%d). Exiting.\n", GetLastError());
        return;
    }
    SetConsoleCtrlHandler((PHANDLER_ROUTINE) exit_handler, TRUE);
#else
    struct sigaction sa;
    sa.sa_handler = exit_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
#endif

    memset(&apache_conf[0], 0, sizeof(apache_conf));
    memset(&openam_url[0], 0, sizeof(openam_url));
    memset(&agent_url[0], 0, sizeof(agent_url));
    memset(&agent_user[0], 0, sizeof(agent_user));
    memset(&agent_realm[0], 0, sizeof(agent_realm));
    memset(&agent_password[0], 0, sizeof(agent_password));

    snprintf(lic_file_path, sizeof(lic_file_path), "%s%s", app_path, LICENSE_FILE);

    install_log("%s for %s Server interactive installation", DESCRIPTION,
            am_container_str(instance_type));

    if (!file_exists(license_tracker_path)) {
        /* display a license */
        char *lic_data = load_file(lic_file_path, NULL);
        if (lic_data != NULL) {
            fprintf(stdout, "Please read the following License Agreement carefully:\n\n%s\n", lic_data);
            free(lic_data);
        }
        input = prompt_and_read("Do you completely agree with all the terms and conditions \n"
                "of this License Agreement (yes/no): [no]:");
        if (ISVALID(input) && strcasecmp(input, "yes") == 0) {
            install_log("license accepted");
            lic_accepted = AM_TRUE;
            am_make_path(instance_path, NULL, NULL);
            write_file(license_tracker_path, AM_SPACE_CHAR, 1);
        }
        am_free(input);
    } else {
        lic_accepted = AM_TRUE;
        install_log("license was accepted earlier");
    }

    if (!lic_accepted) {
        install_log("license was not accepted");
        fprintf(stdout, "\nYou need to accept the License terms and conditions to continue.\n");
        exit(1);
    }

    fprintf(stdout, "\n%s for %s Server interactive installation.\n\n", DESCRIPTION,
            am_container_str(instance_type));

    am_bool_t error = AM_TRUE;
    do {
        switch (instance_type) {
            case AM_I_APACHE: {
                char *conf = NULL;

                /* Apache HTTPD specific */

                input = prompt_and_read("\nEnter the complete path to the httpd.conf file which is used by Apache HTTPD\n"
                        "Server to store its configuration.\n"
                        "[ q or 'ctrl+c' to exit ]\n"
                        "Configuration file ["APACHE_DEFAULT_CONF_FILE"]:");
                check_if_quit_wanted(input);
                if (!ISVALID(input)) {
                    am_free(input);
                    input = strdup(APACHE_DEFAULT_CONF_FILE);
                    if (input == NULL) {
                        install_log("installation exit (memory allocation error)");
                        exit(1);
                    }
                }

                conf = load_file(input, NULL);
                if (conf != NULL) {
                    find_user(conf, &uid, &gid);
                    find_group(conf, &gid);

                    if (strstr(conf, "LoadModule amagent_module") != NULL && strstr(conf, "#LoadModule amagent_module") == NULL) {
                        fprintf(stdout, "\nError: this server instance is already configured with %s module.\nPlease try again.\n\n", DESCRIPTION);
                        install_log("server instance %s is already configured with %s",
                                input, DESCRIPTION);
                    } else if (strstr(conf, "LoadModule") == NULL) {
                        fprintf(stdout, "\nError: invalid server configuration file %s.]\nPlease try again.\n\n",
                                input);
                        install_log("could not locate LoadModule configuration directive in %s", input);
                    } else {
                        strncpy(apache_conf, input, sizeof(apache_conf) - 1);
                        install_log("server configuration file %s", apache_conf);
                        error = AM_FALSE;
                    }
                    free(conf);
                } else {
                    fprintf(stdout, "\nError: unable to load the server configuration file %s.\nPlease try again.\n\n",
                            input);
                    install_log("unable to load server configuration file %s", input);
                }

#if !defined(_WIN32) && !defined(SOLARIS)
                /**
                 * If not running as root, we cannot offer to chown directories.
                 */
                if (getuid() != 0) {
                    am_free(uid);
                    am_free(gid);
                    uid = NULL;
                    gid = NULL;
                }
#endif
                /**
                 * If we have a uid and gid by this stage, actually ask the user if they want us to chown the
                 * directories we create.  This saves a lot of guesswork looking at "Listen" values in the
                 * httpd.conf file.
                 */
                if (uid != NULL && gid != NULL) {
                    input = prompt_and_read("\nChange ownership of created directories using User and Group settings in httpd.conf\n"
                                            "[ q or 'ctrl+c' to exit ]\n"
                                            "(yes/no): [no]:");
                    check_if_quit_wanted(input);
                    if (ISINVALID(input) || strcasecmp(input, "no") == 0) {
                        AM_FREE(uid, gid);
                        uid = NULL;
                        gid = NULL;
                    }
                }

                free(input);
                
                break; /* avoid fall through into IIS */
            }
            case AM_I_IIS: {
                iis_status = 0;
                /* IIS specific */
                list_iis_sites(argc, argv);

                input = prompt_and_read("\nEnter IIS Server Site identification number.\n"
                        "[ q or 'ctrl+c' to exit ]\n"
                        "Site id:");
                check_if_quit_wanted(input);
                if (input == NULL) {
                    install_log("installation exit");
                    exit(1);
                }

                iis_status = test_module(input);
                if (iis_status == ADMIN_IIS_MOD_LOCAL) {
                    fprintf(stdout, "\nError: this server site is already configured with %s module.\nPlease try again.\n\n", DESCRIPTION);
                    install_log("IIS server site %s is already configured with %s", NOTNULL(input), DESCRIPTION);
                } else {
                    install_log("IIS server site %s is not yet configured with %s (status: %d)",
                            NOTNULL(input), DESCRIPTION, iis_status);
                    strncpy(apache_conf, input, sizeof(apache_conf) - 1);
                    error = AM_FALSE;
                }

                free(input);
                
                break; /* avoid fall through into varnish */
            }
            case AM_I_VARNISH: {
                fprintf(stdout, "Error: %s installation type not supported yet. Exiting.\n",
                        am_container_str(instance_type));
                install_log("unknown installation type");
                exit(1);
            }
            default: {
                fprintf(stdout, "Error: unknown installation type. Exiting.\n");
                install_log("unknown installation type");
                exit(1);
            }
        }
    } while (error == AM_TRUE);

    am_bool_t outer_loop = AM_TRUE;
    do {
        
        /**
         * Get the URL of OpenAM and try to verify it.
         */
        am_bool_t inner_loop = AM_TRUE;
        do {
            int httpcode = 0;
            
            input = prompt_and_read("\nEnter the URL where the OpenAM server is running. Please include the\n"
                    "deployment URI also as shown below:\n"
                    "(http://openam.sample.com:58080/openam)\n"
                    "[ q or 'ctrl+c' to exit ]\n"
                    "OpenAM server URL:");
            check_if_quit_wanted(input);
            if (ISVALID(input)) {
                strncpy(openam_url, input, sizeof(openam_url) - 1);
                install_log("OpenAM URL %s", openam_url);
                if (am_url_validate(0, openam_url, NULL, &httpcode) == AM_SUCCESS) {
                    inner_loop = AM_FALSE;
                } else {
                    fprintf(stdout, "Cannot connect to OpenAM at URI %s, please make sure OpenAM is started\n", openam_url);
                    install_log("OpenAM at %s cannot be contacted (invalid, or not running)", openam_url);
                }
            }
            am_free(input);

        } while (inner_loop == AM_TRUE);

        /**
         * Get the URL of the Agent and try to verify it is not running.
         */
        inner_loop = AM_TRUE;
        do {
            int httpcode = 0;

            input = prompt_and_read("\nEnter the Agent URL as shown below:\n"
                    "(http://agent.sample.com:1234)\n"
                    "[ q or 'ctrl+c' to exit ]\n"
                    "Agent URL:");
            check_if_quit_wanted(input);
            if (ISVALID(input)) {
                strncpy(agent_url, input, sizeof(agent_url) - 1);
                install_log("Agent URL %s", agent_url);

                if (am_url_validate(0, agent_url, NULL, &httpcode) != AM_SUCCESS) {
                    /* hopefully we cannot contact because the agent is not running,
                     * rather than because the URI is complete rubbish
                     */
                    inner_loop = AM_FALSE;
                } else {
                    fprintf(stdout, "The Agent at URI %s should be stopped before installation", agent_url);
                    install_log("Agent URI %s rejected because agent is running", agent_url);
                }
            }
            am_free(input);

        } while (inner_loop == AM_TRUE);
        
        /**
         * The agent profile name.  There is no way to verify this, unless we can contact OpenAM,
         * and we haven't connected in a meaningful way yet.
         */
        input = prompt_and_read("\nEnter the Agent profile name\n"
                "[ q or 'ctrl+c' to exit ]\n"
                "Agent Profile name:");
        check_if_quit_wanted(input);
        if (ISVALID(input)) {
            strncpy(agent_user, input, sizeof(agent_user) - 1);
            install_log("Agent Profile name %s", agent_user);
        }
        am_free(input);

        /**
         * The realm.  Again no way to verify without connecting to OpenAM.
         */
        input = prompt_and_read("\nEnter the Agent realm/organization\n"
                "[ q or 'ctrl+c' to exit ]\n"
                "Agent realm/organization name: [/]:");
        check_if_quit_wanted(input);
        if (ISVALID(input)) {
            strncpy(agent_realm, input, sizeof(agent_realm) - 1);
            install_log("Agent realm/organization name %s", agent_realm);
        } else {
            strncpy(agent_realm, "/", sizeof(agent_realm) - 1);
            install_log("Agent realm/organization name %s", "/");
        }
        am_free(input);

        /**
         * Prompt for the file containing the agent password.  This we can verify -
         * the file must exist, and be readable.
         */
        inner_loop = AM_TRUE;
        do {
            input = prompt_and_read("\nEnter the path to a file that contains the password to be used\n"
                    "for identifying the Agent\n"
                    "[ q or 'ctrl+c' to exit ]\n"
                    "The path to the password file:");
            check_if_quit_wanted(input);
            if (ISVALID(input)) {
                char* password_data = load_file(input, NULL);
                install_log("Agent password file %s", input);
                if (password_data != NULL) {
                    trim(password_data, '\0');
                    install_log("agent password file %s opened successfully", input);
                    strncpy(agent_password, password_data, sizeof(agent_password) - 1);
                    free(password_data);
                    inner_loop = AM_FALSE;
                } else {
                    install_log("unable to open password file %s", input);
                }
            }
            // do not "free(input)" here, "input" is used in the fprintf below
        } while (inner_loop == AM_TRUE);
        
        fprintf(stdout, "\nInstallation parameters:\n\n"
                "   OpenAM URL: %s\n"
                "   Agent URL: %s\n"
                "   Agent Profile name: %s\n"
                "   Agent realm/organization name: %s\n"
                "   Agent Profile password file: %s\n\n",
                openam_url, agent_url, agent_user, agent_realm, NOTNULL(input));

        am_free(input);
        input = prompt_and_read("Confirm configuration (yes/no): [no]:");
        if (ISVALID(input) && strcasecmp(input, "yes") == 0) {
            outer_loop = AM_FALSE;
        } else {
            fprintf(stdout, "\nRestarting the configuration...\n");
            install_log("installation restarted");
        }
        am_free(input);
        
    } while (outer_loop == AM_TRUE);
    
    install_log("validating configuration parameters...");
    fprintf(stdout, "\nValidating...\n");

    am_net_init();

    rv = am_agent_login(0, openam_url, NULL,
            agent_user, agent_password, agent_realm, AM_TRUE, 0, NULL,
            &agent_token, NULL, NULL, NULL, install_log);

    if (rv != AM_SUCCESS) {
        fprintf(stdout, "\nError validating OpenAM - Agent configuration.\n"
                "See installation log %s file for more details. Exiting.\n", log_path);
        install_log("error validating OpenAM agent configuration");
    } else {
        fprintf(stdout, "\nValidating... Success.\n");
        install_log("validating configuration parameters... success");
        validated = AM_TRUE;
    }

    if (agent_token != NULL) {
        fprintf(stdout, "\nCleaning up validation data...\n");
        am_agent_logout(0, openam_url, agent_token, NULL, NULL, install_log);
    }

    if (validated) {
        fprintf(stdout, "\nCreating configuration...\n");
        /* do configure the instance and modify the server configuration */

        switch (instance_type) {
            case AM_I_APACHE:
                if (create_agent_instance(0, apache_conf, openam_url, agent_realm,
                        agent_url, agent_user, agent_password, uid, gid) == AM_SUCCESS) {
                    fprintf(stdout, "\nInstallation complete.\n");
                    install_log("installation complete");
                }
                break;
            case AM_I_IIS:
                if (create_agent_instance(iis_status, apache_conf/* site id */, openam_url, agent_realm,
                        agent_url, agent_user, agent_password, uid, gid) == AM_SUCCESS) {
                    fprintf(stdout, "\nInstallation complete.\n");
                    install_log("installation complete");
                }
                break;
            case AM_I_VARNISH:
                //TODO
                break;
            default:
                install_log("unknown installation instance type");
                break;
        }
    }

#ifdef _WIN32
    SetConsoleMode(cons_handle, old_mode);
    SetConsoleCtrlHandler((PHANDLER_ROUTINE) exit_handler, FALSE);
#endif
    install_log("installation exit");
    am_net_shutdown();
}

/*******************************************************************************************************************/

/**
 * The important thing to know about the way this function works is that the arguments are:
 *
 * argv[1] == --s
 * argv[2] = http conf file path
 * argv[3] = OpenAM URL
 * argv[4] = Agent URL
 * argv[5] = Realm
 * argv[6] = Agent name
 * argv[7] = File containing the agent password
 * argv[8] = OPTIONAL "y/n" argument saying whether to chown.
 */
static void install_silent(int argc, char** argv) {
    char lic_file_path[AM_URI_SIZE];
    char lic_accepted = AM_FALSE;

    install_log("%s for %s server silent installation", DESCRIPTION,
            am_container_str(instance_type));
    fprintf(stdout, "\n%s for %s Server installation.\n\n", DESCRIPTION,
            am_container_str(instance_type));

    snprintf(lic_file_path, sizeof(lic_file_path), "%s%s", app_path, LICENSE_FILE);

    if (!file_exists(license_tracker_path)) {
        /* display a license */
        char *input, *lic_data = load_file(lic_file_path, NULL);
        if (lic_data != NULL) {
            fprintf(stdout, "Please read the following License Agreement carefully:\n\n%s\n", lic_data);
            free(lic_data);
        }
        input = prompt_and_read("Do you completely agree with all the terms and conditions \n"
                "of this License Agreement (yes/no): [no]:");
        if (ISVALID(input) && strcasecmp(input, "yes") == 0) {
            install_log("license accepted");
            lic_accepted = AM_TRUE;
            am_make_path(instance_path, NULL, NULL);
            write_file(license_tracker_path, AM_SPACE_CHAR, 1);
        }
        am_free(input);
    } else {
        lic_accepted = AM_TRUE;
        install_log("license was accepted earlier");
    }

    if (!lic_accepted) {
        install_log("license was not accepted");
        fprintf(stdout, "\nYou need to accept the License terms and conditions to continue.\n");
        exit(1);
    }

    if (argc >= 8) {
        int rv = AM_ERROR;
        char validated = AM_FALSE;
        char *agent_token = NULL;
        char *agent_password;
        uid_t* uid = NULL;
        gid_t* gid = NULL;
        char* conf;
        
        conf = load_file(argv[2], NULL);
        if (conf != NULL) {
            find_user(conf, &uid, &gid);
            find_group(conf, &gid);
            free(conf);
        } else {
            fprintf(stderr, "\nError reading config file %s. Exiting.\n", argv[2]);
            install_log("exiting install because config file %s is not readable", argv[2]);
            exit(1);
        }
#if !defined(_WIN32) && !defined(SOLARIS)
        /**
         * If not running as root, we cannot offer to chown directories.
         */
        if (getuid() != 0) {
            am_free(uid);
            am_free(gid);
            uid = NULL;
            gid = NULL;
        }
#endif
        if (argc >= 8 && strcasecmp(argv[8], "n") == 0) {
            am_free(uid);
            am_free(gid);
            uid = NULL;
            gid = NULL;
        }

        agent_password = load_file(argv[7], NULL);
        if (agent_password == NULL) {
            fprintf(stdout, "\nError reading password file %s. Exiting.\n", argv[7]);
            install_log("installation exit");
            exit(1);
        }

        trim(agent_password, '\n');
        trim(agent_password, '\r');

        am_net_init();

        install_log("validating configuration parameters...");
        fprintf(stdout, "\nValidating...\n");

        rv = am_agent_login(0, argv[3], NULL,
                argv[6], agent_password, argv[5], AM_TRUE, 0, NULL,
                &agent_token, NULL, NULL, NULL, install_log);
        if (rv != AM_SUCCESS) {
            fprintf(stdout, "\nError validating OpenAM - Agent configuration.\n"
                    "See installation log %s file for more details. Exiting.\n", log_path);
            install_log("error validating OpenAM agent configuration");
            exit(1);
        } else {
            fprintf(stdout, "\nValidating... Success.\n");
            install_log("validating configuration parameters... success");
            validated = AM_TRUE;
        }

        if (agent_token != NULL) {
            fprintf(stdout, "\nCleaning up validation data...\n");
            am_agent_logout(0, argv[3], agent_token, NULL, NULL, install_log);
        }

        if (validated) {
            fprintf(stdout, "\nCreating configuration...\n");
            if (instance_type == AM_I_APACHE) {
                if (create_agent_instance(0, argv[2], argv[3], argv[5],
                        argv[4], argv[6], agent_password, uid, gid) == AM_SUCCESS) {
                    fprintf(stdout, "\nInstallation complete.\n");
                    install_log("installation complete");
                }
            } else if (instance_type == AM_I_IIS) {
                if (create_agent_instance(0, argv[2], argv[3], argv[5],
                        argv[4], argv[6], agent_password, uid, gid) == AM_SUCCESS) {
                    fprintf(stdout, "\nInstallation complete.\n");
                    install_log("installation complete");
                }
            } else if (instance_type == AM_I_VARNISH) {
                //TODO
            }
        }

        am_free(agent_password);

        am_net_shutdown();
    } else {
        fprintf(stdout, "\nInvalid arguments. Installation exit.\n");
    }
    install_log("installation exit");
}

static void delete_conf_entry_list(struct am_conf_entry **list) {
    struct am_conf_entry *t = *list;
    if (t != NULL) {
        delete_conf_entry_list(&t->next);
        free(t);
        t = NULL;
    }
}

static void list_instances(int argc, char **argv) {
    struct am_conf_entry *list = NULL, *e, *t;
    int rv = am_read_instances(instance_config, &list);
    if (rv <= 0) {
        fprintf(stdout, "\nNo agent configuration exists.\n");
        delete_conf_entry_list(&list);
        return;
    }

    fprintf(stdout, "\n%s configuration instances:\n\n", DESCRIPTION);

    AM_LIST_FOR_EACH(list, e, t) {
        fprintf(stdout,
                "   id:            %s\n"
                "   configuration: %s\n"
                "   server/site:   %s\n\n", e->name, e->path, e->web);
    }
    delete_conf_entry_list(&list);
    fprintf(stdout, "\n");
}

static void remove_instance(int argc, char **argv) {
    struct am_conf_entry *list = NULL, *e, *t;
    int rv;
    if (argc != 3) {
        fprintf(stdout, "\nNo agent configuration specified.\n");
        return;
    }

    rv = am_read_instances(instance_config, &list);
    if (rv <= 0) {
        delete_conf_entry_list(&list);
        return;
    }

    AM_LIST_FOR_EACH(list, e, t) {
        if (strcmp(e->name, argv[2]) == 0) {
            switch (instance_type) {
                case AM_I_APACHE: {
                    char *input = prompt_and_read("\nWarning! This procedure will remove all "DESCRIPTION" references from \na Web server configuration."
                            " In case you are running "DESCRIPTION" in a\nmulti-virtualhost mode, an uninstallation must be carried out manually.\n\nContinue (yes/no): [no]:");
                    if (!ISVALID(input) || strcasecmp(input, "yes") != 0) {
                        am_free(input);
                        break;
                    }
                    am_free(input);

                    fprintf(stdout, "\nRemoving %s configuration...\n", e->name);
                    /* remove LoadModule line */
                    rv = am_cleanup_instance(e->web, "LoadModule amagent_module");
                    /* remove AmAgent On/Off line */
                    rv = am_cleanup_instance(e->web, "AmAgent ");
                    /* remove AmAgentConf line */
                    rv = am_cleanup_instance(e->web, "AmAgentConf ");
                    /* delete agent instance configuration directory */
                    am_delete_directory(e->path);
                    /* remove agent instance configuration */
                    am_cleanup_instance(instance_config, e->name);
                    fprintf(stdout, "\nRemoving %s configuration... Done.\n", e->name);
                    break;
                }
                case AM_I_IIS: {
                    char iis_instc_file[AM_URI_SIZE];
                    snprintf(iis_instc_file, sizeof(iis_instc_file),
                            "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                            e->path);

                    fprintf(stdout, "\nRemoving %s configuration...\n", e->name);
                    /* remove IIS module in the site (global module configuration remains) */
                    disable_module(e->web, iis_instc_file);
                    /* delete agent instance configuration directory */
                    am_delete_directory(e->path);
                    /* remove agent instance configuration */
                    am_cleanup_instance(instance_config, e->name);
                    fprintf(stdout, "\nRemoving %s configuration... Done.\n", e->name);
                    break;
                }
                case AM_I_VARNISH: {
                    //TODO
                    break;
                }
            }
        }
    }
    delete_conf_entry_list(&list);
}

static void remove_global(int argc, char **argv) {
    int rv;
    struct am_conf_entry *list = NULL, *e, *t;
    char *input = prompt_and_read("\nWarning! This procedure will remove all "DESCRIPTION" references from \nIIS Server configuration."
            "\n\nContinue (yes/no): [no]:");
    if (!ISVALID(input) || strcasecmp(input, "yes") != 0) {
        am_free(input);
        return;
    }
    am_free(input);

    rv = am_read_instances(instance_config, &list);
    if (rv > 0) {
        AM_LIST_FOR_EACH(list, e, t) {
            if (strstr(e->web, "conf") == NULL) {/* all, except Apache agent */
                char iis_instc_file[AM_URI_SIZE];
                snprintf(iis_instc_file, sizeof(iis_instc_file),
                        "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                        e->path);
                /* disable agent module in the Site */
                disable_module(e->web, iis_instc_file);
                /* delete agent instance configuration directory */
                am_delete_directory(e->path);
                /* remove agent instance configuration */
                am_cleanup_instance(instance_config, e->name);
            }
        }
    }
    delete_conf_entry_list(&list);
    fprintf(stdout, "\nRemoving agent module from IIS Server configuration...\n");
    remove_module();
    fprintf(stdout, "\nRemoving agent module from IIS Server configuration... Done.\n");
}

static void enable_iis_mod(int argc, char **argv) {
    struct am_conf_entry *list = NULL, *e, *t;
    int rv;
    if (argc != 3) {
        fprintf(stdout, "\nNo agent configuration specified.\n");
        return;
    }
    rv = am_read_instances(instance_config, &list);
    if (rv <= 0) {
        delete_conf_entry_list(&list);
        return;
    }

    AM_LIST_FOR_EACH(list, e, t) {
        if (strcmp(e->name, argv[2]) == 0) {
            if (instance_type == AM_I_IIS) {
                char iis_instc_file[AM_URI_SIZE];
                snprintf(iis_instc_file, sizeof(iis_instc_file),
                        "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                        e->path);
                fprintf(stdout, "\nEnabling %s module configuration in site %s...\n", e->name, e->web);
                enable_module(e->web, iis_instc_file);
                fprintf(stdout, "\nEnabling %s module configuration in site %s... Done.\n", e->name, e->web);
            }
        }
    }
    delete_conf_entry_list(&list);
}

static void disable_iis_mod(int argc, char **argv) {
    struct am_conf_entry *list = NULL, *e, *t;
    int rv;
    if (argc == 3) {
        fprintf(stdout, "\nNo agent configuration specified.\n");
        return;
    }

    rv = am_read_instances(instance_config, &list);
    if (rv <= 0) {
        delete_conf_entry_list(&list);
        return;
    }

    AM_LIST_FOR_EACH(list, e, t) {
        if (strcmp(e->name, argv[2]) == 0) {
            if (instance_type == AM_I_IIS) {
                char iis_instc_file[AM_URI_SIZE];
                snprintf(iis_instc_file, sizeof(iis_instc_file),
                        "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                        e->path);
                fprintf(stdout, "\nDisabling %s module configuration in site %s...\n", e->name, e->web);
                disable_module(e->web, iis_instc_file);
                fprintf(stdout, "\nDisabling %s module configuration in site %s... Done.\n", e->name, e->web);
            }
        }
    }
    delete_conf_entry_list(&list);
}

/**
 * Enable debugging, i.e. logging.  Once we do this, everything will be logged.
 */
static void enable_debug(int argc, char* argv[]) {
    zero_instance_logging_wanted(AM_TRUE);
}

static void archive_files(int argc, char **argv) {
    int i;
    time_t tv;
    struct tm fd;
    zipFile zf = NULL;
    struct am_namevalue *all = NULL, *e, *t;

    if (argc < 4) return;

    zf = zipOpen(argv[2], APPEND_STATUS_CREATE);
    if (zf == NULL) {
        return;
    }

    /* read all directory/file info (recursive) */
    for (i = 3; i < argc; i++) {
        read_directory(argv[i], &all);
    }

    time(&tv);
    localtime_r(&tv, &fd);

    if (all != NULL) {
        fprintf(stdout, "Adding to %s:\n", argv[2]);
    }

    AM_LIST_FOR_EACH(all, e, t) {
        zip_fileinfo zi;
        size_t off = 0;
        uLong file_mode = 0;
        /* fix path prefixes */
        if (e->n[0] == '/') {
            off = 1;
        }

        memset(&zi, 0, sizeof(zi));
        zi.tmz_date.tm_sec = fd.tm_sec;
        zi.tmz_date.tm_min = fd.tm_min;
        zi.tmz_date.tm_hour = fd.tm_hour;
        zi.tmz_date.tm_mday = fd.tm_mday;
        zi.tmz_date.tm_mon = fd.tm_mon;
        zi.tmz_date.tm_year = fd.tm_year;
#ifdef _WIN32
        {
            char fname[AM_URI_SIZE];
            char dir[AM_URI_SIZE];
            char drive[AM_PATH_SIZE];
            char ext[AM_PATH_SIZE];
            if (_splitpath_s(e->n,
                    drive, sizeof(drive) - 1,
                    dir, sizeof(dir) - 1,
                    fname, sizeof(fname) - 1,
                    ext, sizeof(ext) - 1) != 0) {
                continue;
            }
            if (dir[0] == '\\') {
                off = 1;
            }
            if (dir[0] == '\\' && dir[1] == '\\') {
                off = 2;
            }
            off += strlen(drive);
        }
#endif
        fprintf(stdout, "  %s\n", e->n);
#ifndef _WIN32
        if (e->ns == 1) {
            /* a directory */
            file_mode = (S_IFDIR | 0755) << 16L;
        } else {
            /* a file */
            if (strstr(e->n, "agentadmin") != NULL || strstr(e->n, ".so") != NULL) {
                file_mode = 0755 << 16L; /* we need execute bit set for these two */
            } else {
                file_mode = 0644 << 16L;
            }
        }
        zi.external_fa = file_mode;
#endif
        zipOpenNewFileInZip(zf, e->n + off, &zi,
                NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_BEST_COMPRESSION);
        if (e->ns == 1) {
            /* a directory */
            zipCloseFileInZip(zf);
        } else {
            /* a file */
            FILE *f = fopen(e->n, "rb");
            if (f != NULL) {
                int rb;
                unsigned char b[1024];
                while (!feof(f)) {
                    rb = (int) fread(b, 1, sizeof(b), f);
                    zipWriteInFileInZip(zf, b, rb);
                }
                fclose(f);
            }
            zipCloseFileInZip(zf);
        }
    }
    zipClose(zf, NULL);
    delete_am_namevalue_list(&all);
}

int main(int argc, char **argv) {
    int i;
    char tm[64];
    struct tm now;
    char instance_type_mod[AM_URI_SIZE];

    struct command_line params[] = {
        { "--i", install_interactive },
        { "--s", install_silent },
        { "--l", list_instances },
        { "--r", remove_instance },
#ifdef _WIN32
        { "--n", list_iis_sites },
        { "--g", remove_global },
        { "--e", enable_iis_mod },
        { "--d", disable_iis_mod },
#endif
        { "--v", show_version },
        { "--k", generate_key },
        { "--p", password_encrypt },
        { "--d", password_decrypt },
        { "--a", archive_files },
        { NULL }
    };

    /**
     * This is my solution to logging.  If the user defines this environment variable
     * (no matter what its value), then logging to the console is enabled.  I tried
     * a command line flag, --x, but the flags are very much "one off" and inserting
     * another command line argument throws everything out.
     */
    if (getenv("AGENT_INSTALL_DEBUG") != NULL) {
        zero_instance_logging_wanted(AM_TRUE);
    }
    
    if (argc > 1) {
        uid_t* uid = NULL;
        gid_t* gid = NULL;
        time_t tv;
        char* conf;
        
        time(&tv);
        localtime_r(&tv, &now);
        strftime(tm, sizeof(tm) - 1, "%Y%m%d%H%M%S", &now);

        /* get agentadmin path */
        am_bin_path(app_path, sizeof(app_path) - 1);

        /* create/update installer log path */
        snprintf(log_path, sizeof(log_path),
                "%s.."FILE_PATH_SEP"log",
                app_path);
        am_make_path(log_path, uid, gid);
        strcat(log_path, FILE_PATH_SEP"install_");
        strcat(log_path, tm);
        strcat(log_path, ".log");

        /* instances directory */
        snprintf(instance_path, sizeof(instance_path),
                "%s.."FILE_PATH_SEP"instances",
                app_path);

        /* agent configuration template */
        snprintf(config_template, sizeof(config_template),
                "%s.."FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf.template",
                app_path);

        /* instances configuration file (internal) */
        snprintf(instance_config, sizeof(instance_config),
                "%s.."FILE_PATH_SEP"instances"FILE_PATH_SEP".agents",
                app_path);

        /* and add a license tracker path */
        snprintf(license_tracker_path, sizeof(license_tracker_path),
                "%s.."FILE_PATH_SEP"instances"FILE_PATH_SEP".license",
                app_path);

        /* determine installer type */
        snprintf(instance_type_mod, sizeof(instance_type_mod),
                "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"mod_openam."LIB_FILE_EXT, app_path);
        if (file_exists(instance_type_mod)) {
            instance_type = AM_I_APACHE;
        }
        snprintf(instance_type_mod, sizeof(instance_type_mod),
                "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"mod_iis_openam."LIB_FILE_EXT, app_path);
        if (file_exists(instance_type_mod)) {
            instance_type = AM_I_IIS;
        }
        snprintf(instance_type_mod, sizeof(instance_type_mod),
                "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"vmod_openam."LIB_FILE_EXT, app_path);
        if (file_exists(instance_type_mod)) {
            instance_type = AM_I_VARNISH;
        }

        if (instance_type == AM_I_APACHE) {
            conf = load_file(argv[2], NULL);
            if (conf != NULL) {
                find_user(conf, &uid, &gid);
                find_group(conf, &gid);
                free(conf);
            }
        }

        /* run through the cli options */
        for (i = 0; params[i].option; ++i) {
            if (!strcasecmp(argv[1], params[i].option)) {
                params[i].handler(argc, argv);
                return 0;
            }
        }
    }

    fprintf(stdout, "\n%s\n"
            "Usage: agentadmin <option> [<arguments>]\n\n"
            "The available options are:\n\n"
            "install agent instance:\n"
            " agentadmin --i\n\n"
            "install agent instance (silent):\n"
            " agentadmin --s \"web-server configuration/file parameter\" \\\n"
            "                \"OpenAM URL\" \"Agent URL\" \"realm\" \"agent user id\" \\\n"
            "                \"path to the agent password file\"\n\n"
            "list configured agent instances:\n"
            " agentadmin --l\n\n"
#ifdef _WIN32
            "list IIS Server Sites:\n"
            " agentadmin --n\n\n"
            "remove agent module from IIS Server:\n"
            " agentadmin --g\n\n"
            "enable agent module in IIS Server site:\n"
            " agentadmin --e agent_1\n\n"
            "disable agent module in IIS Server site:\n"
            " agentadmin --d agent_1\n\n"
#endif
            "uninstall agent instance:\n"
            " agentadmin --r agent_1\n\n"
            "generate encryption key:\n"
            " agentadmin --k\n\n"
            "encrypt password:\n"
            " agentadmin --p \"key\" \"password\"\n\n"
            "build and version information:\n"
            " agentadmin --v\n\n", DESCRIPTION);

    return 0;
}
