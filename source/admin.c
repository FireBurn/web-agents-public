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
#include <shlobj.h>
#define LIB_FILE_EXT "dll"
#define APACHE_DEFAULT_CONF_FILE "c:\\Apache\\conf\\httpd.conf"
#else
#define LIB_FILE_EXT "so"
#define APACHE_DEFAULT_CONF_FILE "/opt/apache/conf/httpd.conf"
#define VARNISH_DEFAULT_VMODS_DIR "/usr/lib64/varnish/vmods"
#endif

#ifdef AM_BINARY_LICENSE
#define LICENSE_FILE ".."FILE_PATH_SEP"legal"FILE_PATH_SEP"Forgerock_License.txt"
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
#define AM_INSTALL_CONF_PATH "AM_AGENT_CONF_PATH"
#define AM_INSTALL_PDP_PATH "AM_PDP_TEMP_PATH"
#define AM_INSTALL_SSL_KEY "AM_SSL_KEY"
#define AM_INSTALL_SSL_CERT "AM_SSL_CERT"
#define AM_INSTALL_SSL_CA "AM_SSL_CA"
#define AM_INSTALL_SSL_CIPHERS "AM_SSL_CIPHERS"
#define AM_INSTALL_SSL_OPTIONS "AM_SSL_OPTIONS"
#define AM_INSTALL_SSL_KEY_PASSWORD "AM_SSL_PASSWORD"

#define RESET_INPUT_STRING(s) do { am_free(s); s = NULL; } while (0)

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
int add_directory_acl(char *site_id, char *directory, char *user);

static const char *am_container_str(int v) {
    switch (v) {
        case AM_I_APACHE: return "Apache";
        case AM_I_IIS: return "IIS";
        case AM_I_VARNISH: return "Varnish";
        default: return "Unknown";
    }
}

static int instance_type = AM_I_UNKNOWN;
static char app_path[AM_URI_SIZE];
static char log_path[AM_URI_SIZE];
static char log_path_dir[AM_URI_SIZE];
static char license_tracker_path[AM_URI_SIZE];
static char instance_path[AM_URI_SIZE];
static char instance_config[AM_URI_SIZE];
static char config_template[AM_URI_SIZE];
static char instance_config_template[AM_URI_SIZE];
static am_net_options_t net_options;

static const char* agent_4x_obsolete_properties [] =
{
    "com.forgerock.agents.nss.shutdown",
    
    "com.sun.identity.agents.config.debug.file",
    "com.sun.identity.agents.config.sslcert.dir",
    "com.sun.identity.agents.config.certdb.prefix",
    "com.sun.identity.agents.config.certdb.password",
    "com.sun.identity.agents.config.certificate.alias",
    
    "com.sun.identity.agents.config.receive.timeout",
    "com.sun.identity.agents.config.tcp.nodelay.enable",
    
    "com.sun.identity.agents.config.forward.proxy.host",
    "com.sun.identity.agents.config.forward.proxy.port",
    "com.sun.identity.agents.config.forward.proxy.user",
    "com.sun.identity.agents.config.forward.proxy.password",
    "com.sun.identity.agents.config.profilename",
    0
};

static const char *ssl_variables[] = {
    AM_INSTALL_SSL_KEY,
    AM_INSTALL_SSL_CERT,
    AM_INSTALL_SSL_CA,
    AM_INSTALL_SSL_CIPHERS,
    AM_INSTALL_SSL_OPTIONS,
    AM_INSTALL_SSL_KEY_PASSWORD
};

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
        am_net_options_delete(&net_options);
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

static am_bool_t validate_os_version() {
#ifdef _WIN32
    OSVERSIONINFOEXA osvi = {
        sizeof (osvi), 0, 0, 0, 0, { 0 }, 0, 0
    };
    DWORDLONG const mask = VerSetConditionMask(
            VerSetConditionMask(
            VerSetConditionMask(
            0, VER_MAJORVERSION, VER_GREATER_EQUAL),
            VER_MINORVERSION, VER_GREATER_EQUAL),
            VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
    osvi.dwMajorVersion = HIBYTE(_WIN32_WINNT_WIN7);
    osvi.dwMinorVersion = LOBYTE(_WIN32_WINNT_WIN7);
    osvi.wServicePackMajor = 0;
    
    return VerifyVersionInfoA(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, mask) != FALSE;
#else
    return AM_TRUE;
#endif
}

static void show_version(int argc, char **argv) {
    static const char *server_version =
#ifdef SERVER_VERSION
            SERVER_VERSION;
#else
            "";
#endif
    fprintf(stdout, "\n%s for %s Server %s\n", DESCRIPTION,
            am_container_str(instance_type), server_version);
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

static void remove_obsolete_properties(property_map_t* property_map) {
    const char** p;
    for (p = agent_4x_obsolete_properties; *p; p++) {
        if (property_map_remove_key(property_map, *p)) {
            install_log("removing obsolete property %s", *p);
        }
    }
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
                                 gid_t* gid,
                                 property_map_t* property_map) {

    FILE* f = NULL;
    int rv = AM_ERROR;
    char* created_name_path = NULL;
    char* created_name_simple = NULL;
    
    char* agent_conf_template = NULL;
    size_t agent_conf_template_sz = 0;
    
    char* agent_conf_content = NULL;
    size_t agent_conf_sz = 0;
    
    if (am_create_agent_dir(FILE_PATH_SEP, instance_path,
                            &created_name_path, &created_name_simple,
                            uid, gid, install_log) != 0) {
        install_log("failed to create agent instance configuration directories");
        AM_FREE(created_name_path, created_name_simple);
        return rv;
    }

    install_log("agent instance configuration directories created");
    
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
            char* tmp;
            char key[37];
            size_t sz = 16;

            if (log_path == NULL || audit_log_path == NULL || conf_file_path == NULL) {
                install_log("log_path, audit_log_path or conf_file_path is NULL");
                rv = AM_ENOMEM;
                break;
            }

            /* do a search-n-replace (in memory) */
            install_log("updating %s with %s", AM_INSTALL_OPENAMURL, openam_url);
            rv = string_replace(&agent_conf_template, AM_INSTALL_OPENAMURL, openam_url, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_OPENAMURL, am_strerror(rv));
                break;
            } 

            install_log("parsing %s", agent_url);
            rv = parse_url(agent_url, &u);
            if (rv != AM_SUCCESS) {
                install_log("failed to parse_url %s, %s", agent_url, am_strerror(rv));
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_AGENT_FQDN, u.host);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENT_FQDN, u.host, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_AGENT_FQDN, am_strerror(rv));
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_REALM, agent_realm);
            rv = string_replace(&agent_conf_template, AM_INSTALL_REALM, agent_realm, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_REALM, am_strerror(rv));
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_AGENTURL, agent_url);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENTURL, agent_url, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_AGENTURL, am_strerror(rv));
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_AGENTURL, agent_user);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AGENT, agent_user, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_AGENTURL, am_strerror(rv));
                break;
            }

            uuid(key, sizeof(key));
            encoded = base64_encode(key, &sz);
            install_log("updating %s with %s", AM_INSTALL_KEY, encoded);
            rv = string_replace(&agent_conf_template, AM_INSTALL_KEY, encoded, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_KEY, am_strerror(rv));
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
                install_log("updating %s with %s", AM_INSTALL_PASSWORD, password);
                rv = string_replace(&agent_conf_template, AM_INSTALL_PASSWORD, password, &agent_conf_template_sz);
                if (rv != AM_SUCCESS) {
                    install_log("failed to update %s, %s", AM_INSTALL_PASSWORD, am_strerror(rv));
                }
            }
            am_free(password);
            password = NULL;
            if (rv != AM_SUCCESS) {
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_DEBUGPATH, log_path);
            rv = string_replace(&agent_conf_template, AM_INSTALL_DEBUGPATH, log_path, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_DEBUGPATH, am_strerror(rv));
                break;
            }

            install_log("updating %s with %s", AM_INSTALL_AUDITPATH, audit_log_path);
            rv = string_replace(&agent_conf_template, AM_INSTALL_AUDITPATH, audit_log_path, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update agent configuration template file %s (%s)",
                        config_template, am_strerror(rv));
                break;
            }
            
            install_log("updating %s with %s", AM_INSTALL_PDP_PATH, log_path_dir);
            rv = string_replace(&agent_conf_template, AM_INSTALL_PDP_PATH, log_path_dir, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_PDP_PATH, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.cert_key_file)) {
                tmp = net_options.cert_key_file;
                install_log("updating %s with %s", AM_INSTALL_SSL_KEY, tmp);
            } else {
                tmp = AM_SPACE_CHAR;
                install_log("cleaning up %s", AM_INSTALL_SSL_KEY);
            }
            rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_KEY, tmp, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_SSL_KEY, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.cert_file)) {
                tmp = net_options.cert_file;
                install_log("updating %s with %s", AM_INSTALL_SSL_CERT, tmp);
            } else {
                tmp = AM_SPACE_CHAR;
                install_log("cleaning up %s", AM_INSTALL_SSL_CERT);
            }
            rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_CERT, tmp, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_SSL_CERT, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.cert_ca_file)) {
                tmp = net_options.cert_ca_file;
                install_log("updating %s with %s", AM_INSTALL_SSL_CA, tmp);
            } else {
                tmp = AM_SPACE_CHAR;
                install_log("cleaning up %s", AM_INSTALL_SSL_CA);
            }
            rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_CA, tmp, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_SSL_CA, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.ciphers)) {
                tmp = net_options.ciphers;
                install_log("updating %s with %s", AM_INSTALL_SSL_CIPHERS, tmp);
            } else {
                tmp = AM_SPACE_CHAR;
                install_log("cleaning up %s", AM_INSTALL_SSL_CIPHERS);
            }
            rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_CIPHERS, tmp, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_SSL_CIPHERS, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.tls_opts)) {
                tmp = net_options.tls_opts;
                install_log("updating %s with %s", AM_INSTALL_SSL_OPTIONS, tmp);
            } else {
                tmp = AM_SPACE_CHAR;
                install_log("cleaning up %s", AM_INSTALL_SSL_OPTIONS);
            }
            rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_OPTIONS, tmp, &agent_conf_template_sz);
            if (rv != AM_SUCCESS) {
                install_log("failed to update %s, %s", AM_INSTALL_SSL_OPTIONS, am_strerror(rv));
                break;
            }

            if (ISVALID(net_options.cert_key_pass)) {
                password = strdup(net_options.cert_key_pass);
                if (password == NULL) {
                    rv = AM_ENOMEM;
                    break;
                }

                if (encrypt_password(encoded, &password) > 0) {
                    install_log("updating %s with %s", AM_INSTALL_SSL_KEY_PASSWORD, password);
                    rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_KEY_PASSWORD, password, &agent_conf_template_sz);
                    if (rv != AM_SUCCESS) {
                        install_log("failed to update %s, %s", AM_INSTALL_SSL_KEY_PASSWORD, am_strerror(rv));
                    }
                }
                am_free(password);
                am_free(encoded);
                encoded = NULL;
                password = NULL;
                if (rv != AM_SUCCESS) {
                    break;
                }
            } else {
                am_free(encoded);
                install_log("cleaning up %s", AM_INSTALL_SSL_KEY_PASSWORD);
                rv = string_replace(&agent_conf_template, AM_INSTALL_SSL_KEY_PASSWORD, AM_SPACE_CHAR, &agent_conf_template_sz);
                if (rv != AM_SUCCESS) {
                    install_log("failed to update %s, %s", AM_INSTALL_SSL_KEY_PASSWORD, am_strerror(rv));
                    break;
                }
            }
  
            /* remove obsolete properties */
            remove_obsolete_properties(property_map);
            
            /* add updated template to the property map */
            property_map_parse(property_map, "agent 4.0 config", AM_FALSE, install_log, agent_conf_template, agent_conf_template_sz);

            /* generate file content from resulting map */
            agent_conf_content = property_map_write_to_buffer(property_map, &agent_conf_sz);
            if (!ISVALID(agent_conf_content)) {
                install_log("failed to build agent configuration file content %s (%s)");
                rv = AM_ENOMEM;
                break;
            }
            
            /* write an updated template to the agent configuration file */
            install_log("writing configuration to %s", conf_file_path);
            if (write_file(conf_file_path, agent_conf_content, agent_conf_sz) > 0) {
#ifndef _WIN32
                if (instance_type == AM_I_APACHE && uid != NULL && gid != NULL) {
                    /* update agent instance configuration file owner */
                    if (chown(conf_file_path, *uid, *gid) != 0) {
                        install_log("failed to change file %s owner to %d:%d (error: %d)",
                                conf_file_path, *uid, *gid, errno);
                    }
                    /* update global log folder owner */
                    if (chown(log_path_dir, *uid, *gid) != 0) {
                        install_log("failed to change directory %s owner to %d:%d (error: %d)",
                                log_path_dir, *uid, *gid, errno);
                    }
                }
#endif
                rv = AM_SUCCESS;
            } else {
                install_log("failed to write agent configuration to %s", conf_file_path);
                rv = AM_FILE_ERROR;
            }
            am_free(agent_conf_content);

        } while (0);

        AM_FREE(conf_file_path, log_path, audit_log_path, agent_conf_template);
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
            if (rv == AM_SUCCESS && (status == ADMIN_IIS_MOD_NONE || status == ADMIN_IIS_MOD_ERROR)) {
                char schema_file[AM_URI_SIZE];
                char lib_file[AM_URI_SIZE];
                snprintf(schema_file, sizeof (schema_file),
                        "%s.."FILE_PATH_SEP"config"FILE_PATH_SEP"mod_iis_openam_schema.xml",
                        app_path);
                snprintf(lib_file, sizeof (lib_file),
                        "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"mod_iis_openam."LIB_FILE_EXT,
                        app_path);

                /* need to add module to global configuration first */
                if (install_module(lib_file, schema_file) == 0) {
                    rv = AM_ERROR;
                } else {
                    install_log("webserver site global configuration updated");
                }
            } else {
                rv = status == ADMIN_IIS_MOD_GLOBAL ? AM_SUCCESS : AM_ERROR;
            }
            
            if (rv == AM_SUCCESS) {
                /* add read/write ACL to the agent instances directory */
                rv = add_directory_acl((char *) web_conf_path, (char *) instance_path, NULL);
                install_log("agent instance directory %s ACL (site %s) update status: %s", instance_path,
                        web_conf_path, am_strerror(rv));

                /* add read/write ACL to the agent log directory */
                rv = add_directory_acl((char *) web_conf_path, (char *) log_path_dir, NULL);
                install_log("agent log directory %s ACL (site %s) update status: %s", log_path_dir,
                        web_conf_path, am_strerror(rv));
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
#ifndef _WIN32
            if (rv == AM_SUCCESS) {
                char vmod_path[AM_URI_SIZE];
                char instance_type_mod[AM_URI_SIZE];
                char instance_conf_file[AM_URI_SIZE];
                snprintf(vmod_path, sizeof (vmod_path),
                        "%s"FILE_PATH_SEP"libvmod_am."LIB_FILE_EXT, web_conf_path);
                snprintf(instance_type_mod, sizeof (instance_type_mod),
                        "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"libvmod_am."LIB_FILE_EXT, app_path);
                snprintf(instance_conf_file, sizeof (instance_conf_file),
                        "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.conf",
                        created_name_path);

                /* cleanup existing vmods directory */
                if (file_exists(vmod_path) && unlink(vmod_path) != 0) {
                    install_log("failed to unlink %s (error: %d)", vmod_path, errno);
                }

                /* add agent (softlink) to vmods directory */
                rv = symlink(instance_type_mod, vmod_path);
                if (rv == 0) {
                    install_log("webserver vmods directory %s updated", web_conf_path);
                } else {
                    install_log("failed to update vmods directory %s (error: %d)", web_conf_path, errno);
                    rv = AM_ERROR;
                }

                if (rv == AM_SUCCESS) {
                    size_t vcl_template_sz = 0;

                    /* load instance vcl template */
                    char *vcl_template = load_file(instance_config_template, &vcl_template_sz);
                    if (vcl_template != NULL) {
                        install_log("updating %s", AM_INSTALL_CONF_PATH);

                        /* update instance vcl template */
                        rv = string_replace(&vcl_template, AM_INSTALL_CONF_PATH, instance_conf_file, &vcl_template_sz);
                        if (rv != AM_SUCCESS) {
                            install_log("failed to update instance vcl template %s (error: %s)",
                                    instance_config_template, am_strerror(rv));
                            rv = AM_ERROR;
                        } else {
                            char vcl_file[AM_URI_SIZE];

                            /* save instance vcl template to a file */
                            snprintf(vcl_file, sizeof (vcl_file),
                                    "%s"FILE_PATH_SEP"config"FILE_PATH_SEP"agent.vcl", created_name_path);
                            install_log("writing vcl configuration to %s", vcl_file);
                            if (write_file(vcl_file, vcl_template, vcl_template_sz) > 0) {
                                rv = AM_SUCCESS;
                            } else {
                                install_log("failed to write agent vcl configuration to %s", vcl_file);
                                rv = AM_ERROR;
                            }
                        }
                    }
                }
            }
#else
            install_log("unsupported platform");
            rv = AM_ERROR;
#endif
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
        am_net_options_delete(&net_options);
        exit(1);
    }
}

static am_bool_t get_yes_or_no(char * prompt, am_bool_t *response) {
    am_bool_t valid_response = AM_TRUE;
    char * input = prompt_and_read(prompt);
    check_if_quit_wanted(input);
    
    if (! ISVALID(input)) {
        *response = AM_TRUE;
    } else if (strcasecmp(input, "yes") == 0) {
        *response = AM_TRUE;
    } else if (strcasecmp(input, "no") == 0) {
        *response = AM_FALSE;
    } else {
        valid_response = AM_FALSE;
    }
    
    am_free(input);
    return valid_response;
}

/**
 * Get confirmation of a property setting
 */
static am_bool_t get_confirmation(const char *fmt, ...) {
    am_bool_t response = AM_TRUE, valid_response = AM_FALSE;
    
    do {
        va_list va;
        va_start(va, fmt);
        vprintf(fmt, va);
        va_end(va);
        
        valid_response = get_yes_or_no("Confirm this setting (Yes/No, q to quit) [Yes]:", &response);
        if (!valid_response) {
            printf("Please answer yes or no\n");
        }
        
    } while (!valid_response);
    
    return response;
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
    if (gid != NULL) {
        *gid = NULL;
    }
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

/****************************************************************************************************************/

static void install_interactive(int argc, char **argv) {
    int rv;
    int iis_status = 0;
    am_bool_t lic_accepted = AM_FALSE, validated = AM_FALSE, am_validation_skipped = AM_FALSE;
    char* input = NULL;
    char* agent_token = NULL;
    char lic_file_path[AM_URI_SIZE];
    char server_conf[AM_URI_SIZE];
    
    char* openam_url = NULL;
    char* agent_realm = NULL;
    char* agent_url = NULL;
    char* agent_user = NULL;
    char* agent_password = NULL;
    
    char* agent_password_source = NULL;

    property_map_t * property_map;
    
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

    memset(&server_conf[0], 0, sizeof(server_conf));

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
            am_make_path(instance_path, NULL, NULL, install_log);
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
        am_net_options_delete(&net_options);
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
                        am_net_options_delete(&net_options);
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
                        strncpy(server_conf, input, sizeof(server_conf) - 1);
                        install_log("server configuration file %s", server_conf);
                        error = AM_FALSE;
                    }
                    free(conf);
                } else {
                    fprintf(stdout, "\nError: unable to load the server configuration file %s.\nPlease try again.\n\n",
                            input);
                    install_log("unable to load server configuration file %s", input);
                }
#ifdef _WIN32
                am_free(uid);
                am_free(gid);
                uid = NULL;
                gid = NULL;
#else
                /**
                 * If not running as root, we cannot offer to chown directories.
                 */
                if (getuid() != 0) {
                    am_free(uid);
                    am_free(gid);
                    uid = NULL;
                    gid = NULL;
                }

                /**
                 * If we have a uid and gid by this stage, actually ask the user if they want us to chown the
                 * directories we create.  This saves a lot of guesswork looking at "Listen" values in the
                 * httpd.conf file.
                 */
                if (error == AM_FALSE && uid != NULL && gid != NULL) {
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
#endif
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
                    am_net_options_delete(&net_options);
                    exit(1);
                }

                iis_status = test_module(input);
                if (iis_status == ADMIN_IIS_MOD_LOCAL) {
                    fprintf(stdout, "\nError: this server site is already configured with %s module.\nPlease try again.\n\n", DESCRIPTION);
                    install_log("IIS server site %s is already configured with %s", NOTNULL(input), DESCRIPTION);
                } else {
                    install_log("IIS server site %s is not yet configured with %s (status: %d)",
                            NOTNULL(input), DESCRIPTION, iis_status);
                    strncpy(server_conf, input, sizeof(server_conf) - 1);
                    error = AM_FALSE;
                }

                free(input);
                
                break; /* avoid fall through into varnish */
            }
            case AM_I_VARNISH: {
#ifndef _WIN32
                input = prompt_and_read("\nEnter the complete path to Varnish server VMODS directory.\n"
                        "[ q or 'ctrl+c' to exit ]\n"
                        "Directory ["VARNISH_DEFAULT_VMODS_DIR"]:");
                check_if_quit_wanted(input);
                if (!ISVALID(input)) {
                    am_free(input);
                    input = strdup(VARNISH_DEFAULT_VMODS_DIR);
                    if (input == NULL) {
                        install_log("installation exit (memory allocation error)");
                        am_net_options_delete(&net_options);
                        exit(1);
                    }
                }
                if (file_exists(input)) {
                    strncpy(server_conf, input, sizeof (server_conf) - 1);
                    install_log("server vmods directory %s", server_conf);
                    error = AM_FALSE;
                } else {
                    fprintf(stdout, "\nError: unable to access directory %s.\nPlease try again.\n\n",
                            input);
                    install_log("unable to access server VMODS directory %s", input);
                }
                free(input);
                break;
#endif
            }
            default: {
                fprintf(stdout, "Error: unknown installation type. Exiting.\n");
                install_log("unknown installation type");
                am_net_options_delete(&net_options);
                exit(1);
            }
        }
    } while (error == AM_TRUE);

    am_bool_t outer_loop = AM_TRUE;

    am_net_init();
    
    do {
        am_bool_t upgrade = AM_FALSE;
        
        property_map = property_map_create();
        if (property_map == NULL) {
            install_log("unable to allocate property map");
            break;
        }
        /*
         * Get values parameters from existing configuration
         */
        do {
            size_t data_sz = 0;
            char *data;
            
            input = prompt_and_read("\nTo set properties from an existing configuration enter path to file\n"
                                    "[ q or 'ctrl+c' to exit, return to ignore ]\n"
                                    "Existing OpenSSOAgentBootstrap.properties file:");
            if (! ISVALID(input)) {
                break;
            }
            check_if_quit_wanted(input);
            data = load_file(input, &data_sz);
            if (data) {
                install_log("loaded configuration from file ", input);
            }
            am_free(input);
            
            if (data) {
                char* v;
                upgrade = AM_TRUE;
                
                /*
                 * get installer parameters from exiting configuration
                 */
                property_map_parse(property_map, "existing config", AM_TRUE, install_log, data, data_sz);
                free(data);
                
                /* update naming service URLs */
                if ( (v = property_map_get_value(property_map, "com.sun.identity.agents.config.naming.url")) ) {
                    /* we are going to tokenise the property value v in situ, then replace it with dst */
                    char** addr, * dst = malloc(strlen(v) + 1);
                    size_t ofs = 0;
                    
                    const char* s, * e;
                    char* brkt;
                    
                    int c = 0;
                    
                    if (!ISVALID(dst)) {
                        install_log("unable to allocate memory for naming URL list");
                        break;
                    }
                    /* reset any user input */
                    RESET_INPUT_STRING(openam_url);
                    
                    for (s = strtok_r(v, " ", &brkt); s; s = strtok_r(0, " ", &brkt)) {
                        if (c) {
                            dst[ofs++] = ' ';                  /* add separator to dst */
                        }
                        e = strstr(s, "/namingservice");        /* strip the namingservice component if there is one */
                        if (e == NULL) {
                            e = s + strlen(s);
                        }
                        memcpy(dst + ofs, s, e - s);
                        ofs += e - s;
                        
                        if (c++ == 0) {
                            openam_url = strndup(s, e - s);     /* this first one is OpenAM URL */
                        }
                    }
                    dst[ofs++] = '\0';
                    
                    install_log("setting the naming URL list to %s", dst);

                    /* replace the tokenized value with the modified result */
                    addr = property_map_get_value_addr(property_map, "com.sun.identity.agents.config.naming.url");
                    if (*addr) {
                        free(*addr);
                        *addr = dst;
                    }
                }
                
                /* agent url */
                if ( (v = property_map_get_value(property_map, "com.sun.identity.agents.config.agenturi.prefix")) ) {
                    char* e;
                    RESET_INPUT_STRING(agent_url);
                    if ( (e = strstr(v, "/amagent")) ) {
                        agent_url = strndup(v, e - v);
                    } else {
                        agent_url = strdup(v);
                    }
                }
                
                /* realm */
                if ( (v = property_map_get_value(property_map, "com.sun.identity.agents.config.organization.name")) ) {
                    am_free(agent_realm);
                    agent_realm = strdup(v);
                }
                
                /* user */
                if ( (v = property_map_get_value(property_map, "com.sun.identity.agents.config.username")) ) {
                    am_free(agent_user);
                    agent_user = strdup(v);
                }
                
                /* password cannot be preserved because the cypher is not compatible */
                property_map_remove_key(property_map, "com.sun.identity.agents.config.password");
                break;
            }
            fprintf(stdout, "Error: unable to open the configuration file\nPlease try again.\n");

        } while (1);

        /**
         * Get the URL of OpenAM and try to verify it.
         */
        do {
            int httpcode = 0;
            struct url parsed_url;
            
            if (!upgrade && ISVALID(openam_url)) {
                if (!get_confirmation("\nOpenAM server URL: %s\n", openam_url)) {
                    RESET_INPUT_STRING(openam_url);
                } else {
                    /* user answered "Yes" - will use openam_url value entered earlier, which might also mean
                     * that user wants to continue despite the fact that OpenAM is not accessible */
                    break;
                }
            }
            
            while (!ISVALID(openam_url)) {
                input = prompt_and_read("\nEnter the URL where the OpenAM server is running. Please include the\n"
                        "deployment URI also as shown below:\n"
                        "(http://openam.example.com:58080/openam)\n"
                        "[ q or 'ctrl+c' to exit ]\n"
                        "OpenAM server URL:");
                check_if_quit_wanted(input);
            
                if (ISVALID(input)) {
                    openam_url = strdup(input);
                    install_log("OpenAM URL %s", openam_url);
                }
                am_free(input);
            }
            
            /* ensure that the OpenAM URL is syntactically valid */
            /* should be able to connect to OpenAM server during installation */
            if (parse_url(openam_url, &parsed_url) == AM_ERROR) {
                fprintf(stdout, "That OpenAM URL (%s) doesn't appear to be valid\n", openam_url);
                install_log("parse_url fails the OpenAM URL \"%s\"", openam_url);
            } else if (am_url_validate(0, openam_url, &net_options, &httpcode) == AM_SUCCESS && httpcode != 0) {
                am_validation_skipped = AM_FALSE;
                break;
            } else {
                fprintf(stdout, "\nCannot connect to OpenAM at URI %s, please make sure OpenAM is started\n", openam_url);
                install_log("OpenAM at %s cannot be contacted (invalid, or not running)", openam_url);
                am_validation_skipped = AM_TRUE;
            }
            
            if (upgrade) {
                am_bool_t continue_upgrade = AM_FALSE;
                while (!get_yes_or_no("\nPlease make sure OpenAM is started and the OpenAM URL is correct.\n"
                                      "Continue upgrade (Yes/No, q to quit) [Yes]: ", &continue_upgrade)) {
                    printf("Please answer yes or no\n");
                }
                if (!continue_upgrade) {
                    install_log("installation exit because OpenAM is not running");
                    fprintf(stdout, "Exiting installation\n.");
                    am_net_options_delete(&net_options);
                    exit(1);
                }
            }

        } while (1);
        
        /**
         * Get the URL of the Agent and try to verify it is not running (if it is an Apache agent).
         */
        do {
            struct url parsed_url;
            int httpcode = 0;
            
            if (!upgrade && ISVALID(agent_url)) {
                if (!get_confirmation("\nAgent URL: %s\n", agent_url)) {
                    RESET_INPUT_STRING(agent_url);
                }
            }
            
            while (!ISVALID(agent_url)) {
                input = prompt_and_read("\nEnter the Agent URL as shown below:\n"
                        "(http://agent.example.com:1234)\n"
                        "[ q or 'ctrl+c' to exit ]\n"
                        "Agent URL:");
                check_if_quit_wanted(input);
                if (ISVALID(input)) {
                    agent_url = strdup(input);
                    install_log("Agent URL %s", agent_url);
                }
                am_free(input);
            }
            
            /* ensure the URL is syntactically valid */
            if (parse_url(agent_url, &parsed_url) == AM_ERROR) {
                fprintf(stdout, "That Agent URL (%s) doesn't appear to be valid\n", agent_url);
                install_log("parse_url fails the Agent URL \"%s\"", agent_url);
                RESET_INPUT_STRING(agent_url);
                continue;
            }
            
            /* only Apache needs to be shut down before installation */
            if (instance_type != AM_I_APACHE) {
                break;
            }

            if (am_url_validate(0, input, &net_options, &httpcode) != AM_SUCCESS) {
                /* hopefully we cannot contact because the agent is not running,
                 * rather than because the URI is complete rubbish
                 */
                break;
            }
            fprintf(stdout, "The Agent at URI %s should be stopped before installation", input);
            install_log("Agent URI %s rejected because agent is running", input);
            
            if (upgrade) {
                /* we must suspend the installation until the agent is shut down */
                am_bool_t continue_upgrade = AM_FALSE;
                while (!get_yes_or_no("\nPlease shut down the Apache HTTPD server to continue upgrade.\n"
                                      "Continue upgrade (Yes/No, q to quit) [Yes]: ", &continue_upgrade)) {
                    printf("Please answer yes or no\n");
                }
                if (!continue_upgrade) {
                    install_log("installation exit because apache is running");
                    fprintf(stdout, "Exiting installation.\n");
                    am_net_options_delete(&net_options);
                    exit(1);
                }
            }
            
        } while (1);

        /**
         * The agent profile name.  There is no way to verify this, unless we can contact OpenAM,
         * and we haven't connected in a meaningful way yet.
         */
        if (!upgrade && ISVALID(agent_user)) {
            if (!get_confirmation("\nAgent profile name: %s\n", agent_user)) {
                RESET_INPUT_STRING(agent_user);
            }
        }
        
        if (!ISVALID(agent_user)) {
            input = prompt_and_read("\nEnter the Agent profile name\n"
                    "[ q or 'ctrl+c' to exit ]\n"
                    "Agent Profile name:");
            check_if_quit_wanted(input);
            if (ISVALID(input)) {
                agent_user = strdup(input);
                install_log("Agent Profile name %s", agent_user);
            }
            am_free(input);
        }
        
        /**
         * The realm.  Again no way to verify without connecting to OpenAM.
         */
        if (!upgrade && ISVALID(agent_realm)) {
            if (!get_confirmation("\nAgent realm: %s\n", agent_realm)) {
                RESET_INPUT_STRING(agent_realm);
            }
        }
        
        if (!ISVALID(agent_realm)) {
            input = prompt_and_read("\nEnter the Agent realm/organization\n"
                    "[ q or 'ctrl+c' to exit ]\n"
                    "Agent realm/organization name: [/]:");
            check_if_quit_wanted(input);
            if (ISVALID(input)) {
                agent_realm = strdup(input);
                install_log("Agent realm/organization name %s", agent_realm);
            } else {
                agent_realm = strdup("/");
                install_log("Agent realm/organization name %s", "/");
            }
            am_free(input);
        }
        
        /**
         * Prompt for the file containing the agent password.  This we can verify -
         * the file must exist, and be readable.
         */
        if (ISVALID(agent_password_source)) {
            if (!get_confirmation("\nAgent password is taken from %s\n", agent_password_source)) {
                RESET_INPUT_STRING(agent_password_source);
                RESET_INPUT_STRING(agent_password);
            }
        }
        while (!ISVALID(agent_password_source)) {
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
                    agent_password = strdup(password_data);
                    agent_password_source = strdup(input);
                    free(password_data);
                } else {
                    install_log("unable to open password file %s", input);
                }
            }
            am_free(input);
        }
        fprintf(stdout, "\nInstallation parameters:\n\n"
                "   OpenAM URL: %s\n"
                "   Agent URL: %s\n"
                "   Agent Profile name: %s\n"
                "   Agent realm/organization name: %s\n"
                "   Agent Profile password source: %s\n\n",
                openam_url, agent_url, agent_user, agent_realm, agent_password_source);

        
        input = prompt_and_read("Confirm configuration (yes/no): [no]:");
        if (ISVALID(input) && strncasecmp(input, "y", 1) == 0) {
            outer_loop = AM_FALSE;
        } else {
            fprintf(stdout, "\nRestarting the configuration...\n");
            install_log("installation restarted");

            property_map_delete(property_map);
        }
        am_free(input);
        
    } while (outer_loop == AM_TRUE);
    
    if (am_validation_skipped) {
        install_log("configuration parameter validation skipped");
        fprintf(stdout, "\nValidating... Skipped.\n");
        validated = AM_TRUE;
    } else {
        install_log("validating configuration parameters...");
        fprintf(stdout, "\nValidating...\n");

        rv = am_agent_login(0, openam_url, agent_user, agent_password, agent_realm, &net_options,
                &agent_token, NULL, NULL, NULL);

        if (rv != AM_SUCCESS) {
            fprintf(stderr, "\nError validating OpenAM - Agent configuration.\n"
                    "See installation log %s file for more details. Exiting.\n", log_path);
            install_log("error validating OpenAM agent configuration");
        } else {
            fprintf(stdout, "\nValidating... Success.\n");
            install_log("validating configuration parameters... success");
            validated = AM_TRUE;
        }

        if (agent_token != NULL) {
            fprintf(stdout, "\nCleaning up validation data...\n");
            am_agent_logout(0, openam_url, agent_token, &net_options);
            free(agent_token);
            agent_token = NULL;
        }
    }

    if (validated) {
        fprintf(stdout, "\nCreating configuration...\n");
        /* create agent instance and modify the server configuration */

        if (instance_type == AM_I_APACHE || instance_type == AM_I_IIS || instance_type == AM_I_VARNISH) {
            rv = create_agent_instance(instance_type == AM_I_IIS ? iis_status : 0,
                    server_conf /* site id for IIS */, openam_url, agent_realm, agent_url,
                    agent_user, agent_password, uid, gid, property_map);
        } else {
            rv = AM_NOT_IMPLEMENTED;
        }

        if (rv == AM_SUCCESS) {
            fprintf(stdout, "\nInstallation complete.\n");
            install_log("installation complete");
        } else {
            fprintf(stderr, "\nInstallation failed.\n"
                    "See installation log %s file for more details. Exiting.\n", log_path);
            install_log("installation error: %s", am_strerror(rv));
        }
        
    } else {
        fprintf(stderr, "\nInstallation failed.\n"
                "See installation log %s file for more details. Exiting.\n", log_path);
        install_log("installation error");
    }

    AM_FREE(openam_url, agent_url, agent_realm, agent_user, agent_password);
    
    if (property_map) {
        property_map_delete(property_map);
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
 * argv[2] = Apache: path to httpd.conf file; IIS: SiteId; Varnish: path to VMODS directory
 * argv[3] = OpenAM URL
 * argv[4] = Agent URL
 * argv[5] = Realm
 * argv[6] = Agent name
 * argv[7] = File containing the agent password
 * argv[8] = OPTIONAL "--changeOwner" argument saying whether to change instance directory/file ownership data
 * argv[9] = OPTIONAL "--acceptLicence" argument
 * argv[10] = OPTIONAL "--forceInstall" argument.
 */
static void install_silent(int argc, char** argv) {
    char lic_file_path[AM_URI_SIZE];
    am_bool_t lic_accepted = AM_FALSE, am_validation_skipped = AM_FALSE;

    install_log("%s for %s server silent installation", DESCRIPTION,
            am_container_str(instance_type));
    fprintf(stdout, "\n%s for %s Server installation.\n\n", DESCRIPTION,
            am_container_str(instance_type));

    snprintf(lic_file_path, sizeof(lic_file_path), "%s%s", app_path, LICENSE_FILE);
    
    if ((argc > 8 && strcasecmp(argv[8], "--acceptLicence") == 0) ||
            (argc > 9 && strcasecmp(argv[9], "--acceptLicence") == 0) ||
            (argc > 10 && strcasecmp(argv[10], "--acceptLicence") == 0)) {
        install_log("license accepted with --acceptLicence option");
        am_make_path(instance_path, NULL, NULL, install_log);
        write_file(license_tracker_path, AM_SPACE_CHAR, 1);
    }
    
    if ((argc > 8 && strcasecmp(argv[8], "--forceInstall") == 0) ||
            (argc > 9 && strcasecmp(argv[9], "--forceInstall") == 0) ||
            (argc > 10 && strcasecmp(argv[10], "--forceInstall") == 0)) {
        install_log("installer run with --forceInstall option");
        am_validation_skipped = AM_TRUE;
    }

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
            am_make_path(instance_path, NULL, NULL, install_log);
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
        am_net_options_delete(&net_options);
        exit(1);
    }

    if (argc >= 8) {
        int rv = AM_ERROR;
        char validated = AM_FALSE;
        char *agent_token = NULL;
        char *agent_password;
        uid_t *uid = NULL;
        gid_t *gid = NULL;
        char *conf;

        if (instance_type == AM_I_APACHE) {
            conf = load_file(argv[2], NULL);
            if (conf != NULL) {
                find_user(conf, &uid, &gid);
                find_group(conf, &gid);
                free(conf);
            } else {
                fprintf(stderr, "\nError reading config file %s. Exiting.\n", argv[2]);
                install_log("exiting install because config file %s is not readable", argv[2]);
                am_net_options_delete(&net_options);
                exit(1);
            }
#if !defined(_WIN32)
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
            if ((argc > 8 && strcasecmp(argv[8], "--changeOwner") != 0) ||
                    (argc > 9 && strcasecmp(argv[9], "--changeOwner") != 0) ||
                    (argc > 10 && strcasecmp(argv[10], "--changeOwner") != 0)) {
                am_free(uid);
                am_free(gid);
                uid = NULL;
                gid = NULL;
            }
        }

        agent_password = load_file(argv[7], NULL);
        if (agent_password == NULL) {
            fprintf(stdout, "\nError reading password file %s. Exiting.\n", argv[7]);
            install_log("installation exit");
            am_net_options_delete(&net_options);
            exit(1);
        }

        trim(agent_password, '\n');
        trim(agent_password, '\r');

        am_net_init();

        if (am_validation_skipped) {
            install_log("configuration parameter validation skipped");
            fprintf(stdout, "\nValidating... Skipped.\n");
            validated = AM_TRUE;
        } else {
            install_log("validating configuration parameters...");
            fprintf(stdout, "\nValidating...\n");

            rv = am_agent_login(0, argv[3], argv[6], agent_password, argv[5], &net_options,
                    &agent_token, NULL, NULL, NULL);
            if (rv != AM_SUCCESS) {
                fprintf(stderr, "\nError validating OpenAM - Agent configuration.\n");
                install_log("error validating OpenAM agent configuration");
                am_free(agent_token);
            } else {
                fprintf(stdout, "\nValidating... Success.\n");
                install_log("validating configuration parameters... success");
                validated = AM_TRUE;
            }

            if (agent_token != NULL) {
                fprintf(stdout, "\nCleaning up validation data...\n");
                am_agent_logout(0, argv[3], agent_token, &net_options);
                free(agent_token);
                agent_token = NULL;
            }
        }

        if (validated) {
            fprintf(stdout, "\nCreating configuration...\n");
            property_map_t * property_map = property_map_create();
            
            if (instance_type == AM_I_APACHE || instance_type == AM_I_IIS || instance_type == AM_I_VARNISH) {
                rv = create_agent_instance(0, argv[2], argv[3], argv[5],
                        argv[4], argv[6], agent_password, uid, gid, property_map);
            } else {
                rv = AM_NOT_IMPLEMENTED;
            }

            if (rv == AM_SUCCESS) {
                fprintf(stdout, "\nInstallation complete.\n");
                install_log("installation complete");
            } else {
                fprintf(stderr, "\nInstallation failed.\n"
                        "See installation log %s file for more details. Exiting.\n", log_path);
                install_log("installation error: %s", am_strerror(rv));
            }
            
        } else {
            fprintf(stderr, "\nInstallation failed.\n"
                    "See installation log %s file for more details. Exiting.\n", log_path);
            install_log("installation error");
        }

        am_free(agent_password);

        am_net_shutdown();
    } else {
        fprintf(stderr, "\nInvalid arguments. Installation exit.\n");
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
                    /* remove AmAgentId line */
                    rv = am_cleanup_instance(e->web, "AmAgentId ");
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
                    char vmod_path[AM_URI_SIZE];
                    snprintf(vmod_path, sizeof (vmod_path),
                            "%s"FILE_PATH_SEP"libvmod_am."LIB_FILE_EXT, e->web);
                    fprintf(stdout, "\nRemoving %s configuration...\n", e->name);
                    unlink(vmod_path);
                    /* delete agent instance configuration directory */
                    am_delete_directory(e->path);
                    /* remove agent instance configuration */
                    am_cleanup_instance(instance_config, e->name);
                    fprintf(stdout, "\nRemoving %s configuration... Done.\n", e->name);
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

static void modify_ownership(int argc, char **argv) {
    int rv;
    if (argc == 4) {
        rv = add_directory_acl(NULL, argv[3], argv[2]);
        fprintf(stdout, "\nAdding \"%s\" to \"%s\" ACLs with status: %s.\n",
                argv[2], argv[3], am_strerror(rv));
    }
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
        { "--o", modify_ownership },
#endif
        { "--v", show_version },
        { "--k", generate_key },
        { "--p", password_encrypt },
        { "--d", password_decrypt },
        { "--a", archive_files },
        { NULL }
    };
    
    if (!validate_os_version()) {
#ifdef _WIN32
        fprintf(stderr, "\nYou are running unsupported Microsoft Windows OS version.\n"
                DESCRIPTION" supports Microsoft Windows 2008R2 or newer.\n\n");
#endif
        exit(1);
    }

#ifdef _WIN32
    if (argc > 1 && strcmp(argv[1], "--v") != 0 && strcmp(argv[1], "--a") != 0
            && strcmp(argv[1], "--k") != 0 && strcmp(argv[1], "--p") != 0
            && strcmp(argv[1], "--d") != 0
            && !IsUserAnAdmin()) {
        fprintf(stderr, "\nYou need Administrator privileges to run "DESCRIPTION" agentadmin.\n\n");
        exit(1);
    }
#endif
    
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
        strcpy(log_path_dir, log_path);
        am_make_path(log_path, uid, gid, install_log);
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
                "%s.."FILE_PATH_SEP"lib"FILE_PATH_SEP"libvmod_am."LIB_FILE_EXT, app_path);
        if (file_exists(instance_type_mod)) {
            snprintf(instance_config_template, sizeof (instance_config_template),
                    "%s.."FILE_PATH_SEP"config"FILE_PATH_SEP"agent.vcl.template",
                    app_path);
            instance_type = AM_I_VARNISH;
        }
        
#ifndef _WIN32
        /* find user and group for non-windows installation */
        if (instance_type == AM_I_APACHE && argc > 2) {
            conf = load_file(argv[2], NULL);
            if (conf != NULL) {
                find_user(conf, &uid, &gid);
                find_group(conf, &gid);
                free(conf);
            }
        }
#endif

        /* read environment variables and create am_net_options */
        memset(&net_options, 0, sizeof (am_net_options_t));
        for (i = 0; i < ARRAY_SIZE(ssl_variables); i++) {
            char *env = getenv(ssl_variables[i]);
            if (ISVALID(env)) {
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_KEY) == 0) {
                    net_options.cert_key_file = strdup(env);
                }
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_CERT) == 0) {
                    net_options.cert_file = strdup(env);
                }
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_CA) == 0) {
                    net_options.cert_ca_file = strdup(env);
                }
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_CIPHERS) == 0) {
                    net_options.ciphers = strdup(env);
                }
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_OPTIONS) == 0) {
                    net_options.tls_opts = strdup(env);
                }
                if (strcmp(ssl_variables[i], AM_INSTALL_SSL_KEY_PASSWORD) == 0) {
                    net_options.cert_key_pass = strdup(env);
                    if (net_options.cert_key_pass != NULL) {
                        net_options.cert_key_pass_sz = strlen(net_options.cert_key_pass);
                    }
                }
            }
        }
        net_options.keepalive = net_options.local = net_options.cert_trust = AM_TRUE;
        net_options.log = install_log;

        /* run through the cli options */
        for (i = 0; params[i].option; ++i) {
            if (!strcasecmp(argv[1], params[i].option)) {
                params[i].handler(argc, argv);
                am_net_options_delete(&net_options);
                return 0;
            }
        }
    }

    fprintf(stdout, "\n%s\n"
            "Usage: agentadmin <option> [<arguments>]\n\n"
            "The available options are:\n\n"
            "Install agent instance (interactive):\n"
            " agentadmin --i\n\n"
            "Install agent instance (silent):\n"
            " agentadmin --s \"web-server configuration file, directory or site parameter\" \\\n"
            "                \"OpenAM URL\" \"Agent URL\" \"realm\" \"agent user id\" \\\n"
            "                \"path to the agent password file\" [--changeOwner] [--acceptLicence] [--forceInstall]\n\n"
            "List configured agent instances:\n"
            " agentadmin --l\n\n"
#ifdef _WIN32
            "List IIS Server Sites:\n"
            " agentadmin --n\n\n"
            "Remove agent module from IIS Server:\n"
            " agentadmin --g\n\n"
            "Enable agent module in IIS Server site:\n"
            " agentadmin --e agent_1\n\n"
            "Disable agent module in IIS Server site:\n"
            " agentadmin --d agent_1\n\n"
            "Modify Access Control Lists (ACLs) for files and folders:\n"
            " agentadmin --o \"IIS APPPOOL\\AgentSite\" \"C:\\web_agents\\iis_agent\\instances\"\n\n"
#endif
            "Uninstall agent instance:\n"
            " agentadmin --r agent_1\n\n"
            "Generate encryption key:\n"
            " agentadmin --k\n\n"
            "Encrypt password:\n"
            " agentadmin --p \"key\" \"password\"\n\n"
            "Build and version information:\n"
            " agentadmin --v\n\n", DESCRIPTION);

    am_net_options_delete(&net_options);
    return 0;
}
