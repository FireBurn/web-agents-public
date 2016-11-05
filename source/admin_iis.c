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
 * Copyright 2014 - 2016 ForgeRock AS.
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS

#include "platform.h"
#include "am.h"
#include "utility.h"
#include <objbase.h>
#include <oleauto.h>
#include <ahadmin.h>
#include <accctrl.h>
#include <aclapi.h>

#define IIS_SCHEMA_CONF_FILE "\\inetsrv\\config\\schema\\mod_iis_openam_schema.xml"
#define AM_IIS_APPHOST L"MACHINE/WEBROOT/APPHOST"
#define AM_IIS_SITES L"system.applicationHost/sites"
#define AM_IIS_POOLS L"system.applicationHost/applicationPools"
#define AM_IIS_GLOBAL L"system.webServer/globalModules"
#define AM_IIS_MODULES L"system.webServer/modules"
#define AM_IIS_MODULE_CONF L"system.webServer/OpenAmModule"
#define AM_IIS_ENAME L"name"
#define AM_IIS_EADD L"add"
#define AM_IIS_EID L"id"
#define AM_IIS_E32BIT L"enable32BitAppOnWin64"
#define AM_IIS_EPOOL L"applicationPool"
#define AM_IIS_EPATH L"path"
#define AM_IIS_MODULE_NAME L"OpenAmModule"
#define AM_IIS_MODULE_NAME64 AM_IIS_MODULE_NAME L"64"

static BOOL add_to_modules(IAppHostWritableAdminManager* manager, BSTR config_path, const char* siteid);
static char *get_site_application_pool(const char *site_id);
static char *get_property_value_byname(IAppHostElement* ahe, VARIANT* value, BSTR name, VARTYPE type);

typedef void (WINAPI * GET_SYS_INFO)(LPSYSTEM_INFO);

static DWORD hr_to_winerror(HRESULT hr) {
    if ((hr & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0)) {
        return HRESULT_CODE(hr);
    }
    return hr == S_OK ? ERROR_SUCCESS : ERROR_CAN_NOT_COMPLETE;
}

static void show_windows_error(DWORD err) {
    LPVOID e = NULL;
    if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) & e, 0, NULL) != 0) {
        char *p = strchr(e, '\r');
        if (p != NULL)
            *p = '\0';
        fprintf(stderr, "%s (error: %#x)\n", e, err);
    } else {
        fprintf(stderr, "[Could not find a description for error %#x]\n", err);
    }
    if (e) LocalFree(e);
}

static BOOL is_win64() {
    SYSTEM_INFO info;
    ZeroMemory(&info, sizeof (SYSTEM_INFO));
    GET_SYS_INFO native = (GET_SYS_INFO) GetProcAddress(GetModuleHandle("kernel32.dll"), "GetNativeSystemInfo");
    if (native != NULL) {
        native(&info);
    } else {
        GetSystemInfo(&info);
    }
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        return TRUE;
    }
    return FALSE;
}

static char *utf8_encode(const wchar_t *wstr, int *iolen) {
    char *tmp;
    int out_len, len;

    if (iolen == NULL || *iolen <= 0) return NULL;
    len = *iolen;

    out_len = WideCharToMultiByte(CP_UTF8, 0, wstr, len, NULL, 0, NULL, NULL);
    *iolen = 0;
    if (out_len <= 0) return NULL;

    tmp = (char *) malloc(out_len + 1);
    if (tmp == NULL) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, wstr, len, tmp, out_len, NULL, NULL);
    tmp[out_len] = 0;
    *iolen = out_len;
    return tmp;
}

static wchar_t *utf8_decode(const char *str) {
    wchar_t *tmp;
    int out_len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (out_len <= 0) return NULL;

    tmp = (wchar_t *) malloc(sizeof (wchar_t) * out_len);
    if (tmp == NULL) return NULL;

    MultiByteToWideChar(CP_UTF8, 0, str, -1, tmp, out_len);
    tmp[out_len - 1] = 0;
    return tmp;
}

/**
 * Test that site runs in 32 bit application pool.
 *
 * @param site_id: site id
 * 
 * @return TRUE when site/application pool runs in 32 bit mode else FALSE
 */
static BOOL is_site_32bit(const char *site_id) {
    HRESULT hr;
    IAppHostWritableAdminManager *admin_manager = NULL;
    IAppHostElement *he = NULL, *ce = NULL;
    IAppHostElementCollection *hec = NULL;
    DWORD i, num;
    BOOL found;

    /* check if we are running on 32 or 64 bit Windows OS */
    BOOL win64bit = is_win64();
    /* get application pool name */
    char *pool_name = get_site_application_pool(site_id);
    if (ISINVALID(pool_name)) {
        /* error: default to TRUE on 32bit Windows as all application pools are 32bit, FALSE on 64bit */
        fprintf(stderr, "Failed to get application pool name for Site %s.\n", site_id);
        return !win64bit;
    }

    do {
        /* create AdminManager instance */
        hr = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hr)) {
            break;
        }
        /* get application pool section */
        hr = IAppHostWritableAdminManager_GetAdminSection(admin_manager, AM_IIS_POOLS, AM_IIS_APPHOST, &he);
        if (FAILED(hr) || he == NULL) {
            break;
        }
        /* prepare Collection iterator */
        hr = IAppHostElement_get_Collection(he, &hec);
        if (FAILED(hr)) {
            break;
        }
        hr = IAppHostElementCollection_get_Count(hec, &num);
        if (FAILED(hr)) {
            break;
        }

        for (i = 0; i < num; i++) {
            VARIANT index, value;
            VariantInit(&value);
            VariantInit(&index);
            index.vt = VT_UINT;
            index.uintVal = i;
            /* read Collection item and test whether it (pool) is configured in 32 bit mode */
            hr = IAppHostElementCollection_get_Item(hec, index, &ce);
            if (SUCCEEDED(hr)) {
                char *val = get_property_value_byname(ce, &value, AM_IIS_ENAME, VT_BSTR);

                /* pool_name consists of a fixed 'IIS APPPOOL\\' prefix and a pool name */
                found = strcmp(pool_name + 12, NOTNULL(val)) == 0;
                am_free(val);
                val = NULL;
                if (!found) continue;

                val = get_property_value_byname(ce, &value, AM_IIS_E32BIT, VT_BOOL);
                found = strcmp(NOTNULL(val), "true") == 0;
                am_free(val);
            }
            if (ce != NULL) {
                IAppHostElement_Release(ce);
                ce = NULL;
            }
            VariantClear(&index);
            VariantClear(&value);
            if (found) break;
        }

    } while (FALSE);

    if (FAILED(hr)) {
        show_windows_error(hr_to_winerror(hr));
    }

    if (he != NULL) {
        IAppHostElement_Release(he);
    }
    if (hec != NULL) {
        IAppHostElementCollection_Release(hec);
    }
    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }

    /* status: always TRUE on 32bit Windows, 'found' value otherwise */
    return win64bit ? found : TRUE;
}

/**
 * Get AppHostElement property value.
 */
static char *get_property_value_byname(IAppHostElement* ahe, VARIANT* value, BSTR name, VARTYPE type) {
    IAppHostProperty *property = NULL;
    HRESULT hresult;
    char *ret = NULL;

    hresult = IAppHostElement_GetPropertyByName(ahe, name, &property);
    if (FAILED(hresult) || property == NULL) {
        fwprintf(stderr, L"get_property_value_byname(%s) failed. Property not found.\n", name);
        return NULL;
    }
    hresult = IAppHostProperty_get_Value(property, value);
    if (FAILED(hresult)) {
        fwprintf(stderr, L"get_property_value_byname(%s) failed. Value not set.\n", name);
        if (property != NULL) {
            IAppHostProperty_Release(property);
        }
        return NULL;
    }
    if (value->vt != type) {
        fwprintf(stderr, L"get_property_value_byname(%s) failed. Property type %d differs from type expected %d.",
                name, value->vt, type);
        if (property != NULL) {
            IAppHostProperty_Release(property);
        }
        return NULL;
    }

    if (type == VT_BOOL) {
        am_asprintf(&ret, "%s", value->boolVal == VARIANT_TRUE ? "true" : "false");
    } else if (type == VT_UI4) {
        am_asprintf(&ret, "%d", value->ulVal);
    } else {
        int len = SysStringLen(value->bstrVal);
        ret = utf8_encode(value->bstrVal, &len);
    }
    if (property != NULL) {
        IAppHostProperty_Release(property);
    }
    return ret;
}

/**
 * List all IIS sites.
 */
void list_iis_sites(int argc, char **argv) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    IAppHostElement *he = NULL, *ce = NULL;
    IAppHostElementCollection *hec = NULL;
    DWORD i, num;
    HRESULT hresult;
    char *name, *id;

    fprintf(stdout, "\nIIS Site configuration:\n");

    do {
        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostWritableAdminManager_GetAdminSection(admin_manager, AM_IIS_SITES, AM_IIS_APPHOST, &he);
        if (FAILED(hresult) || he == NULL) {
            break;
        }
        hresult = IAppHostElement_get_Collection(he, &hec);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostElementCollection_get_Count(hec, &num);
        if (FAILED(hresult)) {
            break;
        }

        fprintf(stdout, "\nNumber of Sites: %d\n\n", num);

        for (i = 0; i < num; i++) {
            VARIANT index, value;
            VariantInit(&index);
            VariantInit(&value);
            index.vt = VT_UINT;
            index.uintVal = i;
            hresult = IAppHostElementCollection_get_Item(hec, index, &ce);
            if (SUCCEEDED(hresult)) {
                name = get_property_value_byname(ce, &value, AM_IIS_ENAME, VT_BSTR);
                id = get_property_value_byname(ce, &value, AM_IIS_EID, VT_UI4);
                if (name != NULL && id != NULL) {
                    char *p;
                    for (p = name; *p != '\0'; ++p) {
                        *p = toupper(*p);
                    }
                    fprintf(stdout, "id: %s\tname: \"%s\"\n", id, name);
                }
                AM_FREE(name, id);
                name = NULL;
                id = NULL;
            }
            if (ce != NULL) {
                IAppHostElement_Release(ce);
            }
            VariantClear(&index);
            VariantClear(&value);
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (he != NULL) {
        IAppHostElement_Release(he);
    }
    if (hec != NULL) {
        IAppHostElementCollection_Release(hec);
    }
    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
}

/**
 * Set AppHostElement property value.
 */
static BOOL set_property(IAppHostElement* element, BSTR name, BSTR value) {
    IAppHostProperty* property = NULL;
    HRESULT hresult;
    VARIANT value_variant;

    VariantInit(&value_variant);
    value_variant.vt = VT_BSTR;
    value_variant.bstrVal = SysAllocString(value);

    do {
        if (value_variant.bstrVal == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        hresult = IAppHostElement_GetPropertyByName(element, name, &property);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to get property.\n");
            break;
        }

        hresult = IAppHostProperty_put_Value(property, value_variant);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to set property value.\n");
            break;
        }
    } while (FALSE);

    if (property != NULL) {
        IAppHostProperty_Release(property);
    }
    VariantClear(&value_variant);
    return SUCCEEDED(hresult);
}

/**
 * Get AppHostElement property value.
 */
static BOOL get_property(IAppHostElement* element, BSTR name, VARIANT* value) {
    IAppHostProperty* property = NULL;
    HRESULT hresult;
    do {
        hresult = IAppHostElement_GetPropertyByName(element, name, &property);
        if (FAILED(hresult)) {
            fwprintf(stderr, L"Failed to get property: %s.\n", name);
            break;
        }
        hresult = IAppHostProperty_get_Value(property, value);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to get property value.\n");
            break;
        }
    } while (FALSE);

    if (property != NULL) {
        IAppHostProperty_Release(property);
    }
    return SUCCEEDED(hresult);
}

/**
 * Get indexed AppHostElementCollection property value.
 */
static BOOL get_from_collection_idx(IAppHostElementCollection* collection,
        BSTR property_key, BSTR property_value, short* index) {
    IAppHostElement* element = NULL;
    USHORT i;
    DWORD count;
    HRESULT hresult;

    *index = -1;
    do {
        hresult = IAppHostElementCollection_get_Count(collection, &count);
        if (FAILED(hresult)) {
            fprintf(stderr, "Unable to get the count of collection.\n");
            break;
        }

        for (i = 0; i < count; ++i) {
            VARIANT var_value, idx;
            VariantInit(&idx);
            idx.vt = VT_I2;
            idx.iVal = i;
            hresult = IAppHostElementCollection_get_Item(collection, idx, &element);
            VariantClear(&idx);
            if (FAILED(hresult)) {
                fprintf(stderr, "Unable to get item (%d).\n", i);
                break;
            }

            VariantInit(&var_value);
            if (!get_property(element, property_key, &var_value)) {
                VariantClear(&var_value);
                fprintf(stderr, "Failed to get property value.\n");
                hresult = S_FALSE;
                break;
            }

            if (wcscmp(property_value, var_value.bstrVal) == 0) {
                VariantClear(&var_value);
                *index = i;
                break;
            }

            VariantClear(&var_value);
            IAppHostElement_Release(element);
            element = NULL;
        }
    } while (FALSE);

    if (element != NULL) {
        IAppHostElement_Release(element);
    }

    return SUCCEEDED(hresult);
}

/**
 * Get AppHostElement from AppHostElementCollection (by property key/value).
 */
static BOOL get_from_collection(IAppHostElementCollection* collection,
        BSTR property_key, BSTR property_value, IAppHostElement** element) {
    short idx;
    HRESULT hresult;
    if (!get_from_collection_idx(collection, property_key, property_value, &idx)) {
        fprintf(stderr, "Failed to get child from collection.\n");
    }

    if (idx != -1) {
        VARIANT idx_var;
        VariantInit(&idx_var);
        idx_var.vt = VT_I2;
        idx_var.iVal = idx;
        hresult = IAppHostElementCollection_get_Item(collection, idx_var, element);
        VariantClear(&idx_var);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to get element from collection.\n");
            return FALSE;
        }
        return TRUE;
    }

    *element = NULL;
    return TRUE;
}

/**
 * Update AdminManager configuration section with module name.
 */
static BOOL update_config_sections(IAppHostWritableAdminManager* manager, BSTR mod_name) {
    IAppHostConfigManager *cmgr = NULL;
    IAppHostConfigFile *cfile = NULL;
    IAppHostSectionGroup *root = NULL;
    IAppHostSectionGroup *swsg = NULL;
    IAppHostSectionDefinitionCollection *swsgcol = NULL;
    IAppHostSectionDefinition *modsec = NULL;
    HRESULT hresult;
    BOOL result = FALSE;
    VARIANT sys_ws_gn;
    VARIANT msn;

    VariantInit(&sys_ws_gn);
    sys_ws_gn.vt = VT_BSTR;
    sys_ws_gn.bstrVal = SysAllocString(L"system.webServer");
    VariantInit(&msn);
    msn.vt = VT_BSTR;
    msn.bstrVal = SysAllocString(mod_name);

    do {
        if (sys_ws_gn.bstrVal == NULL || msn.bstrVal == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            hresult = E_OUTOFMEMORY;
            break;
        }
        hresult = IAppHostWritableAdminManager_get_ConfigManager(manager, &cmgr);
        if (FAILED(hresult) || &cmgr == NULL) {
            fprintf(stderr, "Unable to get config manager.\n");
            break;
        }

        hresult = IAppHostConfigManager_GetConfigFile(cmgr, AM_IIS_APPHOST, &cfile);
        if (FAILED(hresult) || &cfile == NULL) {
            fprintf(stderr, "Unable to get config file.\n");
            break;
        }

        hresult = IAppHostConfigFile_get_RootSectionGroup(cfile, &root);
        if (FAILED(hresult) || &root == NULL) {
            fprintf(stderr, "Unable to get root section group.\n");
            break;
        }

        hresult = IAppHostSectionGroup_get_Item(root, sys_ws_gn, &swsg);
        if (FAILED(hresult) || &swsg == NULL) {
            fprintf(stderr, "Unable to get system.webServer section group.\n");
            break;
        }

        hresult = IAppHostSectionGroup_get_Sections(swsg, &swsgcol);
        if (FAILED(hresult) || &swsgcol == NULL) {
            fprintf(stderr, "Unable to get system.webServer section group collection.\n");
            break;
        }

        hresult = IAppHostSectionDefinitionCollection_get_Item(swsgcol, msn, &modsec);
        if (FAILED(hresult) || modsec == NULL) {
            hresult = IAppHostSectionDefinitionCollection_AddSection(swsgcol, mod_name, &modsec);
            if (FAILED(hresult) || modsec == NULL) {
                fprintf(stderr, "Unable to add module section entry.\n");
            } else {
                result = TRUE;
            }
        } else {
            result = TRUE;
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (modsec != NULL) {
        IAppHostSectionDefinitionCollection_Release(modsec);
    }
    if (swsgcol != NULL) {
        IAppHostSectionGroup_Release(swsgcol);
    }
    if (swsg != NULL) {
        IAppHostSectionGroup_Release(swsg);
    }
    if (root != NULL) {
        IAppHostConfigFile_Release(root);
    }
    if (cfile != NULL) {
        IAppHostConfigManager_Release(cfile);
    }
    if (cmgr != NULL) {
        IAppHostWritableAdminManager_Release(cmgr);
    }
    VariantClear(&sys_ws_gn);
    VariantClear(&msn);

    return result;
}

/**
 * Update AdminManager global configuration section with module image location.
 */
static BOOL add_to_global_modules(IAppHostWritableAdminManager* manager, BSTR image, BOOL btype) {
    IAppHostElement* parent = NULL;
    IAppHostElementCollection* collection = NULL;
    IAppHostElement* element = NULL;
    HRESULT hresult;
    BOOL result = FALSE;

    do {
        hresult = IAppHostWritableAdminManager_GetAdminSection(manager, AM_IIS_GLOBAL, AM_IIS_APPHOST, &parent);
        if (FAILED(hresult) || &parent == NULL) {
            fprintf(stderr, "Unable to get globalModules configuration.\n");
            break;
        }

        hresult = IAppHostElement_get_Collection(parent, &collection);
        if (FAILED(hresult) || &collection == NULL) {
            fprintf(stderr, "Unable to get globalModules child collection.\n");
            break;
        }

        /* create a global modules child element, like:
         * <add name="ModuleName", image="module.dll" />
         **/

        if (!get_from_collection(collection, AM_IIS_ENAME, btype ? AM_IIS_MODULE_NAME64 : AM_IIS_MODULE_NAME, &element)) {
            fprintf(stderr, "Failed to try detect old modules.\n");
            break;
        }

        if (element == NULL) {
            hresult = IAppHostElementCollection_CreateNewElement(collection, AM_IIS_EADD, &element);
            if (FAILED(hresult)) {
                fprintf(stderr, "Failed to create globalModules/add element.\n");
                break;
            }

            if (!set_property(element, AM_IIS_ENAME, btype ? AM_IIS_MODULE_NAME64 : AM_IIS_MODULE_NAME)) {
                fprintf(stderr, "Failed to set name property.\n");
                break;
            }

            if (!set_property(element, L"preCondition", btype ? L"bitness64" : L"bitness32")) {
                fprintf(stderr, "Failed to set preCondition property.\n");
                break;
            }

            hresult = IAppHostElementCollection_AddElement(collection, element, -1);
            if (FAILED(hresult)) {
                fprintf(stderr, "Failed to add globalModule/add element.\n");
                break;
            }
        }

        if (!set_property(element, L"image", image)) {
            fprintf(stderr, "Failed to set image property.\n");
            break;
        }

        result = TRUE;
    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (element != NULL) {
        IAppHostElement_Release(element);
    }
    if (collection != NULL) {
        IAppHostElementCollection_Release(collection);
    }
    if (parent != NULL) {
        IAppHostElement_Release(parent);
    }
    return result;
}

/**
 * Update AdminManager site configuration section with module configuration.
 */
static BOOL update_module_site_config(IAppHostWritableAdminManager* manager,
        BSTR config_path, BSTR mod_config_path, BOOL enabled) {
    IAppHostElement *element = NULL;
    IAppHostPropertyCollection *properties = NULL;
    IAppHostProperty *enabled_prop = NULL;
    IAppHostProperty *cfile_prop = NULL;
    HRESULT hresult;
    BOOL result = FALSE;
    VARIANT a, av, b, bv;

    VariantInit(&a);
    VariantInit(&av);
    VariantInit(&b);
    VariantInit(&bv);
    av.vt = VT_BOOL;
    av.boolVal = enabled ? VARIANT_TRUE : VARIANT_FALSE;
    a.vt = VT_BSTR;
    a.bstrVal = SysAllocString(L"enabled");
    b.vt = VT_BSTR;
    b.bstrVal = SysAllocString(L"configFile");
    bv.vt = VT_BSTR;
    bv.bstrVal = SysAllocString(mod_config_path);

    do {
        if (a.bstrVal == NULL || b.bstrVal == NULL || bv.bstrVal == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            hresult = E_OUTOFMEMORY;
            break;
        }
        hresult = IAppHostWritableAdminManager_GetAdminSection(manager,
                AM_IIS_MODULE_CONF, config_path, &element);
        if (FAILED(hresult) || &element == NULL) {
            fprintf(stderr, "Unable to get module configuration element.\n");
            break;
        }

        hresult = IAppHostElement_get_Properties(element, &properties);
        if (FAILED(hresult) || &properties == NULL) {
            fprintf(stderr, "Unable to get module element properties.\n");
            break;
        }

        hresult = IAppHostPropertyCollection_get_Item(properties, a, &enabled_prop);
        if (FAILED(hresult) || &enabled_prop == NULL) {
            fprintf(stderr, "Unable to get module element properties item (enabled).\n");
            break;
        }
        hresult = IAppHostProperty_put_Value(enabled_prop, av);
        if (FAILED(hresult)) {
            fprintf(stderr, "Unable to set module element properties item (enabled).\n");
            break;
        }

        hresult = IAppHostPropertyCollection_get_Item(properties, b, &cfile_prop);
        if (FAILED(hresult) || &cfile_prop == NULL) {
            fprintf(stderr, "Unable to get module element properties item (configFile).\n");
            break;
        }
        hresult = IAppHostProperty_put_Value(cfile_prop, bv);
        if (FAILED(hresult)) {
            fprintf(stderr, "Unable to set module element properties item (configFile).\n");
            break;
        }
        result = TRUE;
    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (cfile_prop != NULL) {
        IAppHostPropertyCollection_Release(cfile_prop);
    }
    if (enabled_prop != NULL) {
        IAppHostPropertyCollection_Release(enabled_prop);
    }
    if (properties != NULL) {
        IAppHostElement_Release(properties);
    }
    if (element != NULL) {
        IAppHostElement_Release(element);
    }
    VariantClear(&a);
    VariantClear(&av);
    VariantClear(&b);
    VariantClear(&bv);
    return result;
}

/**
 * Remove module from AdminManager configuration section.
 */
static BOOL remove_from_modules(IAppHostWritableAdminManager* manager, BSTR config_path,
        BSTR section, BOOL test_only) {
    IAppHostElement* parent = NULL;
    IAppHostElementCollection* collection = NULL;
    IAppHostElement* element = NULL;
    IAppHostProperty* name_property = NULL;
    HRESULT hresult;
    BOOL result = FALSE;
    short sitemap_index;
    DWORD rv = 0;
    do {
        hresult = IAppHostWritableAdminManager_GetAdminSection(manager, section,
                config_path, &parent);
        if (FAILED(hresult) || &parent == NULL) {
            fprintf(stderr, "Unable to get section to remove module.\n");
            break;
        }

        hresult = IAppHostElement_get_Collection(parent, &collection);
        if (FAILED(hresult) || &collection == NULL) {
            fprintf(stderr, "Unable to get collection to remove module.\n");
            break;
        }

        rv = get_from_collection_idx(collection, AM_IIS_ENAME, AM_IIS_MODULE_NAME, &sitemap_index);
        if (rv) {
            if (test_only) {
                result = sitemap_index != -1;
            } else if (sitemap_index != -1) {
                VARIANT var_index;
                VariantInit(&var_index);
                var_index.vt = VT_I2;
                var_index.iVal = sitemap_index;
                hresult = IAppHostElementCollection_DeleteElement(collection, var_index);
                if (FAILED(hresult)) {
                    fprintf(stderr, "Failed to remove OpenAM module.\n");
                }
                VariantClear(&var_index);
                result = SUCCEEDED(hresult);
            }
        }

        rv = get_from_collection_idx(collection, AM_IIS_ENAME, AM_IIS_MODULE_NAME64, &sitemap_index);
        if (rv) {
            if (test_only) {
                result = sitemap_index != -1;
            } else if (sitemap_index != -1) {
                VARIANT var_index;
                VariantInit(&var_index);
                var_index.vt = VT_I2;
                var_index.iVal = sitemap_index;
                hresult = IAppHostElementCollection_DeleteElement(collection, var_index);
                if (FAILED(hresult)) {
                    fprintf(stderr, "Failed to remove OpenAM module.\n");
                }
                VariantClear(&var_index);
                result = SUCCEEDED(hresult);
            }
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (name_property != NULL) {
        IAppHostProperty_Release(name_property);
    }
    if (element != NULL) {
        IAppHostElement_Release(element);
    }
    if (collection != NULL) {
        IAppHostElementCollection_Release(collection);
    }
    if (parent != NULL) {
        IAppHostElement_Release(parent);
    }
    return result;
}

/**
 * Concatenate module prefix with suffix values and convert them to BSTR.
 */
static BSTR create_module_path(const char *prefix, const char *suffix) {
    BSTR ret;
    char *temp = NULL;
    am_asprintf(&temp, "%s%s", prefix, suffix);
    if (temp == NULL) return NULL;
    ret = utf8_decode(temp);
    free(temp);
    return ret;
}

/**
 * Install module and configuration schema.
 */
int install_module(const char *modpath, const char *schema) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    int rv = 0;
    BSTR module_wpath;
    HRESULT hresult;
    char schema_sys_file[MAX_PATH];

    if (GetWindowsDirectoryA(schema_sys_file, MAX_PATH) == 0) {
        fprintf(stderr, "Failed to locate Windows directory.\n");
        return rv;
    }

    if (is_win64()) {
        strcat(schema_sys_file, "\\Sysnative");
    } else {
        strcat(schema_sys_file, "\\System32");
    }
    strcat(schema_sys_file, IIS_SCHEMA_CONF_FILE);

    do {
        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create AppHostWritableAdminManager.\n");
            break;
        }

        if (!file_exists(schema_sys_file)) {
            rv = CopyFileExA(schema, schema_sys_file, NULL, NULL, FALSE, COPY_FILE_NO_BUFFERING) != 0;
            if (!rv) {
                fprintf(stderr, "Failed to create configuration schema.\n");
                show_windows_error(GetLastError());
                break;
            }
        }

        hresult = IAppHostWritableAdminManager_put_CommitPath(admin_manager, AM_IIS_APPHOST);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to put commit path.\n");
            break;
        }

        module_wpath = create_module_path(modpath, "32.dll");
        if (module_wpath == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        rv = add_to_global_modules(admin_manager, module_wpath, FALSE) &&
                update_config_sections(admin_manager, AM_IIS_MODULE_NAME);
        free(module_wpath);
        if (!rv) {
            fprintf(stderr, "Failed to add 32bit entry to globalModules.\n");
            break;
        }

        module_wpath = create_module_path(modpath, "64.dll");
        if (module_wpath == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        rv = add_to_global_modules(admin_manager, module_wpath, TRUE) &&
                update_config_sections(admin_manager, AM_IIS_MODULE_NAME64);
        free(module_wpath);
        if (!rv) {
            fprintf(stderr, "Failed to add 64bit entry to globalModules.\n");
            break;
        }

        hresult = IAppHostWritableAdminManager_CommitChanges(admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to save module configuration changes.\n");
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return rv;
}

/**
 * Remove module.
 */
int remove_module() {
    IAppHostWritableAdminManager *admin_manager = NULL;
    int rv = 0;
    HRESULT hresult;

    do {
        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create AppHostWritableAdminManager.\n");
            break;
        }

        hresult = IAppHostWritableAdminManager_put_CommitPath(admin_manager, AM_IIS_APPHOST);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to put commit path.\n");
            break;
        }

        if (!remove_from_modules(admin_manager, AM_IIS_APPHOST, AM_IIS_GLOBAL, FALSE)) {
            fprintf(stderr, "Failed to remove entry from globalModules.\n");
            break;
        }

        rv = 1;

        hresult = IAppHostWritableAdminManager_CommitChanges(admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to save changes to remove module.\n");
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return rv;
}

/**
 * Get site name by site id.
 */
static char *get_site_name(const char *sid) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    IAppHostElement *he = NULL, *ce = NULL;
    IAppHostElementCollection *hec = NULL;
    DWORD i, num;
    HRESULT hresult;
    char *name, *id, *ret = NULL;

    do {
        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostWritableAdminManager_GetAdminSection(admin_manager, AM_IIS_SITES, AM_IIS_APPHOST, &he);
        if (FAILED(hresult) || he == NULL) {
            break;
        }
        hresult = IAppHostElement_get_Collection(he, &hec);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostElementCollection_get_Count(hec, &num);
        if (FAILED(hresult)) {
            break;
        }

        for (i = 0; i < num; i++) {
            VARIANT index, value;
            VariantInit(&index);
            VariantInit(&value);
            index.vt = VT_UINT;
            index.uintVal = i;
            hresult = IAppHostElementCollection_get_Item(hec, index, &ce);
            if (SUCCEEDED(hresult)) {
                name = get_property_value_byname(ce, &value, AM_IIS_ENAME, VT_BSTR);
                id = get_property_value_byname(ce, &value, AM_IIS_EID, VT_UI4);
                if (strcmp(id, sid) == 0) {
                    if (name != NULL && id != NULL) {
                        char cpath[2048];
                        char *p;
                        for (p = name; *p != '\0'; ++p) {
                            *p = toupper(*p);
                        }
                        snprintf(cpath, sizeof (cpath), "MACHINE/WEBROOT/APPHOST/%s", name);
                        ret = strdup(cpath);
                        i = num;
                    }
                }
                AM_FREE(name, id);
                name = NULL;
                id = NULL;
            }
            if (ce != NULL) {
                IAppHostElement_Release(ce);
            }
            VariantClear(&index);
            VariantClear(&value);
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (he != NULL) {
        IAppHostElement_Release(he);
    }
    if (hec != NULL) {
        IAppHostElementCollection_Release(hec);
    }
    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return ret;
}

/**
 * Enable module in site.
 */
int enable_module(const char *siteid, const char *modconf) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    HRESULT hresult;
    int rv = 0;
    wchar_t *config_path_w;
    wchar_t *modconf_w;
    char *config_path;

    if (siteid == NULL || modconf == NULL) {
        fprintf(stderr, "Invalid arguments.\n");
        return rv;
    }

    config_path = get_site_name(siteid);
    if (config_path == NULL) {
        fprintf(stderr, "Unknown site id: %s.\n", siteid);
        return rv;
    }

    config_path_w = utf8_decode(config_path);
    free(config_path);
    modconf_w = utf8_decode(modconf);

    do {
        if (config_path_w == NULL || modconf_w == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create AppHostWritableAdminManager.\n");
            break;
        }
        hresult = IAppHostWritableAdminManager_put_CommitPath(admin_manager, config_path_w);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to put commit path.\n");
            break;
        }

        if (!add_to_modules(admin_manager, config_path_w, siteid)) {
            fprintf(stderr, "Failed to add entry to modules.\n");
            break;
        }

        if (!update_module_site_config(admin_manager, config_path_w, modconf_w, TRUE)) {
            fprintf(stderr, "Failed to add module configuration entry.\n");
        } else {
            rv = 1;
        }

        hresult = IAppHostWritableAdminManager_CommitChanges(admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to save module configuration changes.\n");
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    AM_FREE(modconf_w, config_path_w);

    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return rv;
}

/**
 * Disable module in site.
 */
int disable_module(const char *siteid, const char *modconf) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    HRESULT hresult;
    int rv = 0;
    wchar_t *config_path_w;
    wchar_t *modconf_w;
    char *config_path;

    if (siteid == NULL || modconf == NULL) {
        fprintf(stderr, "Invalid arguments.\n");
        return rv;
    }

    config_path = get_site_name(siteid);
    if (config_path == NULL) {
        fprintf(stderr, "Unknown site id: %s.\n", siteid);
        return rv;
    }

    config_path_w = utf8_decode(config_path);
    free(config_path);
    modconf_w = utf8_decode(modconf);

    do {
        if (config_path_w == NULL || modconf_w == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create AppHostWritableAdminManager.\n");
            break;
        }
        hresult = IAppHostWritableAdminManager_put_CommitPath(admin_manager, config_path_w);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to put commit path.\n");
            break;
        }

        if (!remove_from_modules(admin_manager, config_path_w, AM_IIS_MODULES, FALSE)) {
            fprintf(stderr, "Failed to remove entry from modules.\n");
            break;
        }

        if (!update_module_site_config(admin_manager, config_path_w, modconf_w, FALSE)) {
            fprintf(stderr, "Failed to add module configuration entry.\n");
        } else {
            rv = 1;
        }

        hresult = IAppHostWritableAdminManager_CommitChanges(admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to save module configuration changes.\n");
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    AM_FREE(modconf_w, config_path_w);

    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return rv;
}

/**
 * Add module to AdminManager module list.
 */
static BOOL add_to_modules(IAppHostWritableAdminManager* manager, BSTR config_path, const char* siteid) {
    IAppHostElement* parent = NULL;
    IAppHostElementCollection* collection = NULL;
    IAppHostElement* element = NULL;
    HRESULT hresult;
    BOOL result = FALSE;

    BOOL site32bit = is_site_32bit(siteid);
    BSTR mod_name = site32bit ? AM_IIS_MODULE_NAME : AM_IIS_MODULE_NAME64;

    do {
        hresult = IAppHostWritableAdminManager_GetAdminSection(manager, AM_IIS_MODULES, config_path, &parent);
        if (FAILED(hresult) || parent == NULL) {
            fprintf(stderr, "Unable to get modules configuration.\n");
            break;
        }

        hresult = IAppHostElement_get_Collection(parent, &collection);
        if (FAILED(hresult) || collection == NULL) {
            fprintf(stderr, "Unable to get modules child collection.\n");
            break;
        }

        if (!get_from_collection(collection, AM_IIS_ENAME, mod_name, &element)) {
            fprintf(stderr, "Failed to try detect old modules.\n");
            break;
        }

        if (element != NULL) {
            /* module is already registered */
            result = TRUE;
            break;
        }

        hresult = IAppHostElementCollection_CreateNewElement(collection, AM_IIS_EADD, &element);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create modules/add element.\n");
            break;
        }

        if (!set_property(element, AM_IIS_ENAME, mod_name)) {
            fprintf(stderr, "Failed to set name property.\n");
            break;
        }

        if (site32bit) {
            if (!set_property(element, L"preCondition", L"bitness32")) {
                fprintf(stderr, "Failed to set preCondition property.\n");
                break;
            }
        } else {
            if (!set_property(element, L"preCondition", L"bitness64")) {
                fprintf(stderr, "Failed to set preCondition property.\n");
                break;
            }
        }

        hresult = IAppHostElementCollection_AddElement(collection, element, -1);
        switch (hresult) {
            case S_OK:
                result = TRUE;
                break;
            case ERROR_INVALID_INDEX:
                fprintf(stderr, "AddElement failed with ERROR_INVALID_INDEX");
                break;
            case ERROR_FILE_NOT_FOUND:
            {
                char* c_str_config_path = get_site_name(siteid);
                if (c_str_config_path == NULL) {
                    fprintf(stderr, "AddElement failed, unknown site id: %s.\n", siteid);
                    break;
                }
                fprintf(stderr, "AddElement failed, file %s: ERROR_FILE_NOT_FOUND", c_str_config_path);
                free(c_str_config_path);
                break;
            }
            default:
            {
                char* c_str_config_path = get_site_name(siteid);
                if (c_str_config_path == NULL) {
                    fprintf(stderr, "AddElement failed, unknown site id: %s.\n", siteid);
                    break;
                }
                fprintf(stderr, "AddElement failed, file %s\n", c_str_config_path);
                show_windows_error(hr_to_winerror(hresult));
                free(c_str_config_path);
                break;
            }
        }
    } while (FALSE);

    if (element != NULL) {
        IAppHostElement_Release(element);
    }
    if (collection != NULL) {
        IAppHostElementCollection_Release(collection);
    }
    if (parent != NULL) {
        IAppHostElement_Release(parent);
    }
    return result;
}

/**
 * Test if site is configured with agent module.
 */
int test_module(const char *siteid) {
    BOOL local = FALSE;
    BOOL global = FALSE;
    int rv = ADMIN_IIS_MOD_ERROR;
    IAppHostWritableAdminManager *admin_manager = NULL;
    HRESULT hresult;
    wchar_t *config_path_w;
    char *config_path;

    if (siteid == NULL) {
        fprintf(stderr, "Invalid arguments.\n");
        return rv;
    }

    config_path = get_site_name(siteid);
    if (config_path == NULL) {
        fprintf(stderr, "Unknown site id: %s.\n", siteid);
        return rv;
    }

    config_path_w = utf8_decode(config_path);
    free(config_path);

    do {
        if (config_path_w == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            break;
        }

        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID*) & admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to create AppHostWritableAdminManager.\n");
            break;
        }
        hresult = IAppHostWritableAdminManager_put_CommitPath(admin_manager, config_path_w);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to put commit path.\n");
            break;
        }

        global = remove_from_modules(admin_manager, config_path_w, AM_IIS_GLOBAL, TRUE);
        local = remove_from_modules(admin_manager, config_path_w, AM_IIS_MODULES, TRUE);

        if (global == FALSE && local == FALSE) {
            rv = ADMIN_IIS_MOD_NONE;
        } else {
            if (global == TRUE) {
                rv = ADMIN_IIS_MOD_GLOBAL;
            }
            if (local == TRUE) {
                rv = ADMIN_IIS_MOD_LOCAL;
            }
        }

        hresult = IAppHostWritableAdminManager_CommitChanges(admin_manager);
        if (FAILED(hresult)) {
            fprintf(stderr, "Failed to save changes to remove module.\n");
        }

    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    am_free(config_path_w);
    if (admin_manager != NULL) {
        IAppHostWritableAdminManager_Release(admin_manager);
    }
    return rv;
}

/**
 * Get site application pool name.
 */
static char *get_site_application_pool(const char *site_id) {
    IAppHostWritableAdminManager *admin_manager = NULL;
    IAppHostElement *root = NULL;
    IAppHostElementCollection *host_element_collection = NULL;
    HRESULT hresult;
    DWORD i, j, site_count = 0;
    static char app_pool[AM_URI_SIZE];
    memset(&app_pool[0], 0, sizeof (app_pool));

    do {
        hresult = CoCreateInstance(&CLSID_AppHostWritableAdminManager, NULL,
                CLSCTX_INPROC_SERVER, &IID_IAppHostWritableAdminManager, (LPVOID *) & admin_manager);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostWritableAdminManager_GetAdminSection(admin_manager,
                AM_IIS_SITES, AM_IIS_APPHOST, &root);
        if (FAILED(hresult) || &root == NULL) {
            break;
        }
        hresult = IAppHostElement_get_Collection(root, &host_element_collection);
        if (FAILED(hresult)) {
            break;
        }
        hresult = IAppHostElementCollection_get_Count(host_element_collection, &site_count);
        if (FAILED(hresult)) {
            break;
        }
        for (i = 0; i < site_count; i++) {
            IAppHostElement *site = NULL;
            VARIANT index, id_value;
            VariantInit(&index);
            VariantInit(&id_value);
            index.vt = VT_UINT;
            index.uintVal = i;
            hresult = IAppHostElementCollection_get_Item(host_element_collection, index, &site);
            if (SUCCEEDED(hresult)) {
                char *id = get_property_value_byname(site, &id_value, AM_IIS_EID, VT_UI4);
                if (id != NULL && strcmp(id, site_id) == 0) {
                    IAppHostElementCollection *site_element_collection = NULL;
                    DWORD app_count = 0;
                    hresult = IAppHostElement_get_Collection(site, &site_element_collection);
                    if (SUCCEEDED(hresult) && site_element_collection != NULL &&
                            SUCCEEDED(IAppHostElementCollection_get_Count(site_element_collection, &app_count))) {
                        for (j = 0; j < app_count; j++) {
                            IAppHostElement *app_element = NULL;
                            VARIANT app_index;
                            VariantInit(&app_index);
                            app_index.vt = VT_UINT;
                            app_index.uintVal = j;
                            hresult = IAppHostElementCollection_get_Item(site_element_collection, app_index, &app_element);
                            if (SUCCEEDED(hresult)) {
                                VARIANT path_value, app_pool_value;
                                BSTR app_element_name = NULL;
                                VariantInit(&path_value);
                                VariantInit(&app_pool_value);
                                hresult = IAppHostElement_get_Name(app_element, &app_element_name);
                                if (SUCCEEDED(hresult) && app_element_name != NULL &&
                                        wcscmp(app_element_name, L"application") == 0) {
                                    char *path_str = get_property_value_byname(app_element, &path_value, AM_IIS_EPATH, VT_BSTR);
                                    if (path_str != NULL && strcmp(path_str, "/") == 0) {
                                        char *pool_str = get_property_value_byname(app_element, &app_pool_value, AM_IIS_EPOOL, VT_BSTR);
                                        if (pool_str != NULL) {
                                            snprintf(app_pool, sizeof (app_pool), "IIS APPPOOL\\%s", pool_str);
                                            free(pool_str);
                                        }
                                    }
                                    am_free(path_str);
                                }
                                if (app_element_name != NULL) {
                                    SysFreeString(app_element_name);
                                }
                                VariantClear(&path_value);
                                VariantClear(&app_pool_value);
                            }
                            if (app_element != NULL) {
                                IAppHostElement_Release(app_element);
                            }
                            VariantClear(&app_index);
                        }
                    }
                    if (site_element_collection != NULL) {
                        IAppHostElementCollection_Release(site_element_collection);
                    }
                }
                am_free(id);
            }
            if (site != NULL) {
                IAppHostElement_Release(site);
            }
            VariantClear(&index);
            VariantClear(&id_value);
        }
        if (host_element_collection != NULL) {
            IAppHostElementCollection_Release(host_element_collection);
        }
    } while (FALSE);

    if (FAILED(hresult)) {
        show_windows_error(hr_to_winerror(hresult));
    }

    if (root != NULL) {
        IAppHostElement_Release(root);
    }
    return app_pool;
}

/**
 * Add directory ACL.
 */
int add_directory_acl(char *site_id, char *directory, char *user) {
    PACL acl = NULL;
    DWORD rv;
    PACL directory_acl = NULL;
    PSECURITY_DESCRIPTOR directory_secd = NULL;
    EXPLICIT_ACCESS ea[1];
    char *app_pool_name;
    int status = AM_ERROR;

    if (ISINVALID(directory)) {
        return AM_EINVAL;
    }

    app_pool_name = ISVALID(site_id) ? get_site_application_pool(site_id) : user;
    if (ISINVALID(app_pool_name)) {
        return AM_ERROR;
    }

    rv = GetNamedSecurityInfo(directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            NULL, NULL, &directory_acl, NULL, &directory_secd);
    if (rv != ERROR_SUCCESS) {
        if (directory_secd != NULL) {
            LocalFree(directory_secd);
        }
        return AM_FILE_ERROR;
    }

    ZeroMemory(&ea, sizeof (EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPTSTR) app_pool_name;

    rv = SetEntriesInAcl(1, ea, directory_acl, &acl);
    if (rv == ERROR_SUCCESS) {
        rv = SetNamedSecurityInfo(directory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                NULL, NULL, acl, NULL);
        if (rv == ERROR_SUCCESS) {
            status = AM_SUCCESS;
        }
    }
    if (acl != NULL) {
        LocalFree(acl);
    }
    if (directory_secd != NULL) {
        LocalFree(directory_secd);
    }
    return status;
}

#else 

/*no-ops on this platform*/

void list_iis_sites(int argc, char **argv) {

}

int enable_module(const char *siteid, const char *modconf) {
    return 0;
}

int disable_module(const char *siteid, const char *modconf) {
    return 0;
}

int test_module(const char *siteid) {
    return 0;
}

int install_module(const char *modpath, const char *modconf) {
    return 0;
}

int remove_module() {
    return 0;
}

int add_directory_acl(char *site_id, char *directory, char *user) {
    return 0;
}

#endif
