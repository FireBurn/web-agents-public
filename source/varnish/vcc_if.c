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
 * Copyright 2015 ForgeRock AS.
 */

#include "config.h"
#include "vrt.h"
#include "vcc_if.h"
#include "vmod_abi.h"

typedef VCL_VOID td_am_init(VRT_CTX, struct vmod_priv *, VCL_STRING);
typedef VCL_BOOL td_am_authenticate(VRT_CTX, struct vmod_priv *);
typedef VCL_VOID td_am_done(VRT_CTX, struct vmod_priv *);
typedef VCL_VOID td_am_ok(VRT_CTX, struct vmod_priv *);
typedef VCL_VOID td_am_cleanup(VRT_CTX, struct vmod_priv *);
typedef VCL_VOID td_am_request_cleanup(VRT_CTX, struct vmod_priv *);

struct Vmod_am_Func {
    td_am_init *init;
    td_am_authenticate *authenticate;
    td_am_done *done;
    td_am_ok *ok;
    td_am_cleanup *cleanup;
    td_am_request_cleanup *request_cleanup;
    vmod_init_f *_init;
};

static const struct Vmod_am_Func Vmod_Func = {
    vmod_init,
    vmod_authenticate,
    vmod_done,
    vmod_ok,
    vmod_cleanup,
    vmod_request_cleanup,
    init_function,
};

static const char Vmod_Proto[] =
        "/* Functions */\n"
        "typedef VCL_VOID td_am_init(VRT_CTX, struct vmod_priv *,\n"
        "    VCL_STRING);\n"
        "typedef VCL_BOOL td_am_authenticate(VRT_CTX,\n"
        "    struct vmod_priv *);\n"
        "typedef VCL_VOID td_am_done(VRT_CTX, struct vmod_priv *);\n"
        "typedef VCL_VOID td_am_ok(VRT_CTX, struct vmod_priv *);\n"
        "typedef VCL_VOID td_am_cleanup(VRT_CTX, struct vmod_priv *);\n"
        "typedef VCL_VOID td_am_request_cleanup(VRT_CTX,\n"
        "    struct vmod_priv *);\n"
        "\n"

        "struct Vmod_am_Func {\n"
        "\n"
        "	/* Functions */\n"
        "	td_am_init			*init;\n"
        "	td_am_authenticate		*authenticate;\n"
        "	td_am_done			*done;\n"
        "	td_am_ok			*ok;\n"
        "	td_am_cleanup			*cleanup;\n"
        "	td_am_request_cleanup		*request_cleanup;\n"
        "\n"
        "	/* Init/Fini */\n"
        "	vmod_init_f	*_init;\n"
        "};\n"
        "static struct Vmod_am_Func Vmod_am_Func;";

static const char * const Vmod_Spec[] = {
    "am.init\0"
    "Vmod_am_Func.init\0"
    "VOID\0"
    "PRIV_VCL\0"
    "STRING\0"
    "\0",

    "am.authenticate\0"
    "Vmod_am_Func.authenticate\0"
    "BOOL\0"
    "PRIV_VCL\0"
    "\0",

    "am.done\0"
    "Vmod_am_Func.done\0"
    "VOID\0"
    "PRIV_VCL\0"
    "\0",

    "am.ok\0"
    "Vmod_am_Func.ok\0"
    "VOID\0"
    "PRIV_VCL\0"
    "\0",

    "am.cleanup\0"
    "Vmod_am_Func.cleanup\0"
    "VOID\0"
    "PRIV_VCL\0"
    "\0",

    "am.request_cleanup\0"
    "Vmod_am_Func.request_cleanup\0"
    "VOID\0"
    "PRIV_VCL\0"
    "\0",

    "INIT\0Vmod_am_Func._init",
    0
};

extern const struct vmod_data Vmod_am_Data;

const struct vmod_data Vmod_am_Data = {
    .vrt_major = VRT_MAJOR_VERSION,
    .vrt_minor = VRT_MINOR_VERSION,
    .name = "am",
    .func = &Vmod_Func,
    .func_len = sizeof (Vmod_Func),
    .proto = Vmod_Proto,
    .spec = Vmod_Spec,
    .abi = VMOD_ABI_Version,
    .file_id = "IHBOKZULFNRKJPROXGHDQR@DQCQXIQLA",
};
