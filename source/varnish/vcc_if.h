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

struct VCL_conf;
struct vmod_priv;

VCL_VOID vmod_init(VRT_CTX, struct vmod_priv *, VCL_STRING);
VCL_BOOL vmod_authenticate(VRT_CTX, struct vmod_priv *);
VCL_VOID vmod_done(VRT_CTX, struct vmod_priv *);
VCL_VOID vmod_ok(VRT_CTX, struct vmod_priv *);
VCL_VOID vmod_cleanup(VRT_CTX, struct vmod_priv *);
VCL_VOID vmod_request_cleanup(VRT_CTX, struct vmod_priv *);
int init_function(struct vmod_priv *, const struct VCL_conf *);
