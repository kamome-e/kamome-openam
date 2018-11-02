/*
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
 * Copyright 2013 ForgeRock AS.
 */

package org.forgerock.openam.oauth2.model.handlers;

import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.utils.Utils;

import java.security.Key;

/**
 * Utilities related to OAuth2.
 *
 * @author Taisei Morigami
 * @since 2.0.0
 */
public class CustomNOPSigningHandler implements CustomSigningHandler {

    @Override
    public byte[] sign(JwsAlgorithm algorithm, Key privateKey, String data) {
        return "".getBytes(Utils.CHARSET);
    }

    @Override
    public byte[] sign(JwsAlgorithm algorithm, Key privateKey, String data, String clientSecret) {
        return sign(algorithm, privateKey, data);
    }

    @Override
    public boolean verify(JwsAlgorithm algorithm, Key privateKey, byte[] data, byte[] signature) {
        return signature.length == 0;
    }
}
