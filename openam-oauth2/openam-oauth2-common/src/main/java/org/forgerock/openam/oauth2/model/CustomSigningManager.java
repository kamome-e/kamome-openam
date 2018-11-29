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

package org.forgerock.openam.oauth2.model;

import org.forgerock.json.jose.exceptions.JwsException;
import org.forgerock.openam.oauth2.model.handlers.CustomHmacSigningHandler;
import org.forgerock.openam.oauth2.model.handlers.CustomNOPSigningHandler;
import org.forgerock.openam.oauth2.model.handlers.CustomRSASigningHandler;
import org.forgerock.openam.oauth2.model.handlers.CustomSigningHandler;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.util.SignatureUtil;

/**
 * A service to get the appropriate SigningHandler for a specific Java Cryptographic signing algorithm.
 * <p>
 * For details of all supported signing algorithms see {@link JwsAlgorithm}
 *
 * @author Taisei Morigami
 * @since 2.0.0
 */
public class CustomSigningManager {

    private final SignatureUtil signatureUtil = SignatureUtil.getInstance();

    public CustomSigningHandler getSigningHandler(JwsAlgorithmOAuth2 algorithm) {

        switch (algorithm.getAlgorithmType()) {
            case NONE: {
                return new CustomNOPSigningHandler();
            }
            case HMAC: {
                return new CustomHmacSigningHandler();
            }
            case RSA: {
                return new CustomRSASigningHandler(signatureUtil);
            }
            default: {
                throw new JwsException("No Signing Handler for unknown signing algorithm type, "
                        + algorithm.getAlgorithmType() + ".");
            }
        }
    }
}
