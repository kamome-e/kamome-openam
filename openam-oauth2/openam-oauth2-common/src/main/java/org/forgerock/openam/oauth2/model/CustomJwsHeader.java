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

import java.util.Map;
import org.forgerock.json.jose.jws.JwtSecureHeader;

/**
 * An implementation for the JWS Header parameters.
 *
 * @author Phill Cunnington
 * @since 2.0.0
 */
public class CustomJwsHeader extends JwtSecureHeader {

    /**
     * Constructs a new, empty CustomJwsHeader.
     */
    public CustomJwsHeader() {
    }

    /**
     * Constructs a new CustomJwsHeader, with its parameters set to the contents of the given Map.
     *
     * @param headerParameters A Map containing the parameters to be set in the header.
     */
    public CustomJwsHeader(Map<String, Object> headerParameters) {
        super(headerParameters);
    }

    /**
     * Gets the Algorithm set in the JWT header.
     * <p>
     * If there is no algorithm set in the JWT header, then the JwsAlgorithm NONE will be returned.
     *
     * @return {@inheritDoc}
     */
    @Override
    public JwsAlgorithmOAuth2 getAlgorithm() {
        String algorithm = getAlgorithmString();
        if (algorithm == null) {
            return JwsAlgorithmOAuth2.none;
        } else {
            return JwsAlgorithmOAuth2.valueOf(algorithm);
        }
    }
}
