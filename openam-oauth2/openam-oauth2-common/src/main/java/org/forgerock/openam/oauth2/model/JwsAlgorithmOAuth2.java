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

import org.forgerock.json.jose.jwt.Algorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;

/**
 * An Enum of the possible signing algorithms that can be used to sign a JWT.
 * <p>
 * @see <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-11#section-3.1">JWS Algorithms</a>
 *
 * @author Phill Cunnington
 * @since 2.0.0
 */
public enum JwsAlgorithmOAuth2 implements Algorithm {

    /** No digital signature or MAC value included. */
    none("none", JwsAlgorithmType.NONE),
    /** HMAC using SHA-256 hash algorithm. */
    HS256("HS256", JwsAlgorithmType.HMAC),
    /** HMAC using SHA-384 hash algorithm. */
    HS384("HS384", JwsAlgorithmType.HMAC),
    /** HMAC using SHA-512 hash algorithm. */
    HS512("HS512", JwsAlgorithmType.HMAC);

    private final String algorithm;
    private final JwsAlgorithmType algorithmType;

    /**
     * Constructs a new JwsAlgorithm with the Java Cryptographic string name of the algorithm and the JwsAlgorithmType
     * of the algorithm.
     *
     * @param algorithm The Java Cryptographic algorithm name.
     * @param algorithmType The JwsAlgorithmType of the JwsAlgorithm.
     */
    private JwsAlgorithmOAuth2(String algorithm, JwsAlgorithmType algorithmType) {
        this.algorithm = algorithm;
        this.algorithmType = algorithmType;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the JwsAlgorithmType of the JwsAlgorithm.
     *
     * @return The JwsAlgorithmType.
     */
    public JwsAlgorithmType getAlgorithmType() {
        return algorithmType;
    }

    /**
     * Gets the JwsAlgorithm constant that matches the given Java Cryptographic algorithm name.
     * <p>
     * If the given algorithm name does not match the algorithm name of any of the constants, then an
     * IllegalArgumentException will be thrown.
     *
     * @param algorithm The Java Cryptographic string algorithm name.
     * @return The matching JwsAlgorithm.
     */
    public static JwsAlgorithmOAuth2 getJwsAlgorithmOath2(String algorithm) {
        for (JwsAlgorithmOAuth2 jwsAlgorithmOAuth2 : JwsAlgorithmOAuth2.values()) {
            if (algorithm.equalsIgnoreCase(jwsAlgorithmOAuth2.getAlgorithm())) {
                return jwsAlgorithmOAuth2;
            }
        }
        throw new IllegalArgumentException("Unknown JwsAlgorithm, " + algorithm);
    }

    /**
     * Turns the JwsAlgorithm constant into a JSON value string.
     *
     * @return {@inheritDoc}
     */
    @Override
    public String toString() {
        return super.toString();
    }
}
