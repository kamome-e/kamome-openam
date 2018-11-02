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

import org.forgerock.json.jose.exceptions.JwsSigningException;
import org.forgerock.json.jose.exceptions.JwsVerifyingException;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.SignatureUtil;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * Utilities related to OAuth2.
 *
 * @author Taisei Morigami
 * @since 2.0.0
 */
public class CustomRSASigningHandler implements CustomSigningHandler {

    private final SignatureUtil signatureUtil;

    public CustomRSASigningHandler(SignatureUtil signatureUtil) {
        this.signatureUtil = signatureUtil;
    }

    @Override
    public byte[] sign(JwsAlgorithm algorithm, Key privateKey, String data) {
        try {
            return signatureUtil.sign((PrivateKey) privateKey, algorithm.getAlgorithm(), data);
        } catch (SignatureException e) {
            if (e.getCause().getClass().isAssignableFrom(NoSuchAlgorithmException.class)) {
                throw new JwsSigningException("Unsupported Signing Algorithm, " + algorithm.getAlgorithm(), e);
            }
            throw new JwsSigningException(e);
        }
    }

    @Override
    public byte[] sign(JwsAlgorithm algorithm, Key privateKey, String data, String clientSecret) throws JwsSigningException {
        return sign(algorithm, privateKey, data);
    }

    @Override
    public boolean verify(JwsAlgorithm algorithm, Key privateKey, byte[] data, byte[] signature) {
        try {
            return signatureUtil.verify((X509Certificate) null, algorithm.getAlgorithm(),
                    new String(data, Utils.CHARSET), signature);
        } catch (SignatureException e) {
            if (e.getCause().getClass().isAssignableFrom(NoSuchAlgorithmException.class)) {
                throw new JwsVerifyingException("Unsupported Signing Algorithm, " + algorithm.getAlgorithm(), e);
            }
            throw new JwsVerifyingException(e);
        }
    }
}
