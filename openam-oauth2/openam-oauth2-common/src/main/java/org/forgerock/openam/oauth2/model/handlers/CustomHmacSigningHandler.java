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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.forgerock.json.jose.exceptions.JwsSigningException;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.openam.oauth2.model.JwsAlgorithmOAuth2;
import org.forgerock.openam.utils.StringUtils;

/**
 * Utilities related to OAuth2.
 *
 * @author Taisei Morigami
 * @since 2.0.0
 */
public class CustomHmacSigningHandler implements CustomSigningHandler {

    @Override
    public byte[] sign(JwsAlgorithmOAuth2 algorithm, Key privateKey, String data) {
        return signWithHMAC(algorithm.getSignAlgorithm(), privateKey, data.getBytes(Utils.CHARSET));
    }

    @Override
    public byte[] sign(JwsAlgorithmOAuth2 algorithm, String clientSecret, String data) {
        return signWithHMAC(algorithm.getSignAlgorithm(), clientSecret, data.getBytes(Utils.CHARSET));
    }

    private byte[] signWithHMAC(String algorithm, Key key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            byte[] secretByte = key.getEncoded();
            SecretKey secretKey = new SecretKeySpec(secretByte, algorithm.toUpperCase());
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new JwsSigningException("Unsupported Signing Algorithm, " + algorithm, e);
        } catch (InvalidKeyException e) {
            throw new JwsSigningException(e);
        }
    }

    private byte[] signWithHMAC(String algorithm, String clientSecret, byte[] data) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            // decode the base64 encoded string
            byte[] secretByte = clientSecret.getBytes();
            // rebuild key using SecretKeySpec
            SecretKey secretKey = new SecretKeySpec(secretByte, "AES");
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new JwsSigningException("Unsupported Signing Algorithm, " + algorithm, e);
        } catch (InvalidKeyException e) {
            throw new JwsSigningException(e);
        }
    }

    @Override
    public boolean verify(JwsAlgorithmOAuth2 algorithm, Key privateKey, byte[] data, byte[] signature) {
        byte[] signed = signWithHMAC(algorithm.getSignAlgorithm(), privateKey, data);
        return MessageDigest.isEqual(signed, signature);
    }

    @Override
    public boolean verify(JwsAlgorithmOAuth2 algorithm, Key publicKey, String data, byte[] signature) {
        return true;
    }

    @Override
    public boolean verify(JwsAlgorithmOAuth2 algorithm, String clientSecret, byte[] data, byte[] signature) {
        byte[] signed = signWithHMAC(algorithm.getSignAlgorithm(), clientSecret, data);
        return MessageDigest.isEqual(signed, signature);
    }
}
