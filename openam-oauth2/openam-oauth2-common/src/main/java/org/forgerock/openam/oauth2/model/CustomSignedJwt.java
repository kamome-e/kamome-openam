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

import org.forgerock.openam.oauth2.model.handlers.CustomSigningHandler;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jwt.Payload;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.encode.Base64url;

import java.security.Key;
import java.security.PublicKey;

/**
 * A JWS implementation of the <tt>Jwt</tt> interface.
 * <p>
 * JSON Web Signature (JWS) is a means of representing content secured with digital signatures or Message
 * Authentication Codes (MACs) using JSON based data structures.
 * <p>
 * @see <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11">JSON Web Signature Specification</a>
 *
 * @author Phill Cunnington
 * @since 2.0.0
 */
public class CustomSignedJwt  implements Jwt {

    private final CustomSigningManager signingManager = new CustomSigningManager();

    private final CustomJwsHeader header;
    private final Payload payload;

    private final Key privateKey;
    private final String clientSecret;

    private final byte[] signingInput;
    private final byte[] signature;

    /**
     * Constructs a fresh, new SignedJwt from the given CustomJwsHeader and JwtClaimsSet.
     * <p>
     * The specified private key will be used in the creation of the JWS signature.
     *
     * @param header The CustomJwsHeader containing the header parameters of the JWS.
     * @param claimsSet The JwtClaimsSet containing the claims of the JWS.
     * @param privateKey The private key to use to sign the JWS.
     */
    public CustomSignedJwt(CustomJwsHeader header, JwtClaimsSet claimsSet, Key privateKey) {
        this.header = header;
        this.payload = claimsSet;
        this.privateKey = privateKey;

        this.clientSecret = null;
        this.signingInput = null;
        this.signature = null;
    }

    public CustomSignedJwt(CustomJwsHeader header, JwtClaimsSet claimsSet, String clientSecret) {
        this.header = header;
        this.payload = claimsSet;
        this.clientSecret = clientSecret;

        this.privateKey = null;
        this.signingInput = null;
        this.signature = null;
    }

    public CustomSignedJwt(CustomJwsHeader header, JwtClaimsSet claimsSet, Key privateKey, String clientSecret) {
        this.header = header;
        this.payload = claimsSet;
        this.privateKey = privateKey;
        this.clientSecret = clientSecret;

        this.signingInput = null;
        this.signature = null;
    }

    /**
     * Constructs a reconstructed SignedJwt from its constituent parts, the CustomJwsHeader, JwtClaimsSet, signing input and
     * signature.
     * <p>
     * For use when a signed JWT has been reconstructed from its base64url encoded string representation and the
     * signature needs verifying.
     *
     * @param header The CustomJwsHeader containing the header parameters of the JWS.
     * @param claimsSet The JwsClaimsSet containing the claims of the JWS.
     * @param signingInput The original data that was signed, being the base64url encoding of the JWS header and
     *                     claims set concatenated using a "." character.
     * @param signature The resulting signature of signing the signing input.
     */
    public CustomSignedJwt(CustomJwsHeader header, JwtClaimsSet claimsSet, byte[] signingInput, byte[] signature) {
        this.header = header;
        this.payload = claimsSet;
        this.signingInput = signingInput;
        this.signature = signature;

        this.clientSecret = null;
        this.privateKey = null;
    }

    /**
     * Constructs a fresh, new SignedJwt from the given CustomJwsHeader and nested Encrypted JWT.
     * <p>
     * The specified private key will be used in the creation of the JWS signature.
     *
     * @param header The CustomJwsHeader containing the header parameters of the JWS.
     * @param nestedPayload The nested payload that will be the payload of this JWS.
     * @param privateKey The private key to use to sign the JWS.
     */
    protected CustomSignedJwt(CustomJwsHeader header, Payload nestedPayload, Key privateKey) {
        this.header = header;
        this.payload = nestedPayload;
        this.privateKey = privateKey;

        this.clientSecret = null;
        this.signingInput = null;
        this.signature = null;
    }

    /**
     * Constructs a reconstructed SignedJwt from its constituent parts, the CustomJwsHeader, nested Encrypted JWT, signing
     * input and signature.
     * <p>
     * For use when a signed nested encrypted JWT has been reconstructed from its base64url encoded string
     * representation and the signature needs verifying.
     *
     * @param header The CustomJwsHeader containing the header parameters of the JWS.
     * @param nestedPayload The nested payload that is the payload of the JWS.
     * @param signingInput The original data that was signed, being the base64url encoding of the JWS header and
     *                     payload concatenated using a "." character.
     * @param signature The resulting signature of signing the signing input.
     */
    protected CustomSignedJwt(CustomJwsHeader header, Payload nestedPayload, byte[] signingInput, byte[] signature) {
        this.header = header;
        this.payload = nestedPayload;
        this.signingInput = signingInput;
        this.signature = signature;

        this.clientSecret = null;
        this.privateKey = null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CustomJwsHeader getHeader() {
        return header;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JwtClaimsSet getClaimsSet() {
        return (JwtClaimsSet) payload;
    }

    /**
     * Gets the payload for the JWS, which will either be a JWT Claims Set, {@link #getClaimsSet()}, or a nested
     * EncryptedJwt, {@link org.forgerock.json.jose.jwe.EncryptedJwt}.
     *
     * @return The JWS' payload.
     * @see SignedEncryptedJwt
     */
    protected Payload getPayload() {
        return payload;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String build() {

        String jwsHeader = header.build();
        String encodedHeader = Utils.base64urlEncode(jwsHeader);
        String jwsPayload = payload.build();
        String encodedClaims = Utils.base64urlEncode(jwsPayload);

        String signingInput = encodedHeader + "." + encodedClaims;

        CustomSigningHandler signingHandler = signingManager.getSigningHandler(header.getAlgorithm());
        byte[] signature = null;
        if (JwsAlgorithmType.RSA.equals(header.getAlgorithm().getAlgorithmType())) {
            signature = signingHandler.sign(header.getAlgorithm(), privateKey, signingInput);
        } else {
            signature = signingHandler.sign(header.getAlgorithm(), clientSecret, signingInput);
        }

        return signingInput + "." + Base64url.encode(signature);
    }

    /**
     * Verifies that the JWS signature is valid for the contents of its payload.
     * <p>
     * The same private key must be given here as was used to create the signature.
     *
     * @param privateKey The private key used to sign the JWT.
     * @return <code>true</code> if the signature matches the JWS Header and payload.
     */
    public boolean verify(Key privateKey) {
        CustomSigningHandler signingHandler = signingManager.getSigningHandler(header.getAlgorithm());
        if (JwsAlgorithmType.RSA.equals(header.getAlgorithm().getAlgorithmType())) {
            return signingHandler.verify(header.getAlgorithm(), privateKey, signingInput, signature);
        } else {
            return signingHandler.verify(header.getAlgorithm(), clientSecret, signingInput, signature);
        }
    }
}
