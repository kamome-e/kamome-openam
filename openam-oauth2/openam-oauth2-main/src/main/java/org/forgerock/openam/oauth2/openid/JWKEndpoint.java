package org.forgerock.openam.oauth2.openid;

import static org.forgerock.json.fluent.JsonValue.*;

import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.forgerock.json.jose.jwk.KeyUse;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.openam.oauth2.model.JwsAlgorithmOAuth2;
import org.forgerock.openam.oauth2.utils.OAuth2Utils;
import org.forgerock.util.encode.Base64url;
import org.restlet.ext.json.JsonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import com.sun.identity.shared.encode.Base64;

/**
 * JWK_URI Endpoint
 *
 * @author taisei.morigami
 */
public class JWKEndpoint extends ServerResource {

    private final List<Map<String, Object>> jwks = new ArrayList<Map<String, Object>>();

//    private final OAuth2RequestFactory requestFactory;
//    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
//    private final ExceptionHandler exceptionHandler;
//
//    public JWKEndpoint(OAuth2RequestFactory requestFactory,
//            OAuth2ProviderSettingsFactory providerSettingsFactory, ExceptionHandler exceptionHandler) {
//        this.requestFactory = requestFactory;
//        this.providerSettingsFactory = providerSettingsFactory;
//        this.exceptionHandler = exceptionHandler;
//    }

    public JWKEndpoint() {}

    @Get
    public Representation endSession() {
//        OAuth2Request request = requestFactory.create(getRequest());
//        try {
//            OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(request);
//            return new JsonRepresentation(providerSettings.getJWKSet().asMap());
//        } catch (OAuth2Exception e) {
//            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(), null);
//        }
        synchronized (jwks) {
            if (jwks.isEmpty()) {
                PublicKey key = OAuth2Utils.getServerKeyPair(getRequest().getCurrent()).getPublic();
                jwks.add(createRSAJWK((RSAPublicKey) key, KeyUse.SIG, JwsAlgorithmOAuth2.RS256.name()));
            }
        }

//        Map<String, Object> map = new HashMap<String, Object>();
//        map.put("keys", jwks);
//        return new JsonRepresentation(map);
        return new JsonRepresentation(Collections.singletonMap("keys", jwks));
    }

    private Map<String, Object> createRSAJWK(RSAPublicKey key, KeyUse use, String alg) {
        String kid = hash(OAuth2Utils.getArias(getRequest().getCurrent()) + key.getModulus().toString() + key.getPublicExponent().toString());
        return json(object(field("kty", "RSA"), field("kid", kid),
                field("use", use.toString()), field("alg", alg),
                field("n", Base64url.encode(key.getModulus().toByteArray())),
                field("e", Base64url.encode(key.getPublicExponent().toByteArray())))).asMap();
    }

    private String hash(String string) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(string.getBytes("UTF-8"));
            return Base64.encode(sha1.digest());
        } catch (Exception ex) {
            OAuth2Utils.DEBUG.warning("Hash.hash:", ex);
            return null;
        }
    }
}
