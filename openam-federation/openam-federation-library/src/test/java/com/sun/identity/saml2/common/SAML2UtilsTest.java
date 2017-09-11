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
 * Copyright 2014 ForgeRock AS.
 */

package com.sun.identity.saml2.common;

import com.sun.identity.shared.encode.URLEncDec;
import org.apache.commons.lang.RandomStringUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class SAML2UtilsTest {

    @Test
    public void encodeDecodeTest() {

        // the max length of each random String to encode
        int maxStringLength = 300;
        // the number of encode/decode iterations we want to test
        int randomStringsCount = 3000;
        Random R = new Random();

        int i = 0;
        while (i < randomStringsCount) {
            int size = R.nextInt(maxStringLength);
            // We don't want any 0 length arrays
            while (size == 0) {
                size = R.nextInt(maxStringLength);
            }
            i++;
            String randomString = RandomStringUtils.randomAlphanumeric(size);
            String encoded = SAML2Utils.encodeForRedirect(randomString);
            String decoded = SAML2Utils.decodeFromRedirect(URLEncDec.decode(encoded));
            Assert.assertEquals(decoded, randomString);
        }
    }

    @Test
    public void getMappedAttributesTest() {

        List<String> mappings = new ArrayList<>(6);

        mappings.add("invalid entry");
        mappings.add("name1=value");
        mappings.add("name2=\"static value\"");
        mappings.add("name3=\"static cn=value\"");
        mappings.add("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|urn:mace:dir:attribute-def:name4=value");
        mappings.add("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|name5=\"static value\"");

        Map<String, String> mappedAttributes = SAML2Utils.getMappedAttributes(mappings);

        Assert.assertNotNull(mappedAttributes);
        Assert.assertEquals(mappedAttributes.size(), 5);

        Assert.assertTrue(mappedAttributes.containsKey("name1"));
        Assert.assertEquals(mappedAttributes.get("name1"), "value");
        
        Assert.assertTrue(mappedAttributes.containsKey("name2"));
        Assert.assertEquals(mappedAttributes.get("name2"), "\"static value\"");

        Assert.assertTrue(mappedAttributes.containsKey("name3"));
        Assert.assertEquals(mappedAttributes.get("name3"), "\"static cn=value\"");

        Assert.assertTrue(mappedAttributes.containsKey("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|urn:mace:dir:attribute-def:name4"));
        Assert.assertEquals(mappedAttributes.get("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|urn:mace:dir:attribute-def:name4"), "value");

        Assert.assertTrue(mappedAttributes.containsKey("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|name5"));
        Assert.assertEquals(mappedAttributes.get("urn:oasis:names:tc:SAML:2.0:attrname-format:uri|name5"), "\"static value\"");
    }
}
