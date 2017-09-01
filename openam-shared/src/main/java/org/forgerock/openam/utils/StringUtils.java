/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */
package org.forgerock.openam.utils;

import java.util.Map;

/**
 * Utility class for handling Strings
 *
 * @author Peter Major
 */
public final class StringUtils {

    /**
     *
     * @param content The String content to be replaced
     * @param tagSwapMap A map containing the replacable tokens with their new
     * values
     * @return the tagswapped String content
     */
    public static String tagSwap(String content, Map<String, String> tagSwapMap) {
        for (Map.Entry<String, String> entry : tagSwapMap.entrySet()) {
            content = content.replace(entry.getKey(), entry.getValue());
        }
        return content;
    }

    /**
     * Inserted content into a string.
     *
     * @param original The original string.
     * @param position The insertion position.
     * @param content The content to insert.
     * @return A new string with the inserted content.
     */
    public static String insertContent(String original, int position, String content) {
        return original.substring(0, position) + content + original.substring(position);
    }

    /**
     * Determines if the string is empty.
     *
     * @param s string to test
     * @return true if the specified string is null or zero length.
     */
    public static boolean isEmpty(final String s) {
        return (s == null || s.length() == 0);
    }

    /**
     * Determines if the string is blank.
     *
     * @param s string to test
     * @return true if the specified string is null or when trimmed is empty (i.e. when trimmed it has zero length)
     */
    public static boolean isBlank(final String s) {
        return (s == null || s.trim().length() == 0);
    }

    /**
     * Determines if the string is not empty.
     *
     * @param s string to test
     * @return test if the specified string is not null and not empty (i.e. is greater than zero length).
     */
    public static boolean isNotEmpty(final String s) {
        return (s != null && s.length() > 0);
    }

    /**
     * Determines if the string is not blank.
     *
     * @param s string to test
     * @return true if the specified string is not null and when trimmed has greater than zero length.
     */
    public static boolean isNotBlank(final String s) {
        return (s != null && s.trim().length() > 0);
    }
}
