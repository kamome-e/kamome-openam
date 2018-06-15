package com.sun.identity.saml2.plugins;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.plugin.session.SessionProvider;
import com.sun.identity.saml2.assertion.AssertionFactory;
import com.sun.identity.saml2.assertion.NameID;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.profile.IDPCache;
import com.sun.identity.saml2.profile.IDPSSOUtil;
import com.sun.identity.saml2.profile.IDPSession;
import com.sun.identity.saml2.profile.NameIDandSPpair;

/**
 * Copy-paste of the OpenAM DefaultIDPAccountMapper class, with a twist to allow SP-specific configuration.
 * To specify a custom attribute for a given SP, use the following mapping : NAMING-FORMAT:SPENTITYID=attribute
 * Example : urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified:google.com/a/mycompany.com=mail
 */
public class CustomIDPAccountMapper extends DefaultAccountMapper implements IDPAccountMapper {
    private DefaultIDPAccountMapper defaultIDPAccountMapperDelegate;

    public CustomIDPAccountMapper () {
        debug.message("MyIDPAccountMapper .constructor");
        this.role = "IDPRole";
        defaultIDPAccountMapperDelegate = new DefaultIDPAccountMapper();
    }


    public NameID getNameID(Object session, String hostEntityID, String remoteEntityID, String realm, String nameIDFormat)
            throws SAML2Exception {
        String userID = null;
        try {
            SessionProvider sessionProv = SessionManager.getProvider();
            userID = sessionProv.getPrincipalName(session);
        } catch (SessionException se) {
            throw new SAML2Exception(SAML2Utils.bundle.getString("invalidSSOToken"));
        }


        String nameIDValue = null;
        if (nameIDFormat.equals(SAML2Constants.NAMEID_TRANSIENT_FORMAT)) {
            String sessionIndex = IDPSSOUtil.getSessionIndex(session);
            if (sessionIndex != null) {
                IDPSession idpSession = (IDPSession) IDPCache.idpSessionsByIndices.get(sessionIndex);

                if (idpSession != null) {
                    List list = idpSession.getNameIDandSPpairs();
                    if ((list != null) && (!list.isEmpty())) {
                        Iterator iter = list.iterator();
                        while (iter.hasNext()) {
                            NameIDandSPpair pair = (NameIDandSPpair) iter.next();

                            if (pair.getSPEntityID().equals(remoteEntityID)) {
                                nameIDValue = pair.getNameID().getValue();
                                break;
                            }
                        }
                    }
                }
            }
            if (nameIDValue == null) {
                nameIDValue = getNameIDValueFromUserProfile(realm, hostEntityID, remoteEntityID, userID, nameIDFormat);

                if (nameIDValue == null) {
                    nameIDValue = SAML2Utils.createNameIdentifier();
                }
            }
        } else {
            nameIDValue = getNameIDValueFromUserProfile(realm, hostEntityID, remoteEntityID, userID, nameIDFormat);

            if (nameIDValue == null) {
                if (nameIDFormat.equals(SAML2Constants.PERSISTENT)) {
                    nameIDValue = SAML2Utils.createNameIdentifier();
                } else {
                    throw new SAML2Exception(bundle.getString("unableToGenerateNameIDValue"));
                }
            }
        }


        NameID nameID = AssertionFactory.getInstance().createNameID();
        nameID.setValue(nameIDValue);
        nameID.setFormat(nameIDFormat);
        nameID.setNameQualifier(hostEntityID);
        nameID.setSPNameQualifier(remoteEntityID);
        nameID.setSPProvidedID(null);
        return nameID;
    }


    public String getIdentity(NameID nameID, String hostEntityID, String remoteEntityID, String realm)
            throws SAML2Exception {
        debug.warning("MyIDPAccountMapper -specific implementation received a call to getIdentity(). This is not supported by this implementation and will be deferred to the DefaultIDPAccountMapper delegate.");
        return defaultIDPAccountMapperDelegate.getIdentity(nameID, hostEntityID, remoteEntityID, realm);
    }


    @Override
    public boolean shouldPersistNameIDFormat(String realm, String hostEntityID, String remoteEntityID,
            String nameIDFormat) {
        return defaultIDPAccountMapperDelegate.shouldPersistNameIDFormat(realm, hostEntityID, remoteEntityID, nameIDFormat);
    }


    protected String getNameIDValueFromUserProfile(String realm, String hostEntityID, String remoteEntityID, String userID, String nameIDFormat) {
        if (debug.messageEnabled()) {
            debug.message("Asking NameID for user " + userID + ", nameId format " + nameIDFormat + ", SP entity : " + remoteEntityID);
        }
        String nameIDValue = null;
        Map<String, String> formatAttrMap = getFormatAttributeMap(realm, hostEntityID);

        String spSpecificNameIDFormat = nameIDFormat + ":" + remoteEntityID;
        String attrName = formatAttrMap.get(spSpecificNameIDFormat);

        if (attrName == null) {
            attrName = formatAttrMap.get(nameIDFormat);
            if (debug.messageEnabled()) {
                debug.message("Could not find a SP-specific attribute name, found generic attribute name : " + attrName);
            }
        } else {
            if (debug.messageEnabled()) {
                debug.message("Found SP-specific attribute name : " + attrName);
            }
        }


        if (attrName != null) {
            try {
                Set<String> attrValues = dsProvider.getAttribute(userID, attrName);
                if (attrValues != null && !attrValues.isEmpty()) {
                    nameIDValue = (String) attrValues.iterator().next();
                }
            } catch (DataStoreProviderException dspe) {
                if (debug.warningEnabled()) {
                    debug.warning("DefaultIDPAccountMapper.getNameIDValueFromUserProfile:", dspe);
                }
            }
        }


        return nameIDValue;
    }

    private Map<String, String> getFormatAttributeMap(String realm, String hostEntityID) {
        String key = hostEntityID + "|" + realm;
        Map<String, String> formatAttributeMap = IDPCache.formatAttributeHash.get(key);
        if (formatAttributeMap != null) {
            return formatAttributeMap;
        }

        formatAttributeMap = new HashMap<>();
        List<String> values = SAML2Utils.getAllAttributeValueFromSSOConfig(realm, hostEntityID, role,
                SAML2Constants.NAME_ID_FORMAT_MAP);
        if (values != null) {
            for (String value : values) {
                int index = value.indexOf('=');
                if (index != -1) {
                    String format = value.substring(0, index).trim();
                    String attrName = value.substring(index + 1).trim();
                    if (!format.isEmpty() && !attrName.isEmpty()) {
                        formatAttributeMap.put(format, attrName);
                    }
                }
            }
        }

        IDPCache.formatAttributeHash.put(key, formatAttributeMap);

        return formatAttributeMap;
    }
}