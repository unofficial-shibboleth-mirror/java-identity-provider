/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.saml.metadata.impl;

import static org.testng.Assert.assertEquals;

import java.util.Locale;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.resolver.filter.MetadataNodeProcessor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.testng.annotations.Test;

import net.shibboleth.idp.saml.metadata.IdPUIInfo;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

public final class UIInfoNodeProcessorTest extends BaseNodeProcessorTest {
    
    @Test 
    public void test() throws ResolverException {
        final EntityDescriptor entity  = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion("https://scopes.example.org")));

        final IDPSSODescriptor idpSSO = entity.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
        IdPUIInfo uiInfo = null;
        for (final XMLObject  x: idpSSO.getExtensions().getUnknownXMLObjects()) {
            if (!(x instanceof UIInfo)) {
                continue;
            }
            uiInfo = x.getObjectMetadata().get(IdPUIInfo.class).get(0);
            break;
        }
        
        
        final Locale l = Locale.forLanguageTag("en");
        assertEquals(uiInfo.getDisplayNames().get(l), "Display");
        assertEquals(uiInfo.getDescriptions().get(l), "Desc");
        assertEquals(uiInfo.getLocaleLogos().get(l).size(), 1);
        assertEquals(uiInfo.getNonLocaleLogos().size(), 2);
    }

    /** {@inheritDoc} */
    protected MetadataNodeProcessor getProcessor() {
        return new UIInfoNodeProcessor();
    }

}