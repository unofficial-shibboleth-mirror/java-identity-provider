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

package net.shibboleth.idp.saml.impl.profile;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.saml.authn.principal.NameIDPrincipal;
import net.shibboleth.idp.saml.authn.principal.NameIdentifierPrincipal;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.xml.XMLObjectBaseTestCase;
import org.opensaml.profile.ProfileException;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml1.core.Request;
import org.opensaml.saml.saml1.profile.SAML1ActionTestingSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.profile.SAML2ActionTestingSupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** Unit test for {@link ExtractSubjectFromRequest}. */
public class ExtractSubjectFromRequestTest extends XMLObjectBaseTestCase {

    private RequestContext rc;
    
    private ProfileRequestContext prc;
    
    private ExtractSubjectFromRequest action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        rc = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(rc);
        
        action = new ExtractSubjectFromRequest();
        action.setId("test");
        action.initialize();
    }

    @Test
    public void testNoInboundContext() throws ProfileException {
        prc.setInboundMessageContext(null);
        
        final Event event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, ExtractSubjectFromRequest.NO_SUBJECT);
    }
   
    @Test
    public void testNoMessage() throws ProfileException {
        prc.getInboundMessageContext().setMessage(null);
        
        final Event event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, ExtractSubjectFromRequest.NO_SUBJECT);
    }

    @Test
    public void testNoSubject() throws ProfileException {
        prc.getInboundMessageContext().setMessage(SAML2ActionTestingSupport.buildAuthnRequest());
        
        final Event event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, ExtractSubjectFromRequest.NO_SUBJECT);
    }

    @Test
    public void testSAML2Subject() throws ProfileException {
        final AuthnRequest request = SAML2ActionTestingSupport.buildAuthnRequest();
        request.setSubject(SAML2ActionTestingSupport.buildSubject("foo"));
        prc.getInboundMessageContext().setMessage(request);
        
        request.getSubject().getNameID().setNameQualifier("foo");
        Event event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_SUBJECT);
        
        request.getSubject().getNameID().setNameQualifier(ActionTestingSupport.OUTBOUND_MSG_ISSUER);
        request.getSubject().getNameID().setSPNameQualifier("foo");
        event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_SUBJECT);
        
        request.getSubject().getNameID().setSPNameQualifier(ActionTestingSupport.INBOUND_MSG_ISSUER);
        event = action.execute(rc);
        ActionTestingSupport.assertProceedEvent(event);
        
        final SubjectCanonicalizationContext scc = prc.getSubcontext(SubjectCanonicalizationContext.class);
        Assert.assertNotNull(scc);
        Assert.assertEquals(scc.getSubject().getPrincipals(NameIDPrincipal.class).size(), 1);
        
        final NameIDPrincipal princ = scc.getSubject().getPrincipals(NameIDPrincipal.class).iterator().next();
        Assert.assertEquals(princ.getNameID().getValue(), "foo");
    }
    
    @Test
    public void testSAML1Subject() throws ProfileException {
        final Request request = SAML1ActionTestingSupport.buildAttributeQueryRequest(
                SAML1ActionTestingSupport.buildSubject("foo"));
        prc.getInboundMessageContext().setMessage(request);
        
        request.getAttributeQuery().getSubject().getNameIdentifier().setNameQualifier("foo");
        Event event = action.execute(rc);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_SUBJECT);
        
        request.getAttributeQuery().getSubject().getNameIdentifier().setNameQualifier(ActionTestingSupport.OUTBOUND_MSG_ISSUER);
        event = action.execute(rc);
        ActionTestingSupport.assertProceedEvent(event);
        
        final SubjectCanonicalizationContext scc = prc.getSubcontext(SubjectCanonicalizationContext.class);
        Assert.assertNotNull(scc);
        Assert.assertEquals(scc.getSubject().getPrincipals(NameIdentifierPrincipal.class).size(), 1);
        
        final NameIdentifierPrincipal princ =
                scc.getSubject().getPrincipals(NameIdentifierPrincipal.class).iterator().next();
        Assert.assertEquals(princ.getNameIdentifier().getNameIdentifier(), "foo");
    }

}