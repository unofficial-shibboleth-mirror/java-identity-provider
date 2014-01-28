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

package net.shibboleth.idp.saml.impl.nameid;

import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.SubjectCanonicalizationException;
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.saml.authn.principal.NameIDPrincipal;
import net.shibboleth.idp.saml.nameid.NameIdentifierAttributeDecoder;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.profile.ProfileException;
import org.opensaml.profile.action.ActionTestingSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** {@link SimpleSubjectCanonicalization} unit test. */
public class NameIDCanonicalizationTest extends OpenSAMLInitBaseTestCase {

    private ProfileRequestContext prc;

    private NameIDCanonicalization action;

    private NameIDBuilder builder;

    private static final String REQUESTER = "TestRequest";

    private static final String RESPONDER = "TestResp";

    private static final String VALUE_PREFIX = "TestPrefix";

    private static final List<String> formats = Arrays.asList(NameID.KERBEROS, NameID.ENCRYPTED, null);

    @BeforeClass public void initialize() {
        builder = new NameIDBuilder();
    }

    @BeforeMethod public void setUp() throws Exception {
        prc = new ProfileRequestContext<>();
        action = new NameIDCanonicalization();
        action.setFormats(formats);
        action.setDecoder(new NameIdentifierAttributeDecoder() {

            @Override @Nonnull public String decode(@Nullable String value, @Nonnull String issuerId,
                    @Nonnull String requesterId) throws SubjectCanonicalizationException {
                if (RESPONDER.equals(issuerId) && REQUESTER.equals(requesterId)) {
                    return VALUE_PREFIX + value;
                }
                throw new SubjectCanonicalizationException();
            }
        });
        action.initialize();
    }

    private void setSubContext(@Nullable Subject subject, @Nullable String responder, @Nullable String requester) {
        SubjectCanonicalizationContext scc = prc.getSubcontext(SubjectCanonicalizationContext.class, true);
        if (subject != null) {
            scc.setSubject(subject);
        }
        if (requester != null) {
            scc.setRequesterId(requester);
        }
        if (responder != null) {
            scc.setResponderId(responder);
        }
    }

    private NameID nameId(String value, String format, String nameQualifier) {

        NameID id = builder.buildObject();

        id.setValue(value);
        id.setFormat(format);
        id.setNameQualifier(nameQualifier);
        return id;
    }

    @Test public void testFormatCount() {
        Assert.assertEquals(action.getFormats().size(), 2);
    }

    @Test(expectedExceptions={UnsupportedOperationException.class}) public void testFormatSet() {
        action.getFormats().add("bar");
    }

    @Test public void testNoContext() throws ProfileException {
        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.INVALID_SUBJECT_C14N_CTX);
    }

    @Test public void testNoPrincipal() throws ProfileException {
        Subject subject = new Subject();
        setSubContext(subject, null, null);

        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.INVALID_SUBJECT);
        Assert.assertNotNull(prc.getSubcontext(SubjectCanonicalizationContext.class, false).getException());
    }

    @Test public void testMultiPrincipals() throws ProfileException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new NameIDPrincipal(nameId("value", NameID.KERBEROS, "qual")));
        subject.getPrincipals().add(new NameIDPrincipal(nameId("value2", NameID.X509_SUBJECT, "qual")));

        setSubContext(subject, null, null);

        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.INVALID_SUBJECT);
        Assert.assertNotNull(prc.getSubcontext(SubjectCanonicalizationContext.class, false).getException());
    }

    @Test public void testWrongFormat() throws ProfileException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new NameIDPrincipal(nameId("value", NameID.X509_SUBJECT, "qual")));

        setSubContext(subject, RESPONDER, REQUESTER);

        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.INVALID_SUBJECT);
        Assert.assertNotNull(prc.getSubcontext(SubjectCanonicalizationContext.class, false).getException());
    }

    @Test public void testWrongRequester() throws ProfileException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new NameIDPrincipal(nameId("value", NameID.KERBEROS, "qual")));
        setSubContext(subject, RESPONDER, RESPONDER);

        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.SUBJECT_C14N_ERROR);
        Assert.assertNotNull(prc.getSubcontext(SubjectCanonicalizationContext.class, false).getException());
    }

    @Test public void testWrongResponder() throws ProfileException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new NameIDPrincipal(nameId("value", NameID.KERBEROS, "qual")));
        setSubContext(subject, REQUESTER, REQUESTER);

        action.execute(prc);

        ActionTestingSupport.assertEvent(prc, AuthnEventIds.SUBJECT_C14N_ERROR);
        Assert.assertNotNull(prc.getSubcontext(SubjectCanonicalizationContext.class, false).getException());
    }

    @Test public void testSuccess() throws ProfileException {
        Subject subject = new Subject();
        subject.getPrincipals().add(new UsernamePrincipal("foo@osu.edu"));
        subject.getPrincipals().add(new NameIDPrincipal(nameId("works", NameID.KERBEROS, "qual")));
        setSubContext(subject, RESPONDER, REQUESTER);


        action.execute(prc);

        ActionTestingSupport.assertProceedEvent(prc);
        SubjectCanonicalizationContext sc = prc.getSubcontext(SubjectCanonicalizationContext.class, false);
        Assert.assertEquals(sc.getPrincipalName(), VALUE_PREFIX+"works");
    }

}