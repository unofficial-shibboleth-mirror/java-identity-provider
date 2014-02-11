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

package net.shibboleth.idp.saml.impl.profile.saml2;

import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.Assert;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.ProfileException;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.profile.SAMLEventIds;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.profile.SAML2ActionTestingSupport;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.crypto.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;

/** Unit test for {@link DecryptNameIDs}. */
public class DecryptNameIDsTest extends OpenSAMLInitBaseTestCase {
    
    private KeyInfoCredentialResolver keyResolver;
    
    private String encURI;
    
    private EncryptionParameters encParams;
    
    private Encrypter encrypter;

    private RequestContext src; 
    
    private ProfileRequestContext prc;
    
    private DecryptNameIDs action;
    
    private SAMLObjectBuilder<NameID> nameIdBuilder;

    private SAMLObjectBuilder<Subject> subjectBuilder;
    
    @BeforeMethod
    public void setUp() throws NoSuchAlgorithmException, KeyException, ComponentInitializationException {
        encURI = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;
        nameIdBuilder = (SAMLObjectBuilder<NameID>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<NameID>getBuilderOrThrow(
                        NameID.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Subject>getBuilderOrThrow(
                        Subject.DEFAULT_ELEMENT_NAME);

        Credential encCred = AlgorithmSupport.generateSymmetricKeyAndCredential(encURI);
        keyResolver = new StaticKeyInfoCredentialResolver(encCred);
        encParams = new EncryptionParameters();
        encParams.setAlgorithm(encURI);
        encParams.setEncryptionCredential(encCred);
        
        encrypter = new Encrypter(encParams);
        
        final DecryptionParameters decParams = new DecryptionParameters();
        decParams.setDataKeyInfoCredentialResolver(keyResolver);
        
        src = new RequestContextBuilder().buildRequestContext();
        prc = (ProfileRequestContext) src.getConversationScope().get(ProfileRequestContext.BINDING_KEY);
        prc.getSubcontext(SecurityParametersContext.class, true).setDecryptionParameters(decParams);
        
        action = new DecryptNameIDs();
        action.setId("test");
    }
    
    @Test
    public void testNoMessage() throws ComponentInitializationException, ProfileException {
        action.initialize();
        
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }
    
    /**
     * Test decryption of an NameID as an EncryptedID.
     *  
     * @throws EncryptionException
     * @throws ComponentInitializationException 
     * @throws ProfileException 
     */
    @Test
    public void testEncryptedNameID() throws EncryptionException, ComponentInitializationException, ProfileException {
        final AuthnRequest authnRequest = SAML2ActionTestingSupport.buildAuthnRequest();
        prc.getInboundMessageContext().setMessage(authnRequest);
        final Subject subject = subjectBuilder.buildObject();
        authnRequest.setSubject(subject);
        
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setFormat(NameID.TRANSIENT);
        nameId.setValue("foo");
        
        final EncryptedID encryptedTarget = encrypter.encrypt(nameId);
        subject.setEncryptedID(encryptedTarget);

        action.initialize();
        
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(authnRequest.getSubject().getNameID());
        Assert.assertEquals(authnRequest.getSubject().getNameID().getValue(), "foo");
        Assert.assertEquals(authnRequest.getSubject().getNameID().getFormat(), NameID.TRANSIENT);
    }

    /**
     * Test failed decryption of an NameID as an EncryptedID.
     *  
     * @throws EncryptionException
     * @throws ComponentInitializationException 
     * @throws ProfileException 
     * @throws KeyException 
     * @throws NoSuchAlgorithmException 
     */
    @Test
    public void testWrongKeyFatal() throws Exception {
        final AuthnRequest authnRequest = SAML2ActionTestingSupport.buildAuthnRequest();
        prc.getInboundMessageContext().setMessage(authnRequest);
        final Subject subject = subjectBuilder.buildObject();
        authnRequest.setSubject(subject);
        
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setFormat(NameID.TRANSIENT);
        nameId.setValue("foo");
        
        final EncryptedID encryptedTarget = encrypter.encrypt(nameId);
        subject.setEncryptedID(encryptedTarget);

        Credential encCred = AlgorithmSupport.generateSymmetricKeyAndCredential(encURI);
        KeyInfoCredentialResolver badKeyResolver = new StaticKeyInfoCredentialResolver(encCred);
        prc.getSubcontext(SecurityParametersContext.class).getDecryptionParameters().setDataKeyInfoCredentialResolver(
                badKeyResolver);
        
        action.initialize();
        
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, SAMLEventIds.DECRYPT_NAMEID_FAILED);
        Assert.assertNull(authnRequest.getSubject().getNameID());
    }

    /**
     * Test failed decryption of an NameID as an EncryptedID.
     *  
     * @throws EncryptionException
     * @throws ComponentInitializationException 
     * @throws ProfileException 
     * @throws KeyException 
     * @throws NoSuchAlgorithmException 
     */
    @Test
    public void testWrongKeyNonFatal() throws Exception {
        final AuthnRequest authnRequest = SAML2ActionTestingSupport.buildAuthnRequest();
        prc.getInboundMessageContext().setMessage(authnRequest);
        final Subject subject = subjectBuilder.buildObject();
        authnRequest.setSubject(subject);
        
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setFormat(NameID.TRANSIENT);
        nameId.setValue("foo");
        
        final EncryptedID encryptedTarget = encrypter.encrypt(nameId);
        subject.setEncryptedID(encryptedTarget);

        Credential encCred = AlgorithmSupport.generateSymmetricKeyAndCredential(encURI);
        KeyInfoCredentialResolver badKeyResolver = new StaticKeyInfoCredentialResolver(encCred);
        prc.getSubcontext(SecurityParametersContext.class).getDecryptionParameters().setDataKeyInfoCredentialResolver(
                badKeyResolver);
        
        action.setErrorFatal(false);
        action.initialize();
        
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(authnRequest.getSubject().getNameID());
    }
    
}