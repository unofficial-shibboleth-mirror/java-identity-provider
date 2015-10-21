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

package net.shibboleth.idp.saml.saml2.profile.delegation.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.context.navigate.RelyingPartyIdLookupFunction;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.idp.saml.authn.principal.NameIDPrincipal;
import net.shibboleth.idp.saml.saml2.profile.delegation.LibertySSOSContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.wssecurity.SAML20AssertionToken;
import org.opensaml.soap.wssecurity.messaging.Token;
import org.opensaml.soap.wssecurity.messaging.Token.ValidationStatus;
import org.opensaml.soap.wssecurity.messaging.WSSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;


//TODO need a lot more Javadoc detail here, and event ID's supported.

/**
 * Process the pre-validated SAML 2 Assertion WS-Security token, and set up the resulting
 * NameID for subject canonicalization as the effective subject of the request.
 */
public class ProcessSAML20AssertionWSSToken extends AbstractProfileAction {
    
    /** Logger. */
    private Logger log = LoggerFactory.getLogger(ProcessSAML20AssertionWSSToken.class);
    

    /** Function used to obtain the requester ID. */
    @Nullable private Function<ProfileRequestContext,String> requesterLookupStrategy;

    /** Function used to obtain the responder ID. */
    @Nullable private Function<ProfileRequestContext,String> responderLookupStrategy;
    
    /** Function used to resolve the assertion token to process. */
    @Nonnull private Function<ProfileRequestContext, SAML20AssertionToken> assertionTokenStrategy;
    
    /** The SAML 2 Assertion token being processed. */
    private SAML20AssertionToken assertionToken;
    
    /** The SAML 2 NameID representing the authenticated user. */
    private NameID nameID;
    
    /**
     * Constructor.
     */
    public ProcessSAML20AssertionWSSToken() {
        requesterLookupStrategy = new RelyingPartyIdLookupFunction();
        responderLookupStrategy = new ResponderIdLookupFunction();
    }
    
    /**
     * Set the strategy used to locate the requester ID for canonicalization.
     * 
     * @param strategy lookup strategy
     */
    public void setAssertionTokenStrategy(
            @Nonnull final Function<ProfileRequestContext,SAML20AssertionToken> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        assertionTokenStrategy = Constraint.isNotNull(strategy, "Assertion token strategy may not be null");
    }
    
    /**
     * Set the strategy used to locate the requester ID for canonicalization.
     * 
     * @param strategy lookup strategy
     */
    public void setRequesterLookupStrategy(
            @Nullable final Function<ProfileRequestContext,String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        requesterLookupStrategy = strategy;
    }

    /**
     * Set the strategy used to locate the responder ID for canonicalization.
     * 
     * @param strategy lookup strategy
     */
    public void setResponderLookupStrategy(
            @Nullable final Function<ProfileRequestContext,String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        responderLookupStrategy = strategy;
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        
        assertionToken = assertionTokenStrategy.apply(profileRequestContext);
        
        if (assertionToken == null) {
            log.info("{} No valid SAML20AssertionToken available within inbound WSSecurityContext", getLogPrefix());
            //TODO can use this event ID here?
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        
        org.opensaml.saml.saml2.core.Subject samlSubject = assertionToken.getWrappedToken().getSubject();
        if (samlSubject == null || samlSubject.getNameID() == null) {
            log.info("{} SAML20AssertionToken does not contain either a Subject or a NameID", getLogPrefix());
            //TODO can use this event ID here?
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        
        nameID = samlSubject.getNameID();
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (log.isDebugEnabled()) {
            try {
                log.debug("{} Authenticated user based on inbound WS-Security SAML 2 Assertion token with NameID: {}", 
                        getLogPrefix(), SerializeSupport.nodeToString(XMLObjectSupport.marshall(nameID)));
            } catch (MarshallingException e) {
                log.debug("{} Could not marshall SAML 2 NameID for logging purposes", getLogPrefix(), e);
            }
        }
        
        // Populate Liberty context for use later.
        LibertySSOSContext ssosContext = profileRequestContext.getSubcontext(LibertySSOSContext.class, true);
        ssosContext.setAttestedToken(assertionToken.getWrappedToken());
        ssosContext.setAttestedSubjectConfirmationMethod(assertionToken.getSubjectConfirmation().getMethod());
        
        // Set up Subject c14n context for call to c14n subflow.
        Subject subject = new Subject();
        subject.getPrincipals().add(new NameIDPrincipal(nameID));
        
        final SubjectCanonicalizationContext c14n = new SubjectCanonicalizationContext();
        c14n.setSubject(subject);
        if (requesterLookupStrategy != null) {
            c14n.setRequesterId(requesterLookupStrategy.apply(profileRequestContext));
        }
        if (responderLookupStrategy != null) {
            c14n.setResponderId(responderLookupStrategy.apply(profileRequestContext));
        }
        profileRequestContext.addSubcontext(c14n, true);
    }
    
    /**
     * Default strategy for resolving the assertion token to process.
     * 
     * <p>This impl just returns the first valid {@link SAML20AssertionToken} found
     * in the inbound {@link WSSecurityContext}.</p>
     */
    public class TokenStrategy implements Function<ProfileRequestContext, SAML20AssertionToken> {

        /** {@inheritDoc} */
        @Nullable
        public SAML20AssertionToken apply(@Nullable ProfileRequestContext input) {
            if (input == null) {
                return null;
            }
            WSSecurityContext wssContext = 
                    input.getInboundMessageContext().getSubcontext(WSSecurityContext.class);
            if (wssContext == null) {
                log.info("{} No WSSecurityContext available within inbound message context", getLogPrefix());
                return null;
            }
            
            for (Token token : wssContext.getTokens()) {
                if (token.getValidationStatus().equals(ValidationStatus.VALID) 
                        && token instanceof SAML20AssertionToken) {
                    return (SAML20AssertionToken) token;
                }
            }
            return null;
        }
        
    }
    
}
