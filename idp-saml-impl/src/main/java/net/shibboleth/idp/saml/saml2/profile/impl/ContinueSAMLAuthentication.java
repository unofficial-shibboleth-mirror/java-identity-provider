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

package net.shibboleth.idp.saml.saml2.profile.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that checks for an {@link ExternalAuthenticationContext} for a signaled event via the
 * {@link ExternalAuthenticationContext#getAuthnError()} method, and otherwise enforces the presence
 * of an inbound SAML Response to process.
 * 
 * <p>This is a bridge from the external portion of the SAML proxy implementation to transition
 * back into the flow and pick up any signaled errors if necessary.</p>
 *  
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#MESSAGE_PROC_ERROR}
 * @event {@link AuthnEventIds#INVALID_AUTHN_CTX}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event various
 */
public class ContinueSAMLAuthentication extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ContinueSAMLAuthentication.class);

    /** Context containing the result to examine. */
    @Nullable private ExternalAuthenticationContext extContext;

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        
        extContext = authenticationContext.getSubcontext(ExternalAuthenticationContext.class);
        if (extContext == null) {
            log.debug("{} No ExternalAuthenticationContext available within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (extContext.getAuthnError() != null) {
            log.info("{} SAML authentication attempt signaled an error: {}", getLogPrefix(),
                    extContext.getAuthnError());
            ActionSupport.buildEvent(profileRequestContext, extContext.getAuthnError());
        } else if (profileRequestContext.getInboundMessageContext() == null) {
            log.info("{} No inbound SAML Response found", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
        } else if (!(profileRequestContext.getInboundMessageContext().getMessage() instanceof Response)) {
            log.info("{} Inbound message was not a SAML Response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_PROC_ERROR);
        }
        
        final Response response = (Response) profileRequestContext.getInboundMessageContext().getMessage();
        if (response.getStatus() == null || response.getStatus().getStatusCode() == null ||
                response.getStatus().getStatusCode().getValue() == null) {
            log.info("{} SAML response did not contain a StatusCode", getLogPrefix());
            authenticationContext.removeSubcontext(SAMLAuthnContext.class);
            ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_PROC_ERROR);
        } else if (!StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
            log.info("{} SAML response contained error status: {}", getLogPrefix(),
                    response.getStatus().getStatusCode().getValue());
            authenticationContext.removeSubcontext(SAMLAuthnContext.class);
            ActionSupport.buildEvent(profileRequestContext, EventIds.MESSAGE_PROC_ERROR);
        }
    }
    
}