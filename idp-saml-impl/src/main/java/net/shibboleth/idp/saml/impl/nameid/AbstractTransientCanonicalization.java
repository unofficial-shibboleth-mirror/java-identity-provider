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

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.SubjectCanonicalizationException;
import net.shibboleth.idp.saml.nameid.TransientIdParameters;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO
 * An abstract action which contains the logic to do transient decoding matching (shared between SAML2
 * and SAML1).
 */
public abstract class AbstractTransientCanonicalization extends AbstractSAMLNameCanonicalization {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractTransientCanonicalization.class);

    /** Store used to map identifiers to principals. */
    @NonnullAfterInit private StorageService idStore;

    /**
     * Gets the ID store we are using.
     * 
     * @return the ID store we are using.
     */
    @NonnullAfterInit public StorageService getIdStore() {
        return idStore;
    }

    /**
     * Sets the ID store we should use.
     * 
     * @param store the store to use.
     */
    public void setIdStore(@Nonnull final StorageService store) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        idStore = Constraint.isNotNull(store, "StorageService cannot be null");
    }

    /**
     * Convert the transient Id into the principal.
     * 
     * @param transientId the transientID
     * @param requesterId the SP
     * @return the decoded entity.
     * @throws SubjectCanonicalizationException if a decode error occurrs.
     */
    protected String decode(@Nullable String transientId, @Nonnull String requesterId)
            throws SubjectCanonicalizationException {
        Constraint.isNotNull(requesterId, "Supplied requested should be null");

        if (null == transientId) {
            throw new SubjectCanonicalizationException(getLogPrefix() + " transient Identifier was null");
        }

        try {
            final StorageRecord record = idStore.read(TransientIdParameters.CONTEXT, transientId);

            if (null == record) {
                throw new SubjectCanonicalizationException(getLogPrefix() + " Could not find transient Identifier");
            }

            if (record.getExpiration() < System.currentTimeMillis()) {
                throw new SubjectCanonicalizationException(getLogPrefix() + " Transient identifier has expired");
            }

            final TransientIdParameters param = new TransientIdParameters(record.getValue());

            if (!requesterId.equals(param.getAttributeRecipient())) {
                throw new SubjectCanonicalizationException(getLogPrefix() + " Transient identifier was issued to "
                        + param.getAttributeRecipient() + " but is being used by " + requesterId);
            }

            return param.getPrincipal();
        } catch (IOException e) {
            throw new SubjectCanonicalizationException(e);
        }
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (null == idStore) {
            throw new ComponentInitializationException(getLogPrefix() + " no Id store set");
        }
        log.debug("{} using the store '{}'", getLogPrefix(), idStore.getId());
    }
}
