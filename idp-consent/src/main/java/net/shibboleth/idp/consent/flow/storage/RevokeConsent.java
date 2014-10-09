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

package net.shibboleth.idp.consent.flow.storage;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Consent action which deletes records from storage.
 */
// TODO Support revocation of multiple consent flows, not just the first
public class RevokeConsent extends AbstractConsentStorageAction {

    /** Storage service. */
    @Nullable private StorageService storageService;

    /** Storage context. */
    @Nullable @NotEmpty private String context;

    /** Storage key. */
    @Nullable @NotEmpty private String key;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(RevokeConsent.class);

    /** {@inheritDoc} */
    @Override protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final ProfileInterceptorContext interceptorContext) {

        if (!super.doPreExecute(profileRequestContext, interceptorContext)) {
            return false;
        }

        storageService = getStorageService();

        context = getContext();

        key = getKey();

        return true;
    }

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final ProfileInterceptorContext interceptorContext) {

        log.debug("{} Attempting to delete consent storage record with context '{}' and key '{}'", getLogPrefix(),
                context, key);
        boolean success;
        try {
            success = getStorageService().delete(context, key);
            if (success) {
                log.debug("{} Deleted consent storage record with context '{}' and key '{}'", getLogPrefix(), context,
                        key);
            } else {
                log.warn("{} Unable to delete consent storage record with context '{}' and key '{}'", getLogPrefix(),
                        context, key);
                // TODO build appropriate event
            }
        } catch (IOException e) {
            log.error("{} Unable to delete consent storage record with context '{}' and key '{}'", getLogPrefix(),
                    context, key, e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
        }
    }

}
