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

package net.shibboleth.idp.session.context;

import java.util.HashMap;
import java.util.Map;

import net.shibboleth.idp.session.SPSession;
import net.shibboleth.utilities.java.support.annotation.constraint.Live;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.messaging.context.BaseContext;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Context holding information needed to perform logout for a single SP session.
 *
 * @author Marvin S. Addison
 */
public class LogoutPropagationContext extends BaseContext {

    /** Logout propagation result. */
    public enum Result {
        /** Successful logout propagation result. */
        Success,

        /** Failed logout propagation result. */
        Failure
    }

    /** SP session to be destroyed. */
    @Nullable private SPSession session;

    /** Result of logout propagation flow. */
    @Nonnull private Result result = Result.Failure;

    /** Details of result, typically only populated for failures. */
    @Nullable private String detail;

    /** End state view name to render. */
    @Nullable private String resultView;

    /** View model map. */
    @Nonnull @Live private final Map<String, Object> viewMap = new HashMap<>();


    /**
     * Get the {@link SPSession} being destroyed by the logout propagation.
     *  
     * @return the SP session to be destroyed
     */
    @Nullable public SPSession getSession() {
        return session;
    }

    /**
     * Set the {@link SPSession} to be destroyed.
     *
     * @param theSession non-null SP session.
     */
    public void setSession(@Nonnull final SPSession theSession) {
        session = Constraint.isNotNull(theSession, "SPSession cannnot be null");
    }

    /**
     * Get the result of the logout propagation.
     * 
     * @return logout propagation result
     */
    @Nonnull public Result getResult() {
        return result;
    }

    /**
     * Set the logout propagation result.
     *
     * @param theResult non-null result
     */
    public void setResult(@Nonnull final Result theResult) {
        result = Constraint.isNotNull(theResult, "Result cannot be null");
    }

    /**
     * Set the logout propagation result from a string representation of {@link Result}.
     *
     * @param resultString Non-null string representation of {@link Result}.
     */
    public void setResultString(@Nonnull final String resultString) {
        result = Enum.valueOf(Result.class, Constraint.isNotNull(resultString, "Result cannot be null"));
    }

    /**
     * Get detailed message regarding result of logout propagation.
     * 
     * @return logout propagation result detail message
     */
    @Nullable public String getDetail() {
        return detail;
    }

    /**
     * Set the logout propagation result detail message.
     *
     * @param msg result detail message.
     */
    public void setDetail(@Nullable String msg) {
        detail = msg;
    }

    /**
     * Get the name of the view to be rendered at the end of the logout propagation flow.
     * 
     * @return name of the view to be rendered
     */
    @Nullable  public String getResultView() {
        return resultView;
    }

    /**
     * Set the name of the view to render at the end of the logout propagation flow.
     *
     * @param viewName logical view name.
     */
    public void setResultView(@Nonnull String viewName) {
        resultView = Constraint.isNotNull(viewName, "View name cannot be null");
    }

    /**
     * Get the model for the view to render.
     * 
     * @return view model map
     */
    @Nonnull public Map<String, Object> getViewMap() {
        return viewMap;
    }
    
}