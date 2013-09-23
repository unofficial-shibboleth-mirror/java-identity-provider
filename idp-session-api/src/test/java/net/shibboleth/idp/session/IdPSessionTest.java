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

package net.shibboleth.idp.session;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.UsernamePrincipal;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.testng.Assert;
import org.testng.annotations.Test;

/** {@link BaseIdPSession} unit test. */
public class IdPSessionTest {

    /** Tests that everything is properly initialized during object construction. */
    @Test public void testInstantiation() throws Exception {
        long start = System.currentTimeMillis();
        Thread.sleep(50);

        BaseIdPSession session = new DummyIdPSession("test", "foo");
        Assert.assertNotNull(session.getAuthenticationResults());
        Assert.assertTrue(session.getAuthenticationResults().isEmpty());
        Assert.assertTrue(session.getCreationInstant() > start);
        Assert.assertEquals(session.getId(), "test");
        Assert.assertEquals(session.getPrincipalName(), "foo");
        Assert.assertEquals(session.getLastActivityInstant(), session.getCreationInstant());
        Assert.assertNotNull(session.getServiceSessions());
        Assert.assertTrue(session.getServiceSessions().isEmpty());

        try {
            new DummyIdPSession(null, null);
            Assert.fail();
        } catch (ConstraintViolationException e) {

        }

        try {
            new DummyIdPSession("", "");
            Assert.fail();
        } catch (ConstraintViolationException e) {

        }

        try {
            new DummyIdPSession("  ", "  ");
            Assert.fail();
        } catch (ConstraintViolationException e) {

        }

        try {
            new DummyIdPSession("test", null);
            Assert.fail();
        } catch (ConstraintViolationException e) {

        }
    }

    /** Tests mutating the last activity instant. */
    @Test public void testLastActivityInstant() throws Exception {
        BaseIdPSession session = new DummyIdPSession("test", "foo");

        long now = System.currentTimeMillis();
        // this is here to allow the event's last activity time to deviate from the time 'now'
        Thread.sleep(50);

        session.setLastActivityInstantToNow();
        Assert.assertTrue(session.getLastActivityInstant() > now);

        session.setLastActivityInstant(now);
        Assert.assertEquals(session.getLastActivityInstant(), now);
    }

    /** Tests mutating the last activity instant. */
    @Test public void testAddressValidation() throws Exception {
        BaseIdPSession session = new DummyIdPSession("test", "foo");

        Assert.assertTrue(session.validate("127.0.0.1"));
        Assert.assertTrue(session.validate("127.0.0.1"));
        Assert.assertFalse(session.validate("127.0.0.2"));
        Assert.assertTrue(session.validate("::1"));
        Assert.assertTrue(session.validate("::1"));
        Assert.assertFalse(session.validate("fe80::5a55:caff:fef2:65a3"));
    }
    
    /** Tests adding service sessions. */
    @Test public void testAddServiceSessions() {
        long now = System.currentTimeMillis();
        long exp = now + 60000L;
        
        BasicServiceSession svcSession1 = new BasicServiceSession("svc1", "test", now, exp);
        BasicServiceSession svcSession2 = new BasicServiceSession("svc2", "test", now, exp);
        BasicServiceSession svcSession3 = new BasicServiceSession("svc3", "test", now, exp);

        BaseIdPSession session = new DummyIdPSession("test", "foo");
        session.addServiceSession(svcSession1);
        Assert.assertEquals(session.getServiceSessions().size(), 1);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession1));
        Assert.assertEquals(session.getServiceSession("svc1"), svcSession1);

        session.addServiceSession(svcSession2);
        Assert.assertEquals(session.getServiceSessions().size(), 2);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession1));
        Assert.assertEquals(session.getServiceSession("svc1"), svcSession1);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
        Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);

        session.addServiceSession(svcSession3);
        Assert.assertEquals(session.getServiceSessions().size(), 3);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession1));
        Assert.assertEquals(session.getServiceSession("svc1"), svcSession1);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
        Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession3));
        Assert.assertEquals(session.getServiceSession("svc3"), svcSession3);

        try {
            session.addServiceSession(null);
            Assert.fail();
        } catch (ConstraintViolationException e) {
            Assert.assertEquals(session.getServiceSessions().size(), 3);
            Assert.assertTrue(session.getServiceSessions().contains(svcSession1));
            Assert.assertEquals(session.getServiceSession("svc1"), svcSession1);
            Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
            Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);
            Assert.assertTrue(session.getServiceSessions().contains(svcSession3));
            Assert.assertEquals(session.getServiceSession("svc3"), svcSession3);
        }

        session.addServiceSession(svcSession1);
        Assert.assertEquals(session.getServiceSessions().size(), 3);
        Assert.assertTrue(session.getServiceSessions().contains(svcSession1));
        Assert.assertEquals(session.getServiceSession("svc1"), svcSession1);
    }

    /** Tests removing service sessions. */
    @Test public void testRemoveServiceSession() {
        long now = System.currentTimeMillis();
        long exp = now + 60000L;

        BasicServiceSession svcSession1 = new BasicServiceSession("svc1", "test", now, exp);
        BasicServiceSession svcSession2 = new BasicServiceSession("svc2", "test", now, exp);

        BaseIdPSession session = new DummyIdPSession("test", "foo");
        session.addServiceSession(svcSession1);
        session.addServiceSession(svcSession2);

        Assert.assertTrue(session.removeServiceSession(svcSession1));
        Assert.assertEquals(session.getServiceSessions().size(), 1);
        Assert.assertFalse(session.getServiceSessions().contains(svcSession1));
        Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
        Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);

        Assert.assertFalse(session.removeServiceSession(svcSession1));
        Assert.assertEquals(session.getServiceSessions().size(), 1);
        Assert.assertFalse(session.getServiceSessions().contains(svcSession1));
        Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
        Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);

        try {
            session.removeServiceSession(null);
            Assert.fail();
        } catch (ConstraintViolationException e) {
            Assert.assertEquals(session.getServiceSessions().size(), 1);
            Assert.assertFalse(session.getServiceSessions().contains(svcSession1));
            Assert.assertTrue(session.getServiceSessions().contains(svcSession2));
            Assert.assertEquals(session.getServiceSession("svc2"), svcSession2);
        }
    }

    /** Tests remove authentication results. */
    @Test public void testRemoveAuthenticationResult() {
        AuthenticationResult event1 = new AuthenticationResult("foo", new UsernamePrincipal("john"));
        AuthenticationResult event2 = new AuthenticationResult("bar", new UsernamePrincipal("john"));
        AuthenticationResult event3 = new AuthenticationResult("baz", new UsernamePrincipal("john"));

        BaseIdPSession session = new DummyIdPSession("test", "foo");
        session.addAuthenticationResult(event1);
        session.addAuthenticationResult(event2);
        session.addAuthenticationResult(event3);

        session.removeAuthenticationResult(event2);
        Assert.assertEquals(session.getAuthenticationResults().size(), 2);
        Assert.assertTrue(session.getAuthenticationResults().contains(event1));
        Assert.assertEquals(session.getAuthenticationResult("foo"), event1);
        Assert.assertTrue(session.getAuthenticationResults().contains(event3));
        Assert.assertEquals(session.getAuthenticationResult("baz"), event3);

        session.removeAuthenticationResult(event3);
        Assert.assertEquals(session.getAuthenticationResults().size(), 1);
        Assert.assertTrue(session.getAuthenticationResults().contains(event1));
        Assert.assertEquals(session.getAuthenticationResult("foo"), event1);

        try {
            session.removeAuthenticationResult(null);
            Assert.fail();
        } catch (ConstraintViolationException e) {
            Assert.assertEquals(session.getAuthenticationResults().size(), 1);
            Assert.assertTrue(session.getAuthenticationResults().contains(event1));
            Assert.assertEquals(session.getAuthenticationResult("foo"), event1);
        }
    }

    /**
     * Dummy concrete class for testing purposes.
     */
    private class DummyIdPSession extends BaseIdPSession {

        /**
         * Constructor.
         *
         * @param sessionId
         * @param canonicalName
         */
        public DummyIdPSession(String sessionId, String canonicalName) {
            super(sessionId, canonicalName);
        }

        /** {@inheritDoc} */
        protected boolean doTimeoutCheck() {
            return true;
        }
    }
}