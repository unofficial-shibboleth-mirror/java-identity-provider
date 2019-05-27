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

/**
 * {@link net.shibboleth.idp.attribute.IdPAttribute}s are protocol-agnostic 
 * units of information about some thing, usually a user.  Attributes and
 * their values are encoded in to protocol-specific formats by means of 
 * {@link net.shibboleth.idp.attribute.transcoding.AttributeTranscoder}s.
 */

package net.shibboleth.idp.attribute;