/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.innosense.sso.keycloak.actiontoken;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/**
 * @author Harijaona Ravelondrina <hravelondrina@gmail.com>
 * 
 */
public class ExternalAppActionToken extends DefaultActionToken {
    
    public static final String TOKEN_TYPE = "action-token-notification";

    private static final String JSON_FIELD_APP_ID = "applicationId";

    @JsonProperty(value = JSON_FIELD_APP_ID)
    private String applicationId;

    public ExternalAppActionToken(String userId, int absoluteExpirationInSecs, String authenticationSessionId, String applicationId) {
        super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null, authenticationSessionId);
        this.applicationId = applicationId;
    }

    private ExternalAppActionToken() {
        super();
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }
    
}
