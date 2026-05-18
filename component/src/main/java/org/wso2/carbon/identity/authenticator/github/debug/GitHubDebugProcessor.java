/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.github.debug;

import org.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OIDCDebugConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OIDCDebugProcessor;
import org.wso2.carbon.identity.authenticator.github.GithubAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.github.GithubExecutorUtil;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.util.Map;

/**
 * GitHub-specific debug processor.
 * Extends the shared OIDC processor but allows OAuth-style claim extraction without an ID token.
 */
public class GitHubDebugProcessor extends OIDCDebugProcessor {

    private static final Log LOG = LogFactory.getLog(GitHubDebugProcessor.class);

    @Override
    protected Map<String, Object> extractDebugData(DebugContext context) {

        Map<String, Object> claims = new HashMap<>(super.extractDebugData(context));
        if (!claims.isEmpty()) {
            normalizeGitHubIdentifierClaims(claims);
            context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            return claims;
        }

        String accessToken = (String) context.getProperty(OIDCDebugConstants.ACCESS_TOKEN);
        if (StringUtils.isBlank(accessToken)) {
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            return claims;
        }

        String userInfoEndpoint = (String) context.getProperty(GitHubDebugConstants.USERINFO_ENDPOINT);
        if (StringUtils.isBlank(userInfoEndpoint)) {
            userInfoEndpoint = (String) context.getProperty(GitHubDebugConstants.USERINFO);
        }
        if (StringUtils.isBlank(userInfoEndpoint)) {
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            return claims;
        }

        try {
            Map<String, Object> userInfoClaims = fetchUserInfoClaims(userInfoEndpoint, accessToken);
            if (userInfoClaims != null) {
                claims.putAll(userInfoClaims);
            }
            enrichPrimaryEmail(claims, accessToken, context);
            normalizeGitHubIdentifierClaims(claims);
            normalizeComplexClaimValues(claims);

            if (!claims.isEmpty()) {
                context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
                context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            } else {
                context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            }
            return claims;
        } catch (Exception e) {
            LOG.error("Error extracting GitHub user claims from user info endpoint: " + e.getMessage(), e);
            context.setProperty(OIDCDebugConstants.STEP_CLAIM_EXTRACTION_STATUS, OIDCDebugConstants.STATUS_FAILED);
            return new HashMap<>();
        }
    }

    private Map<String, Object> fetchUserInfoClaims(String userInfoEndpoint, String accessToken) throws Exception {

        HttpURLConnection connection = (HttpURLConnection) new URL(userInfoEndpoint).openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);
        connection.setRequestProperty("Accept", "application/json");

        int statusCode = connection.getResponseCode();
        if (statusCode != HttpURLConnection.HTTP_OK) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to retrieve GitHub user info. Status code: " + statusCode);
            }
            return new HashMap<>();
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            StringBuilder builder = new StringBuilder();
            String inputLine;
            while ((inputLine = reader.readLine()) != null) {
                builder.append(inputLine);
            }
            return jsonObjectToMap(new JSONObject(builder.toString()));
        }
    }

    private Map<String, Object> jsonObjectToMap(JSONObject jsonObject) {

        Map<String, Object> values = new HashMap<>();
        Iterator<String> keys = jsonObject.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            values.put(key, jsonObject.opt(key));
        }
        return values;
    }

    private void enrichPrimaryEmail(Map<String, Object> claims, String accessToken, DebugContext context) {

        if (claims.get(GithubAuthenticatorConstants.USER_EMAIL) != null) {
            return;
        }

        boolean usePrimaryEmail = Boolean.parseBoolean(
                String.valueOf(context.getProperty(GithubAuthenticatorConstants.USE_PRIMARY_EMAIL)));
        if (!usePrimaryEmail) {
            return;
        }

        String scope = String.valueOf(context.getProperty(OIDCDebugConstants.IDP_SCOPE));
        if (StringUtils.isBlank(scope) || (!scope.contains(GithubAuthenticatorConstants.USER_SCOPE)
                && !scope.contains(GithubAuthenticatorConstants.USER_EMAIL_SCOPE))) {
            return;
        }

        try {
            String primaryEmail = GithubExecutorUtil.getPrimaryEmail(
                    GithubAuthenticatorConstants.GITHUB_USER_EMAILS_ENDPOINT, accessToken);
            if (StringUtils.isNotBlank(primaryEmail)) {
                claims.put(GithubAuthenticatorConstants.USER_EMAIL, primaryEmail);
            }
        } catch (Exception e) {
            LOG.debug("Unable to retrieve GitHub primary email for debug flow", e);
        }
    }

    private void normalizeGitHubIdentifierClaims(Map<String, Object> claims) {

        Object userId = claims.get(GithubAuthenticatorConstants.USER_ID);
        if (userId != null) {
            String normalizedUserId = String.valueOf(userId);
            claims.put("user_id", normalizedUserId);
            claims.put("userId", normalizedUserId);
            claims.put("sub", normalizedUserId);
        }
    }

    private void normalizeComplexClaimValues(Map<String, Object> claims) {

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map || value instanceof List || value != null && value.getClass().isArray()) {
                entry.setValue(String.valueOf(value));
            }
        }
    }
}
