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

import org.wso2.carbon.identity.application.authenticator.oidc.debug.OIDCDebugCallbackHandler;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.OIDCDebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.extension.DebugProtocolProvider;

/**
 * GitHub-specific debug protocol provider.
 */
public class GitHubDebugProtocolProvider implements DebugProtocolProvider {

    private static final String PROTOCOL_TYPE = "GitHub";

    private final DebugContextProvider contextProvider = new GitHubDebugContextProvider();
    private final DebugExecutor executor = new OIDCDebugExecutor();
    private final DebugProcessor processor = new GitHubDebugProcessor();
    private final DebugCallbackHandler callbackHandler = new OIDCDebugCallbackHandler(processor, PROTOCOL_TYPE);

    @Override
    public String getProtocolType() {

        return PROTOCOL_TYPE;
    }

    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    @Override
    public DebugProcessor getProcessor() {

        return processor;
    }

    @Override
    public DebugCallbackHandler getCallbackHandler() {

        return callbackHandler;
    }

    @Override
    public boolean supports(String protocolType) {

        return PROTOCOL_TYPE.equalsIgnoreCase(protocolType);
    }
}
