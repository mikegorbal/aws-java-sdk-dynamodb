/*
 * Copyright 2011-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.http;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.http.DelegatingDnsResolver;
import com.amazonaws.http.IdleConnectionReaper;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.impl.conn.SchemeRegistryFactory;
import org.apache.http.params.HttpParams;

import java.util.concurrent.TimeUnit;

/**
 * Responsible for creating and configuring instances of Apache HttpClient4's
 * Connection Manager.
 */
class ConnectionManagerFactory {

    public static PoolingClientConnectionManager createPoolingClientConnManager(
            ClientConfiguration config,
            HttpParams httpClientParams) {

        PoolingClientConnectionManager connectionManager = new PoolingClientConnectionManager(
                SchemeRegistryFactory.createDefault(),
                config.getConnectionTTL(),
                TimeUnit.MILLISECONDS,
                new DelegatingDnsResolver(config.getDnsResolver()));

        connectionManager.setDefaultMaxPerRoute(config.getMaxConnections());
        connectionManager.setMaxTotal(config.getMaxConnections());

        if (config.useReaper()) {
            IdleConnectionReaper.registerConnectionManager(connectionManager);
        }

        return connectionManager;
    }
}
