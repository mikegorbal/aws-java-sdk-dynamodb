//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.amazonaws.http;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.AmazonWebServiceResponse;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Request;
import com.amazonaws.RequestClientOptions;
import com.amazonaws.ResetException;
import com.amazonaws.Response;
import com.amazonaws.ResponseMetadata;
import com.amazonaws.SDKGlobalTime;
import com.amazonaws.AmazonServiceException.ErrorType;
import com.amazonaws.RequestClientOptions.Marker;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.Signer;
import com.amazonaws.event.ProgressEventType;
import com.amazonaws.event.ProgressInputStream;
import com.amazonaws.event.ProgressListener;
import com.amazonaws.event.SDKProgressPublisher;
import com.amazonaws.handlers.CredentialsRequestHandler;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.http.ExecutionContext;
import com.amazonaws.http.HttpClientFactory;
import com.amazonaws.http.HttpRequestFactory;
import com.amazonaws.http.HttpResponse;
import com.amazonaws.http.HttpResponseHandler;
import com.amazonaws.http.IdleConnectionReaper;
import com.amazonaws.http.UnreliableTestConfig;
import com.amazonaws.http.conn.ssl.SdkTLSSocketFactory;
import com.amazonaws.internal.CRC32MismatchException;
import com.amazonaws.internal.ReleasableInputStream;
import com.amazonaws.internal.ResettableInputStream;
import com.amazonaws.internal.SdkBufferedInputStream;
import com.amazonaws.metrics.RequestMetricCollector;
import com.amazonaws.retry.RetryPolicy;
import com.amazonaws.retry.RetryUtils;
import com.amazonaws.retry.internal.AuthErrorRetryStrategy;
import com.amazonaws.retry.internal.AuthRetryParameters;
import com.amazonaws.util.AWSRequestMetrics;
import com.amazonaws.util.CollectionUtils;
import com.amazonaws.util.CountingInputStream;
import com.amazonaws.util.DateUtils;
import com.amazonaws.util.FakeIOException;
import com.amazonaws.util.IOUtils;
import com.amazonaws.util.ResponseMetadataCache;
import com.amazonaws.util.TimingInfo;
import com.amazonaws.util.UnreliableFilterInputStream;
import com.amazonaws.util.AWSRequestMetrics.Field;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.net.ssl.SSLContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.StatusLine;
import org.apache.http.annotation.ThreadSafe;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.nio.client.HttpAsyncClient;
import org.apache.http.pool.ConnPoolControl;
import org.apache.http.pool.PoolStats;
import org.apache.http.protocol.BasicHttpContext;

@ThreadSafe
public class AmazonAsyncHttpClient {
/*
    private static final String HEADER_USER_AGENT = "User-Agent";
    private static final Log requestIdLog = LogFactory.getLog("com.amazonaws.requestId");
    private static final Log requestLog = LogFactory.getLog("com.amazonaws.request");
    static final Log log = LogFactory.getLog(AmazonHttpClient.class);
    private static final HttpRequestFactory httpRequestFactory = new HttpRequestFactory();
    private static final HttpClientFactory httpClientFactory = new HttpClientFactory();
    private final CloseableHttpAsyncClient httpClient;
    private final ClientConfiguration config;
    private final ResponseMetadataCache responseMetadataCache;
    private final RequestMetricCollector requestMetricCollector;
    private volatile int timeOffset;
    private static UnreliableTestConfig unreliableTestConfig;

    public AmazonAsyncHttpClient(ClientConfiguration config) {
        this(config, (RequestMetricCollector)null);
    }
/*
    public AmazonAsyncHttpClient(ClientConfiguration config, RequestMetricCollector requestMetricCollector) {
        this(config, httpClientFactory.createHttpClient(config), requestMetricCollector);
    }
*/
  /*  public AmazonAsyncHttpClient(ClientConfiguration config, RequestMetricCollector requestMetricCollector) {
        this(config, HttpAsyncClients.createDefault(), requestMetricCollector);
    }



    AmazonAsyncHttpClient(ClientConfiguration config, CloseableHttpAsyncClient httpClient, RequestMetricCollector requestMetricCollector) {
        this.timeOffset = SDKGlobalTime.getGlobalTimeOffset();
        this.config = config;
        this.httpClient = httpClient;
        this.requestMetricCollector = requestMetricCollector;
        this.responseMetadataCache = new ResponseMetadataCache(config.getResponseMetadataCacheSize());
    }

    public ResponseMetadata getResponseMetadataForRequest(AmazonWebServiceRequest request) {
        return this.responseMetadataCache.get(request);
    }

    public void disableStrictHostnameVerification() {
        if(System.getProperty("com.amazonaws.sdk.disableCertChecking") == null) {
            try {
                SchemeRegistry e = this.httpClient.getConnectionManager().getSchemeRegistry();
                Object sf = this.config.getApacheHttpClientConfig().getSslSocketFactory();
                if(sf == null) {
                    sf = new SdkTLSSocketFactory(SSLContext.getDefault(), SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
                }

                Scheme https = new Scheme("https", 443, (SchemeSocketFactory)sf);
                e.register(https);
            } catch (NoSuchAlgorithmException var4) {
                throw new AmazonClientException("Unable to access default SSL context to disable strict hostname verification");
            }
        }
    }

    public <T> Response<T> execute(Request<?> request, HttpResponseHandler<AmazonWebServiceResponse<T>> responseHandler, HttpResponseHandler<AmazonServiceException> errorResponseHandler, ExecutionContext executionContext) {
        if(executionContext == null) {
            throw new AmazonClientException("Internal SDK Error: No execution context parameter specified.");
        } else {
            List requestHandler2s = this.requestHandler2s(request, executionContext);
            AmazonWebServiceRequest awsreq = request.getOriginalRequest();
            ProgressListener listener = awsreq.getGeneralProgressListener();
            Map customHeaders = awsreq.getCustomRequestHeaders();
            if(customHeaders != null) {
                request.getHeaders().putAll(customHeaders);
            }

            Map customQueryParams = awsreq.getCustomQueryParameters();
            if(customQueryParams != null) {
                this.mergeQueryParameters(request, customQueryParams);
            }

            AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics();
            Response response = null;
            InputStream origContent = request.getContent();
            InputStream toBeClosed = this.beforeRequest(request);
            ReleasableInputStream notCloseable = toBeClosed == null?null:ReleasableInputStream.wrap(toBeClosed).disableClose();
            request.setContent(notCloseable);

            Response var16;
            try {
                SDKProgressPublisher.publishProgress(listener, ProgressEventType.CLIENT_REQUEST_STARTED_EVENT);
                response = this.executeHelper(request, responseHandler, errorResponseHandler, executionContext);
                SDKProgressPublisher.publishProgress(listener, ProgressEventType.CLIENT_REQUEST_SUCCESS_EVENT);
                TimingInfo e = awsRequestMetrics.getTimingInfo().endTiming();
                this.afterResponse(request, requestHandler2s, response, e);
                var16 = response;
            } catch (AmazonClientException var20) {
                SDKProgressPublisher.publishProgress(listener, ProgressEventType.CLIENT_REQUEST_FAILED_EVENT);
                this.afterError(request, response, requestHandler2s, var20);
                throw var20;
            } finally {
                IOUtils.closeQuietly(toBeClosed, log);
                request.setContent(origContent);
            }

            return var16;
        }
    }

    private void mergeQueryParameters(Request<?> request, Map<String, List<String>> params) {
        Map existingParams = request.getParameters();
        Iterator i$ = params.entrySet().iterator();

        while(i$.hasNext()) {
            Entry param = (Entry)i$.next();
            String pName = (String)param.getKey();
            List pValues = (List)param.getValue();
            existingParams.put(pName, CollectionUtils.mergeLists((List)existingParams.get(pName), pValues));
        }

    }

    private InputStream beforeRequest(Request<?> request) {
        AmazonWebServiceRequest awsreq = request.getOriginalRequest();
        ProgressListener listener = awsreq.getGeneralProgressListener();
        Map headers = request.getHeaders();
        String s = (String)headers.get("Content-Length");
        if(s != null) {
            try {
                long content = Long.parseLong(s);
                SDKProgressPublisher.publishRequestContentLength(listener, content);
            } catch (NumberFormatException var8) {
                log.warn("Cannot parse the Content-Length header of the request.");
            }
        }

        Object content1 = request.getContent();
        if(content1 == null) {
            return null;
        } else {
            if(!((InputStream)content1).markSupported() && content1 instanceof FileInputStream) {
                try {
                    content1 = new ResettableInputStream((FileInputStream)content1);
                } catch (IOException var9) {
                    if(log.isDebugEnabled()) {
                        log.debug("For the record; ignore otherwise", var9);
                    }
                }
            }

            if(!((InputStream)content1).markSupported()) {
                content1 = new SdkBufferedInputStream((InputStream)content1);
            }

            InputStream is = ProgressInputStream.inputStreamForRequest((InputStream)content1, awsreq);
            return (InputStream)(unreliableTestConfig == null?is:(new UnreliableFilterInputStream(is, unreliableTestConfig.isFakeIOException())).withBytesReadBeforeException(unreliableTestConfig.getBytesReadBeforeException()).withMaxNumErrors(unreliableTestConfig.getMaxNumErrors()).withResetIntervalBeforeException(unreliableTestConfig.getResetIntervalBeforeException()));
        }
    }

    private void afterError(Request<?> request, Response<?> response, List<RequestHandler2> requestHandler2s, AmazonClientException e) {
        Iterator i$ = requestHandler2s.iterator();

        while(i$.hasNext()) {
            RequestHandler2 handler2 = (RequestHandler2)i$.next();
            handler2.afterError(request, response, e);
        }

    }

    private <T> void afterResponse(Request<?> request, List<RequestHandler2> requestHandler2s, Response<T> response, TimingInfo timingInfo) {
        Iterator i$ = requestHandler2s.iterator();

        while(i$.hasNext()) {
            RequestHandler2 handler2 = (RequestHandler2)i$.next();
            handler2.afterResponse(request, response);
        }

    }

    private List<RequestHandler2> requestHandler2s(Request<?> request, ExecutionContext executionContext) {
        List requestHandler2s = executionContext.getRequestHandler2s();
        if(requestHandler2s == null) {
            return Collections.emptyList();
        } else {
            RequestHandler2 requestHandler2;
            for(Iterator i$ = requestHandler2s.iterator(); i$.hasNext(); requestHandler2.beforeRequest(request)) {
                requestHandler2 = (RequestHandler2)i$.next();
                if(requestHandler2 instanceof CredentialsRequestHandler) {
                    ((CredentialsRequestHandler)requestHandler2).setCredentials(executionContext.getCredentials());
                }
            }

            return requestHandler2s;
        }
    }

    private <T> Response<T> executeHelper(Request<?> request, HttpResponseHandler<AmazonWebServiceResponse<T>> responseHandler, HttpResponseHandler<AmazonServiceException> errorResponseHandler, ExecutionContext executionContext) {
        AWSRequestMetrics awsRequestMetrics = executionContext.getAwsRequestMetrics().addPropertyWith(Field.ServiceName, request.getServiceName()).addPropertyWith(Field.ServiceEndpoint, request.getEndpoint());
        this.setUserAgent(request);
        LinkedHashMap originalParameters = new LinkedHashMap(request.getParameters());
        HashMap originalHeaders = new HashMap(request.getHeaders());
        InputStream originalContent = request.getContent();
        if(originalContent != null && originalContent.markSupported()) {
            AmazonWebServiceRequest p = request.getOriginalRequest();
            int e = p.getRequestClientOptions().getReadLimit();
            originalContent.mark(e);
        }

        AmazonAsyncHttpClient.ExecOneRequestParams p1 = new AmazonAsyncHttpClient.ExecOneRequestParams();

        Response e7;
        while(true) {
            p1.initPerRetry();
            if(p1.redirectedURI != null) {
                String e3 = p1.redirectedURI.getScheme();
                String e1 = e3 == null?"":e3 + "://";
                String entity = p1.redirectedURI.getAuthority();
                String e2 = p1.redirectedURI.getPath();
                request.setEndpoint(URI.create(e1 + entity));
                request.setResourcePath(e2);
            }

            if(p1.authRetryParam != null) {
                request.setEndpoint(p1.authRetryParam.getEndpointForRetry());
            }

            awsRequestMetrics.setCounter(Field.RequestCount, (long)p1.requestCount);
            if(p1.isRetry()) {
                request.setParameters(originalParameters);
                request.setHeaders(originalHeaders);
                request.setContent(originalContent);
            }

            boolean var25 = false;

            HttpEntity e5;
            label224: {
                try {
                    label233: {
                        try {
                            var25 = true;
                            Response e4 = this.executeOneRequest(request, responseHandler, errorResponseHandler, executionContext, awsRequestMetrics, p1);
                            if(e4 != null) {
                                e7 = e4;
                                var25 = false;
                                break;
                            }

                            var25 = false;
                            break label233;
                        } catch (IOException var30) {
                            if(log.isInfoEnabled()) {
                                log.info("Unable to execute HTTP request: " + var30.getMessage(), var30);
                            }
                        } catch (RuntimeException var31) {
                            throw (RuntimeException)this.lastReset(this.captureExceptionMetrics(var31, awsRequestMetrics), request);
                        } catch (Error var32) {
                            throw (Error)this.lastReset(this.captureExceptionMetrics(var32, awsRequestMetrics), request);
                        }

                        this.captureExceptionMetrics(var30, awsRequestMetrics);
                        awsRequestMetrics.addProperty(Field.AWSRequestID, (Object)null);
                        AmazonClientException e6 = new AmazonClientException("Unable to execute HTTP request: " + var30.getMessage(), var30);
                        if(!this.shouldRetry(request.getOriginalRequest(), p1.apacheRequest, e6, p1.requestCount, this.config.getRetryPolicy())) {
                            throw (AmazonClientException)this.lastReset(e6, request);
                        }

                        p1.retriedException = e6;
                        var25 = false;
                        break label224;
                    }
                } finally {
                    if(var25) {
                        if(!p1.leaveHttpConnectionOpen && p1.apacheResponse != null) {
                            HttpEntity entity1 = p1.apacheResponse.getEntity();
                            if(entity1 != null) {
                                try {
                                    IOUtils.closeQuietly(entity1.getContent(), log);
                                } catch (IOException var26) {
                                    log.warn("Cannot close the response content.", var26);
                                }
                            }
                        }

                    }
                }

                if(!p1.leaveHttpConnectionOpen && p1.apacheResponse != null) {
                    e5 = p1.apacheResponse.getEntity();
                    if(e5 != null) {
                        try {
                            IOUtils.closeQuietly(e5.getContent(), log);
                        } catch (IOException var29) {
                            log.warn("Cannot close the response content.", var29);
                        }
                    }
                }
                continue;
            }

            if(!p1.leaveHttpConnectionOpen && p1.apacheResponse != null) {
                e5 = p1.apacheResponse.getEntity();
                if(e5 != null) {
                    try {
                        IOUtils.closeQuietly(e5.getContent(), log);
                    } catch (IOException var28) {
                        log.warn("Cannot close the response content.", var28);
                    }
                }
            }
        }

        if(!p1.leaveHttpConnectionOpen && p1.apacheResponse != null) {
            HttpEntity entity2 = p1.apacheResponse.getEntity();
            if(entity2 != null) {
                try {
                    IOUtils.closeQuietly(entity2.getContent(), log);
                } catch (IOException var27) {
                    log.warn("Cannot close the response content.", var27);
                }
            }
        }

        return e7;
    }

    private <T extends Throwable> T lastReset(T t, Request<?> req) {
        try {
            InputStream ex = req.getContent();
            if(ex != null && ex.markSupported()) {
                ex.reset();
            }
        } catch (Exception var4) {
            log.debug("FYI: failed to reset content inputstream before throwing up", var4);
        }

        return t;
    }

    private <T> Response<T> executeOneRequest(Request<?> request, HttpResponseHandler<AmazonWebServiceResponse<T>> responseHandler, HttpResponseHandler<AmazonServiceException> errorResponseHandler, ExecutionContext execContext, AWSRequestMetrics awsRequestMetrics, AmazonHttpClient.ExecOneRequestParams execParams) throws IOException {
        if(execParams.isRetry()) {
            InputStream credentials = request.getContent();
            if(credentials != null && credentials.markSupported()) {
                try {
                    credentials.reset();
                } catch (IOException var32) {
                    throw new ResetException("Failed to reset the request input stream", var32);
                }
            }
        }

        if(requestLog.isDebugEnabled()) {
            requestLog.debug("Sending Request: " + request);
        }

        AWSCredentials credentials1 = execContext.getCredentials();
        AmazonWebServiceRequest awsreq = request.getOriginalRequest();
        ProgressListener listener = awsreq.getGeneralProgressListener();
        if(execParams.isRetry()) {
            SDKProgressPublisher.publishProgress(listener, ProgressEventType.CLIENT_REQUEST_RETRY_EVENT);
            awsRequestMetrics.startEvent(Field.RetryPauseTime);

            try {
                if(execParams.retriedException != null) {
                    this.pauseBeforeNextRetry(request.getOriginalRequest(), execParams.retriedException, execParams.requestCount, this.config.getRetryPolicy());
                }
            } finally {
                awsRequestMetrics.endEvent(Field.RetryPauseTime);
            }
        }

        execParams.newSigner(request, execContext);
        if(execParams.signer != null && credentials1 != null) {
            awsRequestMetrics.startEvent(Field.RequestSigningTime);

            try {
                if(this.timeOffset != 0) {
                    request.setTimeOffset(this.timeOffset);
                }

                execParams.signer.sign(request, credentials1);
            } finally {
                awsRequestMetrics.endEvent(Field.RequestSigningTime);
            }
        }

        execParams.newApacheRequest(httpRequestFactory, request, this.config, execContext);
        this.captureConnectionPoolMetrics(this.httpClient.getConnectionManager(), awsRequestMetrics);
        BasicHttpContext httpContext = new BasicHttpContext();
        httpContext.setAttribute(AWSRequestMetrics.class.getSimpleName(), awsRequestMetrics);
        execParams.resetBeforeHttpRequest();
        SDKProgressPublisher.publishProgress(listener, ProgressEventType.HTTP_REQUEST_STARTED_EVENT);
        awsRequestMetrics.startEvent(Field.HttpRequestTime);

        boolean isHeaderReqIdAvail;
        try {
            execParams.apacheResponse = this.httpClient.execute(execParams.apacheRequest, httpContext);
            isHeaderReqIdAvail = this.logHeaderRequestId(execParams.apacheResponse);
        } finally {
            awsRequestMetrics.endEvent(Field.HttpRequestTime);
        }

        SDKProgressPublisher.publishProgress(listener, ProgressEventType.HTTP_REQUEST_COMPLETED_EVENT);
        StatusLine statusLine = execParams.apacheResponse.getStatusLine();
        int statusCode = statusLine == null?-1:statusLine.getStatusCode();
        if(this.isRequestSuccessful(execParams.apacheResponse)) {
            awsRequestMetrics.addProperty(Field.StatusCode, Integer.valueOf(statusCode));
            execParams.leaveHttpConnectionOpen = responseHandler.needsConnectionLeftOpen();
            HttpResponse ase2 = this.createResponse(execParams.apacheRequest, request, execParams.apacheResponse);
            Object authRetry2 = this.handleResponse(request, responseHandler, execParams.apacheRequest, ase2, execParams.apacheResponse, execContext, isHeaderReqIdAvail);
            return new Response(authRetry2, ase2);
        } else if(isTemporaryRedirect(execParams.apacheResponse)) {
            Header[] ase1 = execParams.apacheResponse.getHeaders("location");
            String authRetry1 = ase1[0].getValue();
            if(log.isDebugEnabled()) {
                log.debug("Redirecting to: " + authRetry1);
            }

            execParams.redirectedURI = URI.create(authRetry1);
            awsRequestMetrics.addPropertyWith(Field.StatusCode, Integer.valueOf(statusCode)).addPropertyWith(Field.RedirectLocation, authRetry1).addPropertyWith(Field.AWSRequestID, (Object)null);
            return null;
        } else {
            execParams.leaveHttpConnectionOpen = errorResponseHandler.needsConnectionLeftOpen();
            AmazonServiceException ase = this.handleErrorResponse(request, errorResponseHandler, execParams.apacheRequest, execParams.apacheResponse);
            awsRequestMetrics.addPropertyWith(Field.AWSRequestID, ase.getRequestId()).addPropertyWith(Field.AWSErrorCode, ase.getErrorCode()).addPropertyWith(Field.StatusCode, Integer.valueOf(ase.getStatusCode()));
            execParams.authRetryParam = null;
            AuthErrorRetryStrategy authRetry = execContext.getAuthErrorRetryStrategy();
            if(authRetry != null) {
                HttpResponse clockSkew = this.createResponse(execParams.apacheRequest, request, execParams.apacheResponse);
                execParams.authRetryParam = authRetry.shouldRetryWithAuthParam(request, clockSkew, ase);
            }

            if(execParams.authRetryParam == null && !this.shouldRetry(request.getOriginalRequest(), execParams.apacheRequest, ase, execParams.requestCount, this.config.getRetryPolicy())) {
                throw ase;
            } else {
                if(RetryUtils.isThrottlingException(ase)) {
                    awsRequestMetrics.incrementCounterWith(Field.ThrottleException).addProperty(Field.ThrottleException, ase);
                }

                execParams.retriedException = ase;
                if(RetryUtils.isClockSkewError(ase)) {
                    int clockSkew1 = this.parseClockSkewOffset(execParams.apacheResponse, ase);
                    SDKGlobalTime.setGlobalTimeOffset(this.timeOffset = clockSkew1);
                    request.setTimeOffset(this.timeOffset);
                }

                return null;
            }
        }
    }

    private boolean logHeaderRequestId(org.apache.http.HttpResponse res) {
        Header reqIdHeader = res.getFirstHeader("x-amzn-RequestId");
        boolean isHeaderReqIdAvail = reqIdHeader != null;
        if(requestIdLog.isDebugEnabled() || requestLog.isDebugEnabled()) {
            String msg = "x-amzn-RequestId: " + (isHeaderReqIdAvail?reqIdHeader.getValue():"not available");
            if(requestIdLog.isDebugEnabled()) {
                requestIdLog.debug(msg);
            } else {
                requestLog.debug(msg);
            }
        }

        return isHeaderReqIdAvail;
    }

    private void logResponseRequestId(String awsRequestId) {
        if(requestIdLog.isDebugEnabled() || requestLog.isDebugEnabled()) {
            String msg = "AWS Request ID: " + (awsRequestId == null?"not available":awsRequestId);
            if(requestIdLog.isDebugEnabled()) {
                requestIdLog.debug(msg);
            } else {
                requestLog.debug(msg);
            }
        }

    }

    private void captureConnectionPoolMetrics(ClientConnectionManager connectionManager, AWSRequestMetrics awsRequestMetrics) {
        if(awsRequestMetrics.isEnabled() && connectionManager instanceof ConnPoolControl) {
            ConnPoolControl control = (ConnPoolControl)connectionManager;
            PoolStats stats = control.getTotalStats();
            awsRequestMetrics.withCounter(Field.HttpClientPoolAvailableCount, (long)stats.getAvailable()).withCounter(Field.HttpClientPoolLeasedCount, (long)stats.getLeased()).withCounter(Field.HttpClientPoolPendingCount, (long)stats.getPending());
        }

    }

    private <T extends Throwable> T captureExceptionMetrics(T t, AWSRequestMetrics awsRequestMetrics) {
        awsRequestMetrics.incrementCounterWith(Field.Exception).addProperty(Field.Exception, t);
        if(t instanceof AmazonServiceException) {
            AmazonServiceException ase = (AmazonServiceException)t;
            if(RetryUtils.isThrottlingException(ase)) {
                awsRequestMetrics.incrementCounterWith(Field.ThrottleException).addProperty(Field.ThrottleException, ase);
            }
        }

        return t;
    }

    private void setUserAgent(Request<?> request) {
        String userAgent = this.config.getUserAgent();
        if(!userAgent.equals(ClientConfiguration.DEFAULT_USER_AGENT)) {
            userAgent = userAgent + ", " + ClientConfiguration.DEFAULT_USER_AGENT;
        }

        if(userAgent != null) {
            request.addHeader("User-Agent", userAgent);
        }

        AmazonWebServiceRequest awsreq = request.getOriginalRequest();
        RequestClientOptions opts = awsreq.getRequestClientOptions();
        if(opts != null) {
            String userAgentMarker = opts.getClientMarker(Marker.USER_AGENT);
            if(userAgentMarker != null) {
                request.addHeader("User-Agent", createUserAgentString(userAgent, userAgentMarker));
            }
        }

    }

    private static String createUserAgentString(String existingUserAgentString, String userAgent) {
        return existingUserAgentString.contains(userAgent)?existingUserAgentString:existingUserAgentString.trim() + " " + userAgent.trim();
    }

    public void shutdown() {
        IdleConnectionReaper.removeConnectionManager(this.httpClient.getConnectionManager());
        this.httpClient.getConnectionManager().shutdown();
    }

    private boolean shouldRetry(AmazonWebServiceRequest originalRequest, HttpRequestBase method, AmazonClientException exception, int requestCount, RetryPolicy retryPolicy) {
        int retries = requestCount - 1;
        int maxErrorRetry = this.config.getMaxErrorRetry();
        if(maxErrorRetry < 0 || !retryPolicy.isMaxErrorRetryInClientConfigHonored()) {
            maxErrorRetry = retryPolicy.getMaxErrorRetry();
        }

        if(retries >= maxErrorRetry) {
            return false;
        } else {
            if(method instanceof HttpEntityEnclosingRequest) {
                HttpEntity entity = ((HttpEntityEnclosingRequest)method).getEntity();
                if(entity != null && !entity.isRepeatable()) {
                    if(log.isDebugEnabled()) {
                        log.debug("Entity not repeatable");
                    }

                    return false;
                }
            }

            return retryPolicy.getRetryCondition().shouldRetry(originalRequest, exception, retries);
        }
    }

    private static boolean isTemporaryRedirect(org.apache.http.HttpResponse response) {
        int status = response.getStatusLine().getStatusCode();
        return status == 307 && response.getHeaders("Location") != null && response.getHeaders("Location").length > 0;
    }

    private boolean isRequestSuccessful(org.apache.http.HttpResponse response) {
        int status = response.getStatusLine().getStatusCode();
        return status / 100 == 2;
    }

    private <T> T handleResponse(Request<?> request, HttpResponseHandler<AmazonWebServiceResponse<T>> responseHandler, HttpRequestBase method, HttpResponse httpResponse, org.apache.http.HttpResponse apacheHttpResponse, ExecutionContext executionContext, boolean isHeaderReqIdAvail) throws IOException {
        AmazonWebServiceRequest awsreq = request.getOriginalRequest();
        ProgressListener listener = awsreq.getGeneralProgressListener();

        try {
            CountingInputStream e = null;
            Object errorMessage1 = httpResponse.getContent();
            if(errorMessage1 != null) {
                if(System.getProperty("com.amazonaws.sdk.enableRuntimeProfiling") != null) {
                    errorMessage1 = e = new CountingInputStream((InputStream)errorMessage1);
                    httpResponse.setContent((InputStream)errorMessage1);
                }

                httpResponse.setContent(ProgressInputStream.inputStreamForResponse((InputStream)errorMessage1, awsreq));
            }

            Map headers = httpResponse.getHeaders();
            String s = (String)headers.get("Content-Length");
            if(s != null) {
                try {
                    long awsRequestMetrics = Long.parseLong(s);
                    SDKProgressPublisher.publishResponseContentLength(listener, awsRequestMetrics);
                } catch (NumberFormatException var25) {
                    log.warn("Cannot parse the Content-Length header of the response.");
                }
            }

            AWSRequestMetrics awsRequestMetrics1 = executionContext.getAwsRequestMetrics();
            awsRequestMetrics1.startEvent(Field.ResponseProcessingTime);
            SDKProgressPublisher.publishProgress(listener, ProgressEventType.HTTP_RESPONSE_STARTED_EVENT);

            AmazonWebServiceResponse awsResponse;
            try {
                awsResponse = (AmazonWebServiceResponse)responseHandler.handle(httpResponse);
            } finally {
                awsRequestMetrics1.endEvent(Field.ResponseProcessingTime);
            }

            SDKProgressPublisher.publishProgress(listener, ProgressEventType.HTTP_RESPONSE_COMPLETED_EVENT);
            if(e != null) {
                awsRequestMetrics1.setCounter(Field.BytesProcessed, e.getByteCount());
            }

            if(awsResponse == null) {
                throw new RuntimeException("Unable to unmarshall response metadata. Response Code: " + httpResponse.getStatusCode() + ", Response Text: " + httpResponse.getStatusText());
            } else {
                this.responseMetadataCache.add(request.getOriginalRequest(), awsResponse.getResponseMetadata());
                String awsRequestId = awsResponse.getRequestId();
                if(requestLog.isDebugEnabled()) {
                    StatusLine statusLine = apacheHttpResponse.getStatusLine();
                    requestLog.debug("Received successful response: " + (statusLine == null?null:Integer.valueOf(statusLine.getStatusCode())) + ", AWS Request ID: " + awsRequestId);
                }

                if(!isHeaderReqIdAvail) {
                    this.logResponseRequestId(awsRequestId);
                }

                awsRequestMetrics1.addProperty(Field.AWSRequestID, awsRequestId);
                return awsResponse.getResult();
            }
        } catch (CRC32MismatchException var26) {
            throw var26;
        } catch (IOException var27) {
            throw var27;
        } catch (AmazonClientException var28) {
            throw var28;
        } catch (Exception var29) {
            String errorMessage = "Unable to unmarshall response (" + var29.getMessage() + "). Response Code: " + httpResponse.getStatusCode() + ", Response Text: " + httpResponse.getStatusText();
            throw new AmazonClientException(errorMessage, var29);
        }
    }

    private AmazonServiceException handleErrorResponse(Request<?> request, HttpResponseHandler<AmazonServiceException> errorResponseHandler, HttpRequestBase method, org.apache.http.HttpResponse apacheHttpResponse) throws IOException {
        StatusLine statusLine = apacheHttpResponse.getStatusLine();
        int statusCode;
        String reasonPhrase;
        if(statusLine == null) {
            statusCode = -1;
            reasonPhrase = null;
        } else {
            statusCode = statusLine.getStatusCode();
            reasonPhrase = statusLine.getReasonPhrase();
        }

        HttpResponse response = this.createResponse(method, request, apacheHttpResponse);
        AmazonServiceException exception = null;

        try {
            exception = (AmazonServiceException)errorResponseHandler.handle(response);
            if(requestLog.isDebugEnabled()) {
                requestLog.debug("Received error response: " + exception);
            }
        } catch (Exception var12) {
            if(statusCode == 413) {
                exception = new AmazonServiceException("Request entity too large");
                exception.setServiceName(request.getServiceName());
                exception.setStatusCode(statusCode);
                exception.setErrorType(ErrorType.Client);
                exception.setErrorCode("Request entity too large");
            } else {
                if(statusCode != 503 || !"Service Unavailable".equalsIgnoreCase(reasonPhrase)) {
                    if(var12 instanceof IOException) {
                        throw (IOException)var12;
                    }

                    String errorMessage = "Unable to unmarshall error response (" + var12.getMessage() + "). Response Code: " + (statusLine == null?"None":Integer.valueOf(statusCode)) + ", Response Text: " + reasonPhrase;
                    throw new AmazonClientException(errorMessage, var12);
                }

                exception = new AmazonServiceException("Service unavailable");
                exception.setServiceName(request.getServiceName());
                exception.setStatusCode(statusCode);
                exception.setErrorType(ErrorType.Service);
                exception.setErrorCode("Service unavailable");
            }
        }

        exception.setStatusCode(statusCode);
        exception.setServiceName(request.getServiceName());
        exception.fillInStackTrace();
        return exception;
    }

    private HttpResponse createResponse(HttpRequestBase method, Request<?> request, org.apache.http.HttpResponse apacheHttpResponse) throws IOException {
        HttpResponse httpResponse = new HttpResponse(request, method);
        if(apacheHttpResponse.getEntity() != null) {
            httpResponse.setContent(apacheHttpResponse.getEntity().getContent());
        }

        httpResponse.setStatusCode(apacheHttpResponse.getStatusLine().getStatusCode());
        httpResponse.setStatusText(apacheHttpResponse.getStatusLine().getReasonPhrase());
        Header[] arr$ = apacheHttpResponse.getAllHeaders();
        int len$ = arr$.length;

        for(int i$ = 0; i$ < len$; ++i$) {
            Header header = arr$[i$];
            httpResponse.addHeader(header.getName(), header.getValue());
        }

        return httpResponse;
    }

    private void pauseBeforeNextRetry(AmazonWebServiceRequest originalRequest, AmazonClientException previousException, int requestCount, RetryPolicy retryPolicy) {
        int retries = requestCount - 1 - 1;
        long delay = retryPolicy.getBackoffStrategy().delayBeforeNextRetry(originalRequest, previousException, retries);
        if(log.isDebugEnabled()) {
            log.debug("Retriable error detected, will retry in " + delay + "ms, attempt number: " + retries);
        }

        try {
            Thread.sleep(delay);
        } catch (InterruptedException var9) {
            Thread.currentThread().interrupt();
            throw new AmazonClientException(var9.getMessage(), var9);
        }
    }

    private String getServerDateFromException(String body) {
        int startPos = body.indexOf("(");
        int endPos = body.indexOf(" + ");
        if(endPos == -1) {
            endPos = body.indexOf(" - ");
        }

        return endPos == -1?null:body.substring(startPos + 1, endPos);
    }

    private int parseClockSkewOffset(org.apache.http.HttpResponse response, AmazonServiceException exception) {
        long currentTimeMilli = System.currentTimeMillis();
        Date serverDate = null;
        String serverDateStr = null;
        Header[] responseDateHeader = response.getHeaders("Date");

        try {
            if(responseDateHeader.length == 0) {
                String diff = exception.getMessage();
                serverDateStr = this.getServerDateFromException(diff);
                if(serverDateStr == null) {
                    log.warn("Unable to parse clock skew offset from errmsg: " + diff);
                    return 0;
                }

                serverDate = DateUtils.parseCompressedISO8601Date(serverDateStr);
            } else {
                serverDateStr = responseDateHeader[0].getValue();
                serverDate = DateUtils.parseRFC822Date(serverDateStr);
            }
        } catch (RuntimeException var10) {
            log.warn("Unable to parse clock skew offset from response: " + serverDateStr, var10);
            return 0;
        }

        long diff1 = currentTimeMilli - serverDate.getTime();
        return (int)(diff1 / 1000L);
    }

    protected void finalize() throws Throwable {
        this.shutdown();
        super.finalize();
    }

    public RequestMetricCollector getRequestMetricCollector() {
        return this.requestMetricCollector;
    }

    public int getTimeOffset() {
        return this.timeOffset;
    }

    static void configUnreliableTestConditions(UnreliableTestConfig config) {
        unreliableTestConfig = config;
    }

    static {
        List problematicJvmVersions = Arrays.asList(new String[]{"1.6.0_06", "1.6.0_13", "1.6.0_17", "1.6.0_65", "1.7.0_45"});
        String jvmVersion = System.getProperty("java.version");
        if(problematicJvmVersions.contains(jvmVersion)) {
            log.warn("Detected a possible problem with the current JVM version (" + jvmVersion + ").  " + "If you experience XML parsing problems using the SDK, try upgrading to a more recent JVM update.");
        }

    }

    private static class ExecOneRequestParams {
        private Signer signer;
        private URI signerURI;
        int requestCount;
        AmazonClientException retriedException;
        HttpRequestBase apacheRequest;
        org.apache.http.HttpResponse apacheResponse;
        URI redirectedURI;
        AuthRetryParameters authRetryParam;
        boolean leaveHttpConnectionOpen;

        private ExecOneRequestParams() {
        }

        boolean isRetry() {
            return this.requestCount > 1 || this.redirectedURI != null || this.authRetryParam != null;
        }

        void initPerRetry() {
            ++this.requestCount;
            this.apacheRequest = null;
            this.apacheResponse = null;
            this.leaveHttpConnectionOpen = false;
        }

        Signer newSigner(Request<?> request, ExecutionContext execContext) {
            if(this.authRetryParam != null) {
                this.signerURI = this.authRetryParam.getEndpointForRetry();
                this.signer = this.authRetryParam.getSignerForRetry();
                execContext.setSigner(this.signer);
            } else if(this.redirectedURI != null && !this.redirectedURI.equals(this.signerURI)) {
                this.signerURI = this.redirectedURI;
                this.signer = execContext.getSignerByURI(this.signerURI);
            } else if(this.signer == null) {
                this.signerURI = request.getEndpoint();
                this.signer = execContext.getSignerByURI(this.signerURI);
            }

            return this.signer;
        }

        HttpRequestBase newApacheRequest(HttpRequestFactory httpRequestFactory, Request<?> request, ClientConfiguration config, ExecutionContext execContext) throws FakeIOException {
            this.apacheRequest = httpRequestFactory.createHttpRequest(request, config, execContext);
            if(this.redirectedURI != null) {
                this.apacheRequest.setURI(this.redirectedURI);
            }

            return this.apacheRequest;
        }

        void resetBeforeHttpRequest() {
            this.retriedException = null;
            this.authRetryParam = null;
            this.redirectedURI = null;
        }
    }*/
}
