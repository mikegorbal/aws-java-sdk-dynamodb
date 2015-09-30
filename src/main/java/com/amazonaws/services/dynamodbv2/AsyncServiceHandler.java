package com.amazonaws.services.dynamodbv2;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;

public interface AsyncServiceHandler<RESULT, REQUEST extends AmazonWebServiceRequest> {

    /**
     * <p>
     * This method will be called if there is an AmazonServiceException, this is
     * the more specific case of the overloaded handleException method because
     * the AmazonServiceException has easier access to cause of exceptions.
     * </p>
     *
     * @param exception
     */
    public void handleException(AmazonServiceException exception);

    /**
     * <p>
     * This method will be called if there is an AmazonServiceException, this is
     * the less specific case of the overloaded handleException method because
     * the AmazonServiceException has easier access to cause of exceptions.
     * </p>
     *
     * @param exception
     */
    public void handleException(AmazonClientException exception);

    /**
     * <p>
     * This method will be called if there is an AmazonServiceException, this is
     * the least specific case of the overloaded handleException method used to
     * catch all misc exceptions.
     * </p>
     *
     * @param exception
     */
    public void handleException(Exception exception);

    /**
     *
     * @param result
     * The result of the operation e.g. UpdateItemResult
     * @param request
     * The initial request send to aws client e.g. UpdateItemRequest
     */
    public void handleResult(RESULT result, REQUEST request);

}