/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.plugtests.tests;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_LINK_07: Filter discovery results using href attribute and
 * complete value strings
 */
public class CL07 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/.well-known/core";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;
	public static final String EXPECTED_HREF = "href=/link1";

	public CL07(String serverURI) {
		super(CL07.class.getSimpleName());

		// create the request
		Request request = new Request(Code.GET, Type.CON);
		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI + "?" + EXPECTED_HREF);
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.ACK, response.getType());
		success &= checkCode(EXPECTED_RESPONSE_CODE, response.getCode());
		success &= checkOption(MediaTypeRegistry.APPLICATION_LINK_FORMAT, response.getOptions().getContentFormat(), "Content-Format");
		success &= checkDiscoveryAttributes(EXPECTED_HREF, response.getPayloadString());
		
		return success;
	}
}
