package com.soffid.iam.addon.otp.rest;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.net.URISyntaxException;

import javax.imageio.ImageIO;
import javax.naming.InitialContext;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.soffid.iam.addon.otp.json.ResponseChallengeRequest;
import com.soffid.iam.addon.scim.response.SCIMResponseBuilder;
import com.soffid.iam.addon.scim2.json.JSONBuilder;
import com.soffid.iam.addon.scim2.rest.BaseRest;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.service.ejb.OtpService;
import com.soffid.iam.addons.otp.service.ejb.OtpServiceHome;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.api.User;
import com.soffid.iam.common.security.SoffidPrincipal;
import com.soffid.iam.utils.Security;

import es.caib.seycon.util.Base64;

@Path("/scim2/v1/OtpDevice")
@Produces({"application/scim+json", "application/json"})
@Consumes({"application/scim+json", "application/json"})
@ServletSecurity(@HttpConstraint(rolesAllowed = {"scim:invoke"}))
public class OtpDeviceRest extends BaseRest<OtpDevice> {
	Log log = LogFactory.getLog(getClass());
	
	public OtpDeviceRest() {
		super(OtpDevice.class);
	}
	
	
	@Path("")
	@POST
	@Override
	public Response create(String data, @Context HttpServletRequest request) throws URISyntaxException {
		JSONBuilder b = new JSONBuilder(request);
		Security.nestedLogin( (SoffidPrincipal) ((HttpServletRequest) request).getUserPrincipal());
		try {
			JSONObject o = new JSONObject(data);
			OtpDevice obj = loadObject(o);
			OtpDevice newObj = create(o, obj);
			if (newObj != null) {
				BufferedImage bi = newObj.getImage();
				newObj.setImage(null);;
				JSONObject jsonObject = b.build(newObj);
				if (bi != null)
				{
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					ImageIO.write(bi, "PNG", out);
					jsonObject.put("image", Base64.encodeBytes(out.toByteArray(), Base64.DONT_BREAK_LINES));
				}
				String uri = jsonObject.getJSONObject("meta").getString("location");
				return Response
						.status(201)
						.header("Location", uri)
						.entity(jsonObject.toString())
						.build();
			} else
				return SCIMResponseBuilder.responseOnlyHTTP(Status.NOT_FOUND);
		} catch (Exception e) {
			log.warn("Error processing SCIM Request "+request.getRequestURL(), e);
			return SCIMResponseBuilder.errorGeneric(e);
		} finally {
			Security.nestedLogoff();
		}
	}

	@GET
	@Path("/{id}/requestChallenge")
	public Response generateChallenge(@PathParam("id") long id, @Context HttpServletRequest request) throws URISyntaxException {
		Security.nestedLogin( (SoffidPrincipal) ((HttpServletRequest) request).getUserPrincipal());
		try {
			OtpService ejb = (OtpService) new InitialContext().lookup(OtpServiceHome.JNDI_NAME);
			PagedResult<OtpDevice> list = ejb.findOtpDevicesByJsonQuery(null, "id eq "+id, null, null);
			if (list.getTotalResults() != 1) {
				return Response.status(Status.NOT_FOUND).build();
			} else {
				OtpDevice device = list.getResources().iterator().next();
				Challenge ch = ejb.generateChallenge(device);
				JSONObject o = new JSONObject();
				o.put("cell", ch.getCell());
				o.put("cardNumber", ch.getCardNumber());
				return Response
						.status(Status.OK)
						.entity(o.toString())
						.build();
			}
		} catch (Exception e) {
			log.warn("Error processing SCIM Request "+request.getRequestURL(), e);
			return SCIMResponseBuilder.errorGeneric(e);
		} finally {
			Security.nestedLogoff();
		}
	}
	
	@POST
	@Path("/{id}/responseChallenge")
	public Response responseChallenge(@PathParam("id") long id,
			ResponseChallengeRequest data,
			@Context HttpServletRequest request) throws URISyntaxException {
		Security.nestedLogin( (SoffidPrincipal) ((HttpServletRequest) request).getUserPrincipal());
		try {
			OtpService ejb = (OtpService) new InitialContext().lookup(OtpServiceHome.JNDI_NAME);
			PagedResult<OtpDevice> list = ejb.findOtpDevicesByJsonQuery(null, "id eq "+id, null, null);
			if (list.getTotalResults() != 1) {
				return Response.status(Status.NOT_FOUND).build();
			} else {
				OtpDevice device = list.getResources().iterator().next();
				boolean ok = ejb.validateChalleng(device, data.pin);
				JSONObject o = new JSONObject();
				o.put("success", ok);
				o.put("locked", device.getStatus() == OtpStatus.LOCKED);
				return Response
						.status(Status.OK)
						.entity(o.toString())
						.build();
			}
		} catch (Exception e) {
			log.warn("Error processing SCIM Request "+request.getRequestURL(), e);
			return SCIMResponseBuilder.errorGeneric(e);
		} finally {
			Security.nestedLogoff();
		}
	}
	
	@Override
	public void writeObject(OutputStreamWriter w, JSONBuilder builder, OtpDevice obj) {
		JSONObject jsonObject = builder.build(obj);

		addReference (builder, jsonObject, "requestChallenge", "OtpDevice/"+obj.getId()+"/requestChallenge");
		
		addReference (builder, jsonObject, "responseChallenge", "OtpDevice/"+obj.getId()+"/responseChallenge");

		jsonObject.write(w);
	}

}

