package com.soffid.iam.addons.otp.sync;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.User;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class EssoOtpServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("EssoOtpServlet");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
    IOException {
    	String action = req.getParameter("action");
    	String user = req.getParameter("user");
    	String challenge = req.getParameter("challenge");
    	String pin = req.getParameter("pin");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        try {
	    	if ("request".equals(action)) {
	    		writer.write(doRequest(user));
	    	}
	    	else if ("response".equals(action)) {
	    		writer.write(doResponse(challenge, pin));
	    	}
	    	else
	    		writer.write("ERROR|Bad action");
        } catch (Exception e) {
            log.warn("Error performing otp service", e);
            StringBuffer b = new StringBuffer().append (e.getClass().getName()).
            				append ("|").
            				append (e.getMessage()).
            				append ("\n");
            writer.write(b.toString());
        }
        writer.close();
    }

	private String doRequest(String user) throws InternalErrorException {
		User u = ServiceLocator.instance().getUserService().findUserByUserName(user);
		if (u == null) {
			return "ERROR|Wrong user";
		}
		Challenge ch = new Challenge();
		ch.setUser(u);
		Challenge r = ServiceLocator.instance().getOTPValidationService().selectToken(ch);
		if (r.getCardNumber() == null) {
			return "ERROR|No OTP available";
		}
		JSONObject o = new JSONObject();
		o.put("h", r.getOtpHandler());
		o.put("c", r.getCardNumber());
		o.put("l", r.getCell());
		o.put("u", user);
		o.put("i", r.getChallengeId());
		return "OK|"+Base64.encodeBytes(o.toString().getBytes(StandardCharsets.UTF_8), Base64.DONT_BREAK_LINES)+
				"|"+r.getCardNumber()+"|"+r.getCell();
	}

	private String doResponse(String chid, String pin) throws InternalErrorException {
		JSONObject o = new JSONObject(new String(Base64.decode(chid), StandardCharsets.UTF_8));
		String user = o.getString("u");
		
		User u = ServiceLocator.instance().getUserService().findUserByUserName(user);
		if (u == null) {
			return "ERROR|Wrong user";
		}
		Challenge ch = new Challenge();
		ch.setUser(u);
		ch.setCardNumber(o.getString("c"));
		ch.setOtpHandler(o.getString("h"));
		ch.setCell(o.optString("l", null));
		ch.setChallengeId(o.optString("i", null));
		boolean b = ServiceLocator.instance().getOTPValidationService().validatePin(ch, pin);
		if (b) {
			return "OK";
		} else {
			return "ERROR|Wrong PIN";
		}
	}
}
