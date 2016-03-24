package com.soffid.iam.addons.selfcertificate.ss;

import org.zkoss.zk.au.AuRequest;
import org.zkoss.zk.au.Command;
import org.zkoss.zk.au.ComponentCommand;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.Events;
import org.zkoss.zul.Div;

import es.caib.zkib.zkiblaf.SignApplet;

public class CustomDiv extends Div {

	private static final String GENERATED_EVENT = "onGenerated";

	public CustomDiv() {
		super ();
	}

	private static Command _onGenerated  = new ComponentCommand (GENERATED_EVENT, 0) {
		protected void process(AuRequest request) {
			final CustomDiv div = (CustomDiv) request.getComponent();
			Events.postEvent(new Event (GENERATED_EVENT, div, new String[0]));
		}
		
	};

	public Command getCommand(String cmdId) {
		if (GENERATED_EVENT.equals(cmdId))
			return _onGenerated;
		return super.getCommand(cmdId);
	}


}
