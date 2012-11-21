/**
 * 
 */

package it.treviso.provincia.freesigner.applet;

import it.treviso.provincia.freesigner.*;
import it.treviso.provincia.freesigner.applet.*;

import it.trento.comune.j4sign.pcsc.*;
import it.trento.comune.j4sign.pkcs11.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Timer;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import netscape.javascript.JSObject;

import org.bouncycastle.cms.CMSException;

/**
 * @author lorenzettoluca
 *
 */




public class FreeSignerSignApplet1 {

	private ReadCertsTask task;
	private Timer timer;
	private String LIB = "/usr/lib/libbit4ipki.so";
	
	/**
	 * @param callBackUrl 
	 * @param filename
	 * @param jso 
	 * @param library
	 * @throws CMSException 
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws FileNotFoundException 
	 */

	public void sign(String filename, String lib, String callBackUrl, JSObject jso) {
		URLClassLoader cl = (URLClassLoader) getClass().getClassLoader();
		try {
		  URL url = cl.findResource("META-INF/MANIFEST.MF");
		  Manifest manifest = new Manifest(url.openStream());
		  Attributes attr = manifest.getMainAttributes();
		  String value = attr.getValue("Versione");
		  System.out.println("FreeSignerApplet version "+value);
		} catch (IOException E) {
		  E.printStackTrace();
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		task = new ReadCertsTask(null, lib, false);
		task.go();
		while (!task.isDone()) {
				System.out.print("");
		}
		ArrayList slots = task.getSlotInfos();
		if (slots.size()<1) {
			JOptionPane.showMessageDialog(null, "Nessun Lettore Rilevato", "Error", JOptionPane.ERROR_MESSAGE);
			task = null;
			return;
		}
		if (slots.size()==1) {
			JOptionPane.showMessageDialog(null, "Rilevato "+slots.size()+" lettore", "alert", JOptionPane.PLAIN_MESSAGE);
		} else {
			JOptionPane.showMessageDialog(null, "Rilevati "+slots.size()+" lettori, viene selezionato il primo elemento: "+slots.get(0).toString(), "alert", JOptionPane.PLAIN_MESSAGE);
		}
		for(Object slot: slots) {
			System.out.println("Elemento: "+slot.toString());
		}
		task = new ReadCertsTask(slots.get(0).toString(), lib, false);
		task.go();
		while (!task.isDone()) {
			System.out.print("");
		}
		FreeSignerSignApplet2 frame = new FreeSignerSignApplet2(task,filename,callBackUrl,jso);
	}

}

