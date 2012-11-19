package it.treviso.provincia.freesigner.applet;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import netscape.javascript.JSObject;

/* 
 * TODO: implementare rilevamento anticipato della libreria pkcs11wrapper.dll
 * in modo da evitare che l'utente prosegua senza la libreria. Implementare la possibilità
 * di lanciare un tool di installazione della libreria.
 */


/**
 * FreeSignerSignApplet
 * 
 * @author lorenzettoluca
 */
@SuppressWarnings("serial")
public class FreeSignerSignApplet extends javax.swing.JApplet {

    /** Initializes the applet FreeSignerApplet */
    public void init() {
    	try {
    		System.loadLibrary("pkcs11wrapper");
    	} catch (UnsatisfiedLinkError ue) {
    		JOptionPane.showMessageDialog(null, "Libreria pkcs11wrapper mancante\n" +
    				"Procedere con l\'installazione della libreria ed " +
    				"eseguire nuovamente l\'applicazione", "Errore", JOptionPane.ERROR_MESSAGE);
    		//System.out.println(System.getProperty("java.library.path"));
    		ue.printStackTrace();
    		System.exit(ERROR);
    	} catch (SecurityException se){
    		JOptionPane.showMessageDialog(null, "Impossibile caricare la libreria per problemi di sicurezza. " +
    				"Contattare l'amministratore.","Eccezione di sicurezza", JOptionPane.ERROR_MESSAGE);
    		System.exit(ERROR);
    	}
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable() {
                public void run() {
                    initComponents();
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void initComponents() {
    	jButton2 = new JButton();
    	//System.out.println(getClass().getResource("/it/treviso/provincia/freesigner/applet/firma_petizione.png").toString());
    	Icon imgicon = new ImageIcon(getClass().getResource("/it/treviso/provincia/freesigner/applet/firma_petizione.png"));
    	

        jButton2.setText("Firma");
        jButton2.setIcon(imgicon);
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });
        if ((this.getParameter("filename")!=null) && ((new File(this.getParameter("filename"))).exists())) {
        	this.FILE_NAME = this.getParameter("filename");
        } else {
        	FILE_NAME = "File non specificato o non esistente!";
            jButton2.setEnabled(false);
        }
        
        if (this.getParameter("devlib")!=null) {
        	this.LIB=this.getParameter("devlib");
        }
        if (this.getParameter("callback")!=null) this.CALLBACKURL = this.getParameter("callback");
		JSO = JSObject.getWindow(this);
        this.add(jButton2);
    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {
        FreeSignerSignApplet1 frame = new FreeSignerSignApplet1();
        frame.sign(FILE_NAME,LIB,CALLBACKURL,JSO);
    }


    public void jButton2SetClickable() {
    	jButton2.setEnabled(true);
    }

    private String FILE_NAME = "/home/PROV2003/lorenzettoluca/richiesta_fw_20110920.pdf";
	private String LIB = "/usr/lib/libbit4ipki.so";
	private String CALLBACKURL = "";
	private JSObject JSO;
    private JButton jButton2;

}