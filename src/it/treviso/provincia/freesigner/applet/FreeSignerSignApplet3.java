/**
 *	Freesigner - a j4sign-based open, multi-platform digital signature client
 *	Copyright (c) 2005 Francesco Cendron - Infocamere
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

package it.treviso.provincia.freesigner.applet;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.swing.*;
import javax.swing.Timer;

import it.trento.comune.j4sign.cms.*;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;

import netscape.javascript.JSObject;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.*;

/**
 * GUI of signing operation. During this frame, signing operations are
 * performed.<br>
 * <br>
 * GUI interfaccia di firma. Durante questo frame vengono realizzate le
 * operazioni di firma
 * 
 * @author Luca Lorenzetto (original version from Francesco Cendron)
 */
public class FreeSignerSignApplet3 extends JFrame {

	private String callBackUrl;
	private JSObject jso;
	/**
	 * 
	 */
	/**
	 * Constructor
	 * 
	 * @param filepath
	 *            nome of the file to sign
	 * @param t
	 *            task ReadCertsTask
	 * @param selected
	 *            index of certificate chosen in the table of previous frame
	 * @param jso 
	 * @throws GeneralSecurityException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws CMSException
	 */
	public FreeSignerSignApplet3(String filepath, ReadCertsTask t, String callBackUrl, int selected, JSObject jso)
			throws GeneralSecurityException, FileNotFoundException,
			IOException, CMSException {
		fileDaAprire = new String(filepath);
		taskBack = t;
		selectedBack = selected;
		frame = new JFrame();
		log = System.out;
		this.callBackUrl = callBackUrl;
		this.jso = jso;

		//NOTA ROB: selectTokenFromCertIndex dovrebbe inizializzare correttamente il PKCS11Signer
		//		inizializzando la cryptoki (se serve) e il tokenHandle relativo al certificato scelto
		//		Per irrobustire il comportamento occorrerà testare la finalizzazione della lib in selectTokenFromCertIndex
		//		( helper.isLibFinalized() ); per ora si lascia non finalizzata la lib in ReadCrtTask.CertFinder()
		
		t.selectTokenFromCertIndex(selected);
                /* Cades Impl. */
                certforcades = t.getCert(selected);
                /* End Cades Impl. */
		task = new DigestSignTask(t.getPKCS11Signer(),t.getCertID(selected), log);
		
		initComponents();
		char[] p = popUpLogin();
		if (p != null) {
			task.setPassword(p);
			openSignature(CMSSignedDataGenerator.DIGEST_SHA256,
					CMSSignedDataGenerator.ENCRYPTION_RSA, false);
			// this launches the signing thread
			sign(false);

		} else {
			frame.hide();
			JOptionPane.showMessageDialog(null, "Operazione Annullata", "Annullata", JOptionPane.ERROR_MESSAGE);
		}

	}

	/**
	 * PIN login. It opens frame PINDialog
	 * 
	 * @return char[]: password chars
	 * @throws IOException
	 */
	private char[] popUpLogin() throws IOException {
		UserInfo transfer = new UserInfo("");
		dialog = new PINDialog(frame);
		String pwd = new String();
		char[] p = null;
		if (dialog.showDialog(transfer)) {
			pwd = transfer.password;

			p = new char[pwd.length()];
			for (int i = 0; i < pwd.length(); i++) {
				p[i] = pwd.charAt(i);
			}
		}
		return p;
	}

	/**
	 * Starts signing task<br>
	 * <br>
	 * Starta il task di firma
	 * 
	 * @param digestOnToken
	 *            : is digestOnToken?
	 * 
	 */

	public void sign(boolean digestOnToken) {

		if (!digestOnToken && getEncodedDigest() == null) {
			// setStatus(ERROR, "Digest non impostato");
		} else {
			// enableControls(false);
			if (!digestOnToken) {
				task.setDigest(decodeToBytes(getEncodedDigest()));
			} else {
				task.setDataStream(new ByteArrayInputStream(this.bytesToSign));
			}

			task.go();
			timer.start();
		}
	}

	/**
	 * Prepares a signing procedure.
	 * 
	 * @param digestAlg
	 *            String
	 * @param encryptionAlg
	 *            String
	 * @param digestOnToken
	 *            boolean
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CMSException
	 */
	private void openSignature(String digestAlg, String encryptionAlg,
			boolean digestOnToken) throws InvalidKeyException,
			CertificateEncodingException, SignatureException,
			NoSuchProviderException, NoSuchAlgorithmException, IOException,
			CMSException {
		
		File inputFile = new File(fileDaAprire);

		this.msg = new CMSProcessableByteArray(getBytesFromFile(inputFile));
		this.cmsGenerator = new ExternalSignatureCMSSignedDataGenerator();

		this.signersCertList = new ArrayList();

		log.println("\nCalculating digest ...\n");
                
		this.signerInfoGenerator = new ExternalSignatureSignerInfoGenerator(
				digestAlg, encryptionAlg);
                /* Cades Impl. */
                this.signerInfoGenerator.setCertificate(certforcades);
                /* End Cades Impl. */
		byte[] rawDigest = null;
		byte[] dInfoBytes = null;
		byte[] paddedBytes = null;
		
		/**
		 * notes for multiple signing:
		 * 
		 * bytesToSign should be extracted with (byte[]) cmssigneddata.getSignedContent().getContent()
		 */
		
		byte[] bytesToSign = this.signerInfoGenerator.getBytesToSign(
				PKCSObjectIdentifiers.data, msg, "BC");

		/*
		 * Let's calculate DigestInfo in any case (even if digestOnToken is
		 * TRUE) , in order to compare with decryption result
		 */
		rawDigest = applyDigest(digestAlg, bytesToSign);

		log.println("Raw digest bytes:\n" + formatAsHexString(rawDigest));

		log.println("Encapsulating in a DigestInfo...");

		dInfoBytes = encapsulateInDigestInfo(digestAlg, rawDigest);

		log.println("DigestInfo bytes:\n" + formatAsHexString(dInfoBytes));

		if (!digestOnToken) {
			// MessageDigest md = MessageDigest.getInstance(digestAlg);
			// md.update(bytesToSign);
			// byte[] digest = md.digest();
			//
			// log.println("digestAlg digest:\n" + formatAsHexString(digest));
			// log.println("Done.");
			setEncodedDigest(encodeFromBytes(dInfoBytes));
		}

	}

	private byte[] encapsulateInDigestInfo(String digestAlg, byte[] digestBytes)
			throws IOException {

		byte[] bcDigestInfoBytes = null;
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		DEROutputStream dOut = new DEROutputStream(bOut);

		DERObjectIdentifier digestObjId = new DERObjectIdentifier(digestAlg);
		AlgorithmIdentifier algId = new AlgorithmIdentifier(digestObjId, null);
		DigestInfo dInfo = new DigestInfo(algId, digestBytes);

		dOut.writeObject(dInfo);
		return bOut.toByteArray();

	}

	private byte[] applyDigest(String digestAlg, byte[] bytes)
			throws NoSuchAlgorithmException {

		System.out.println("Applying digest algorithm...");
		MessageDigest md = MessageDigest.getInstance(digestAlg);
		md.update(bytes);

		return md.digest();
	}

	/**
	 * Terminates the signing procedure creating the signer information data
	 * structure.
	 * 
	 * @throws CertificateException
	 */
	private void closeSignature() throws CertificateException {
		if ((getCertificate() != null) && (getEncryptedDigest() != null)) {

			log.println("======== Encryption completed =========");
			log.println("Encrypted Digest bytes:\n"
					+ formatAsHexString(getEncryptedDigest()));

			log.println("Certificate bytes:\n"
					+ formatAsHexString(getCertificate()));

			// get Certificate
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
					.getInstance("X.509");
			java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(
					getCertificate());
			java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
					.generateCertificate(bais);

			this.signerInfoGenerator.setCertificate(javaCert);
			this.signerInfoGenerator.setSignedBytes(getEncryptedDigest());

			this.cmsGenerator.addSignerInf(this.signerInfoGenerator);

			this.signersCertList.add(javaCert);

		}
	}

	/**
	 * Creates the signed data structure, using signer infos precedently
	 * accumulated.
	 * 
	 * @return @throws CertStoreException
	 * @throws CertStoreException
	 * @throws InvalidAlgorithmParameterException
	 * @throws CertificateExpiredException
	 * @throws CertificateNotYetValidException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CMSException
	 */
	private CMSSignedData buildCMSSignedData() throws CertStoreException,
			InvalidAlgorithmParameterException, CertificateExpiredException,
			CertificateNotYetValidException, NoSuchAlgorithmException,
			NoSuchProviderException, CMSException {

		CMSSignedData s = null;

		if (this.signersCertList.size() != 0) {

			// Per passare i certificati al generatore li si incapsula
			// in un
			// CertStore.
			CertStore store = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(this.signersCertList),
					"BC");

			log.println("Adding certificates ... ");
			this.cmsGenerator.addCertificatesAndCRLs(store);

			// Finalmente, si può creare il l'oggetto CMS.
			log.println("Generating CMSSignedData ");
			s = this.cmsGenerator.generate(this.msg, true);

			// Verifica

			log.println("\nStarting CMSSignedData verification ... ");
			// recupero dal CMS la lista dei certificati
			CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");

			// Recupero i firmatari.
			SignerInformationStore signers = s.getSignerInfos();
			Collection c = signers.getSigners();

			log.println(c.size() + " signers found.");

			Iterator it = c.iterator();

			// ciclo tra tutti i firmatari
			int i = 0;
			boolean verified = true;
			while (it.hasNext() && verified) {
				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = certs.getCertificates(signer
						.getSID());

				if (certCollection.size() == 1) {
					// Iterator certIt = certCollection.iterator();
					// X509Certificate cert = (X509Certificate)
					// certIt.next();

					X509Certificate cert = (X509Certificate) certCollection
							.toArray()[0];
					log.println(i + ") Verifiying signature from:\n"
							+ cert.getSubjectDN());
					/*
					 * log.println("Certificate follows:");
					 * log.println("====================================");
					 * log.println(cert);
					 * log.println("====================================");
					 */
					if (verified = signer.verify(cert, "BC")) {

						log.println("SIGNATURE " + i + " OK!");
					} else {
						System.err.println("SIGNATURE " + i + " Failure!");
						JOptionPane
								.showMessageDialog(
										this,
										"La verifica della firma di:\n"
												+ cert.getSubjectDN()
												+ "\n è fallita!",
										"Costruzione della busta pkcs7 fallita.",
										JOptionPane.ERROR_MESSAGE);
					}
				} else {
					System.out
							.println("There is not exactly one certificate for this signer!");
				}
				i++;
			}
			if (!verified)
				s = null;
		}

		return s;
	}

	/**
	 * Converts a byte array in its exadecimal representation.
	 * 
	 * @param bytes
	 *            byte[]
	 * @return java.lang.String
	 */
	String formatAsHexString(byte[] bytes) {
		int n, x;
		String w = new String();
		String s = new String();
		for (n = 0; n < bytes.length; n++) {

			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1) {
				w = "0" + w;
			}
			s = s + w + ((n + 1) % 16 == 0 ? "\n" : " ");
		}
		return s;
	}

	/**
	 * Creates the base64 encoding of a byte array.
	 * 
	 * @param bytes
	 *            byte[]
	 * @return java.lang.String
	 */
	public String encodeFromBytes(byte[] bytes) {
		String encString = null;

		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		encString = encoder.encode(bytes);

		return encString;
	}

	/**
	 * Sets the base64 encoded digest.
	 * 
	 * @param data
	 *            String
	 */
	public void setEncodedDigest(String data) {
		this.encodedDigest = data;
	}

	/**
	 * Starts a signing task in a separate thread.
	 * 
	 * @param digestOnToken
	 *            if true, the cryptoki - card takes care of digesting; raw
	 *            bytes to sign are passed to cryptoki functions.
	 */

	/**
	 * Sets the private-key encrypted digest
	 * 
	 * @param newEncryptedDigest
	 *            byte[]
	 */
	public void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * Sets the signer certificate
	 * 
	 * @param newCertificate
	 *            byte[]
	 */
	private void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * Returns the base64 encoding of the digest.
	 * 
	 * @return the base64 encoding.
	 */
	public String getEncodedDigest() {

		return this.encodedDigest;
	}

	/**
	 * Returns information about this applet.
	 * 
	 * @return a string of information about this applet
	 */
	public String getAppletInfo() {
		return "SignApplet\n" + "\n" + "This type was created in VisualAge.\n"
				+ "";
	}

	/**
	 * Returns the signer's certificate.
	 * 
	 * @return byte
	 */
	public byte[] getCertificate() {
		return certificate;
	}

	/**
	 * Returns the CMS.
	 * 
	 * @return CMSSignedData
	 */
	public CMSSignedData getCMS() {
		return cms;
	}

	/**
	 * Returns the cryptoki library name.
	 * 
	 * @return java.lang.String
	 */
	private java.lang.String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Gets the digest encrypted with the private key of the signer.
	 * 
	 * @return byte[]
	 */
	public byte[] getEncryptedDigest() {
		return encryptedDigest;
	}

	/**
	 * Returns the label identifiyng the signer objects on the token.
	 * 
	 * @return java.lang.String
	 */
	private java.lang.String getSignerLabel() {
		return signerLabel;
	}

	/**
	 * Converts a base64 String in a byte array.
	 * 
	 * @param s
	 *            String
	 * @return byte[]
	 */
	public byte[] decodeToBytes(String s) {
		byte[] stringBytes = null;
		try {
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			stringBytes = decoder.decodeBuffer(s);
		} catch (java.io.IOException e) {
			log.println("Errore di io: " + e);
		}
		return stringBytes;
	}

	/**
	 * Inizialize frame components
	 * 
	 * @throws CMSException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private void initComponents() throws CMSException, FileNotFoundException,
			IOException, GeneralSecurityException {
		timer = new Timer(100, new ActionListener() {
			public void actionPerformed(ActionEvent evt) {

				if (task.getMessage() != null) {
					String s = new String();
					s = "Lettura certificato\n" + task.getMessage();
					s = s.substring(0, Math.min(60, s.length()));

					textArea2.setText(s);
					progressBar.setMaximum(2);
					progressBar.setValue(task.getCurrent());

				}
				if (task.error()) {

					textArea2.setText("Errore...\n" + task.getErrorMsg());
					progressBar.setValue(1);
					task.stop();
					timer.stop();

					log.println("Errore PIN");
					JOptionPane.showMessageDialog(frame, task.getErrorMsg(),
							"Attenzione", JOptionPane.WARNING_MESSAGE);
					frame.hide();

					FreeSignerSignApplet2 nuovo = new FreeSignerSignApplet2(
							taskBack, fileDaAprire,callBackUrl,jso);

				}
				if (task.done() && !task.error()) {

					timer.stop();
					
					boolean cmsOk = false;
					String errorReason = null;
					if (task.getCurrent() == DigestSignTask.SIGN_DONE) {
						Toolkit.getDefaultToolkit().beep();

						setEncryptedDigest(task.getEncryptedDigest());
						setCertificate(task.getCertificate());

						try {
							closeSignature();
						} catch (CertificateException e) {
							log.println("Error closing signature process:\n"
									+ e);
						}
						log.println("Building  CMSSignedData...");

						try {
							cms = buildCMSSignedData();
							if (cms != null) {
								cmsOk = true;
								log.println("CMSSignedData built!");
							} else {
								log.println("CMSSignedData NOT built!");
								errorReason = "Errore: Verifica firma fallita";
							}
						} catch (CMSException ex) {
							errorReason = "Errore CMS";
							log.println(errorReason + ":\n" + ex);
						} catch (NoSuchProviderException ex) {
							errorReason = "Errore: Provider crittografico non disponibile";
							log.println(errorReason + ":\n" + ex);
						} catch (NoSuchAlgorithmException ex) {
							errorReason = "Errore: algoritmo non disponibile";
							log.println(errorReason + ":\n" + ex);
						} catch (CertificateNotYetValidException ex) {
							errorReason = "Errore: Certificato non ancora valido";
							log.println(errorReason + ":\n" + ex);
						} catch (CertificateExpiredException ex) {
							errorReason = "Errore: Certificato scaduto!";
							log.println(errorReason + ":\n" + ex);
						} catch (InvalidAlgorithmParameterException ex) {
							errorReason = "Errore parametro algoritmo";
							log.println(errorReason + ":\n" + ex);
						} catch (CertStoreException ex) {
							errorReason = "Errore CertStore";
							log.println(errorReason + ":\n" + ex);
						}

					}

					if (!cmsOk) {
						JOptionPane.showMessageDialog(frame, errorReason,
								"La costruzione dei dati firmati è fallita!",
								JOptionPane.ERROR_MESSAGE);
						frame.hide();
						FreeSignerSignApplet2 nuovo = new FreeSignerSignApplet2(
								taskBack, fileDaAprire, callBackUrl,jso);

					} else {
						frame.hide();
						FreeSignerSignApplet4 nuovo = new FreeSignerSignApplet4(
								cms, fileDaAprire, taskBack, callBackUrl, selectedBack,jso);
					}

				}

			}
		});
		// *********************************

		panel4 = new JPanel();
		label2 = new JLabel();
		textPane1 = new JTextPane();
		panel5 = new JPanel();
		textArea1 = new JTextArea();
		textArea2 = new JTextArea();
		progressBar = new JProgressBar();

		textPane2 = new JTextPane();
		textField1 = new JTextField();
		button1 = new JButton();
		panel6 = new JPanel();
		button2 = new JButton();
		button3 = new JButton();
		button4 = new JButton();
		GridBagConstraints gbc;
		// ======== this ========
		Container contentPane = getContentPane();
		contentPane.setLayout(new GridBagLayout());
		((GridBagLayout) contentPane.getLayout()).columnWidths = new int[] {
				165, 0, 0 };
		((GridBagLayout) contentPane.getLayout()).rowHeights = new int[] { 105,
				50, 0 };
		((GridBagLayout) contentPane.getLayout()).columnWeights = new double[] {
				0.0, 1.0, 1.0E-4 };
		((GridBagLayout) contentPane.getLayout()).rowWeights = new double[] {
				1.0, 0.0, 1.0E-4 };

		// ======== panel4 ========
		{
			panel4.setBackground(Color.white);
			panel4.setLayout(new GridBagLayout());
			((GridBagLayout) panel4.getLayout()).columnWidths = new int[] {
					160, 0 };
			((GridBagLayout) panel4.getLayout()).rowHeights = new int[] { 0, 0,
					0 };
			((GridBagLayout) panel4.getLayout()).columnWeights = new double[] {
					0.0, 1.0E-4 };
			((GridBagLayout) panel4.getLayout()).rowWeights = new double[] {
					1.0, 1.0, 1.0E-4 };

			// ---- label2 ----
			label2.setIcon(new ImageIcon("images"
					+ System.getProperty("file.separator")
					+ "logo-freesigner-piccolo.png"));
			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 0;
			gbc.fill = GridBagConstraints.HORIZONTAL;
			gbc.insets.bottom = 5;
			panel4.add(label2, gbc);

			// ---- textPane1 ----
			textPane1.setFont(new Font("Verdana", Font.BOLD, 12));
			textPane1.setText("Generazione\nfirma");
			textPane1.setEditable(false);
			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 1;
			gbc.anchor = GridBagConstraints.NORTHWEST;
			panel4.add(textPane1, gbc);
		}
		gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.insets.bottom = 5;
		gbc.insets.right = 5;
		contentPane.add(panel4, gbc);

		// ======== panel5 ========
		{
			panel5.setBackground(Color.white);
			panel5.setLayout(new GridBagLayout());
			((GridBagLayout) panel5.getLayout()).columnWidths = new int[] { 0,
					205, 0, 0 };
			((GridBagLayout) panel5.getLayout()).rowHeights = new int[] { 100,
					0, 30, 30, 0 };
			((GridBagLayout) panel5.getLayout()).columnWeights = new double[] {
					1.0, 0.0, 1.0, 1.0E-4 };
			((GridBagLayout) panel5.getLayout()).rowWeights = new double[] {
					0.0, 0.0, 1.0, 1.0, 1.0E-4 };

			// ---- textArea1 ----
			textArea1.setFont(new Font("Verdana", Font.BOLD, 14));
			textArea1.setText("Generazione firma");
			textArea1.setEditable(false);
			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 0;
			gbc.gridwidth = 3;
			gbc.fill = GridBagConstraints.VERTICAL;
			gbc.insets.bottom = 5;
			panel5.add(textArea1, gbc);

			// ---- textArea2 ----
			textArea2.setFont(new Font("Verdana", Font.PLAIN, 12));
			textArea2.setText("Inizializzazione\n");
			textArea2.setEditable(false);
			textArea2.setColumns(30);
			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 1;
			gbc.gridwidth = 3;
			gbc.fill = GridBagConstraints.BOTH;
			panel5.add(textArea2, gbc);

			progressBar.setValue(0);
			progressBar.setStringPainted(true);
			progressBar.setBounds(0, 0, 300, 150);

			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 2;
			gbc.fill = GridBagConstraints.HORIZONTAL;
			gbc.insets.bottom = 5;
			gbc.insets.right = 5;
			gbc.gridwidth = 3;
			panel5.add(progressBar, gbc);

		}
		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.insets.bottom = 5;
		contentPane.add(panel5, gbc);

		// ======== panel6 ========
		{
			panel6.setBackground(Color.white);
			panel6.setLayout(new GridBagLayout());
			((GridBagLayout) panel6.getLayout()).columnWidths = new int[] { 0,
					0, 0, 0 };
			((GridBagLayout) panel6.getLayout()).rowHeights = new int[] { 0, 0 };
			((GridBagLayout) panel6.getLayout()).columnWeights = new double[] {
					1.0, 1.0, 1.0, 1.0E-4 };
			((GridBagLayout) panel6.getLayout()).rowWeights = new double[] {
					1.0, 1.0E-4 };

			// ---- button2 ----
			button2.setText("Indietro");
			gbc = new GridBagConstraints();
			gbc.gridx = 0;
			gbc.gridy = 0;
			gbc.insets.right = 5;
			button2.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					frame.hide();

					FreeSignerSignApplet nuovo = new FreeSignerSignApplet();

				}
			});

			// panel6.add(button2, gbc);

			// ---- button4 ----
			button4.setText("Annulla");
			gbc = new GridBagConstraints();
			gbc.gridx = 2;
			gbc.gridy = 0;
			// panel6.add(button4, gbc);
		}
		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.fill = GridBagConstraints.BOTH;
		contentPane.add(panel6, gbc);
		contentPane.setBackground(Color.white);
		frame.setContentPane(contentPane);
		frame.setTitle("Freesigner");
		frame.setSize(300, 150);
		frame.setResizable(false);
		frame.pack();
		Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
		frame.setLocation((d.width - frame.getWidth()) / 2, (d.height - frame
				.getHeight()) / 2);

		frame.show();

		frame.setVisible(true);

		frame.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		});

	}

	/**
	 * Returns the contents of the file in a byte array.
	 * 
	 * @param file
	 *            File
	 * @throws IOException
	 * @return byte[]
	 */
	public static byte[] getBytesFromFile(File file) throws IOException {
		InputStream is = new FileInputStream(file);

		// Get the size of the file
		long length = file.length();

		// You cannot create an array using a long type.
		// It needs to be an int type.
		// Before converting to an int type, check
		// to ensure that file is not larger than Integer.MAX_VALUE.
		if (length > Integer.MAX_VALUE) {
			// File is too large
		}

		// Create the byte array to hold the data
		byte[] bytes = new byte[(int) length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length
				&& (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file "
					+ file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

	void setMessage(String s) {
		textField1.setText(s);
	}

	private Timer timer;
	private JProgressBar progressBar;
	private DigestSignTask task;
	private String fileDaAprire;
	private JFrame frame;
	private JFrame frameprec;
	private JPanel panel4;
	private JLabel label2;
	private JTextPane textPane1;
	private JPanel panel5;
	private JTextArea textArea1;
	private JTextArea textArea2;
	private JTextPane textPane2;
	private JTextField textField1;
	private JButton button1;
	private JPanel panel6;
	private JButton button2;
	private JButton button3;
	private JButton button4;

	private PINDialog dialog = null;

	private java.io.PrintStream log = null;

	boolean debug = false;

	boolean submitAfterSigning = false;

	private byte[] bytesToSign = null;

	private String encodedDigest = null;

	private byte[] encryptedDigest;

	public final static int ONE_SECOND = 1000;

	private java.lang.String cryptokiLib = null;

	private java.lang.String signerLabel = null;

	private byte[] certificate = null;

	private CMSProcessable msg = null;

	private ExternalSignatureCMSSignedDataGenerator cmsGenerator = null;

	private ExternalSignatureSignerInfoGenerator signerInfoGenerator = null;

	private ArrayList signersCertList = null;

	private File fileToSign = null;
	private CMSSignedData cms = null;
	// questi due servono per reinizializzare FreesignerSignFrame3 quando viene
	// da FreesignerSignFrame4
	private ReadCertsTask taskBack;
	private int selectedBack;
        /* Cades Impl. */
        private X509Certificate certforcades;
        /* End Cades Impl. */

}
