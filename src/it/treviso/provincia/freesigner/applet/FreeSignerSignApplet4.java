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

import it.treviso.provincia.freesigner.applet.FreesignerVerifyFrame2;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.swing.*;

import org.bouncycastle.cms.*;
import org.bouncycastle.util.encoders.*;

import netscape.javascript.JSObject;


/**
 * GUI of signing operation
 *
 * @author Luca Lorenzetto (original version Francesco Cendron)
 */
public class FreeSignerSignApplet4 extends JFrame {


		private JSObject jso;

		/**
         * Constructor
         *
         */

    public FreeSignerSignApplet4() {
        fileDaAprire = "";
        //frame = new JFrame();
        //frame.setBackground(Color.white);
        //initComponents();
        this.doSave();
    }

    /**
     * Constructor
     *
     * @param filepath String
     */
    public FreeSignerSignApplet4(String filepath, String callBackUrl) {
        fileDaAprire = new String(filepath);
        this.callBackUrl = callBackUrl;
        //frame = new JFrame();
        //frame.setBackground(Color.white);
        //initComponents();
        this.doSave();
    }

    /**
     * Constructor
     *
     * @param c cms
     * @param filepath String
     * @param t task ReadCertsTask
     * @param selected index of selected cert
     * @param jso 
     */
    public FreeSignerSignApplet4(CMSSignedData c, String filepath, ReadCertsTask t, String callBackUrl,
                    int selected, JSObject jso) {
        fileDaAprire = new String(filepath);
        taskBack = t;
        selectedBack = selected;
       // frame = new JFrame();
        cms = c;
        this.callBackUrl = callBackUrl;
        log = System.out;
       // frame.setBackground(Color.white);
       // initComponents();
        this.jso = jso;
        this.doSave();
        
    }

    /**
 * Inizialize frane components
 */

    private void initComponents() {
     //   conf = Configuration.getInstance();
        panel4 = new JPanel();
        label2 = new JLabel();
        textPane1 = new JTextPane();
        panel5 = new JPanel();
        textArea1 = new JTextArea();
        textArea2 = new JTextArea();
        textPane2 = new JTextPane();
        textField1 = new JTextField();
        textField2 = new JTextField();
        button1 = new JButton();
        panel6 = new JPanel();
   //     button2 = new JButton();
        button3 = new JButton();
        button4 = new JButton();
        button7 = new JButton();
        GridBagConstraints gbc;

        //======== this ========
        Container contentPane = getContentPane();
        contentPane.setLayout(new GridBagLayout());
        ((GridBagLayout) contentPane.getLayout()).columnWidths = new int[] {165,
                0, 0};
        ((GridBagLayout) contentPane.getLayout()).rowHeights = new int[] {0,
                0, 0};
        ((GridBagLayout) contentPane.getLayout()).columnWeights = new double[] {
                0.0, 1.0, 1.0E-4};
        ((GridBagLayout) contentPane.getLayout()).rowWeights = new double[] {
                1.0, 0.0, 1.0E-4};

        //======== panel4 ========
        {
            panel4.setBackground(Color.white);
            panel4.setLayout(new GridBagLayout());
            ((GridBagLayout) panel4.getLayout()).columnWidths = new int[] {160,
                    0};
            ((GridBagLayout) panel4.getLayout()).rowHeights = new int[] {0, 0,
                    0};
            ((GridBagLayout) panel4.getLayout()).columnWeights = new double[] {
                    0.0, 1.0E-4};
            ((GridBagLayout) panel4.getLayout()).rowWeights = new double[] {1.0,
                    1.0, 1.0E-4};

            //---- label2 ----
            label2.setIcon(new ImageIcon(
                    "images" + System.getProperty("file.separator") +
                    "logo-freesigner-piccolo.png"));
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets.bottom = 5;
            panel4.add(label2, gbc);

            //---- textPane1 ----
            textPane1.setFont(new Font("Verdana", Font.BOLD, 12));
            textPane1.setText("Salvataggio\ndel documento\nfirmato");
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

        //======== panel5 ========
        {
            panel5.setBackground(Color.white);
            panel5.setLayout(new GridBagLayout());
            ((GridBagLayout) panel5.getLayout()).columnWidths = new int[] {50,
                    50, 50, 0};
            ((GridBagLayout) panel5.getLayout()).rowHeights = new int[] {0, 0,
                    0, 0, 0};
            ((GridBagLayout) panel5.getLayout()).columnWeights = new double[] {
                    1.0, 1.0, 1.0, 1.0E-4};
            ((GridBagLayout) panel5.getLayout()).rowWeights = new double[] {0.0,
                    0.0, 1.0, 1.0, 1.0E-4};

            //---- textArea1 ----
            textArea1.setFont(new Font("Verdana", Font.BOLD, 14));
            textArea1.setText(
                    "Salvataggio del documento firmato");
                                textArea1.setEditable(false);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.VERTICAL;
            gbc.insets.bottom = 5;
            panel5.add(textArea1, gbc);

            //---- textArea2 ----
            textArea2.setFont(new Font("Verdana", Font.PLAIN, 12));
                        textArea2.setEditable(false);
                        
            textArea2.setText(
                        "Selezionare dove salvare il file firmato \n[salvataggio in formato Base 64].");


            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.insets.bottom = 5;
            panel5.add(textArea2, gbc);

            //---- textPane2 ----
            textPane2.setFont(new Font("Verdana", Font.PLAIN, 11));
            textPane2.setText("File firmato:");
                        textPane2.setEditable(false);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 2;
            gbc.anchor = GridBagConstraints.WEST;
            gbc.insets.bottom = 2;
            gbc.insets.right = 5;
            panel5.add(textPane2, gbc);

            textField1.setText(fileDaAprire + ".p7m");
            textField1.setColumns(30);
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.gridwidth = 3;

            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets.bottom = 5;
            gbc.insets.right = 5;
            panel5.add(textField1, gbc);

        }
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets.bottom = 5;
        contentPane.add(panel5, gbc);

        //---- button4 ----
        button7.setText("Aggiungi Firma");
        gbc = new GridBagConstraints();
        gbc.gridx = 3;
        gbc.gridy = 5;
        button7.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                CMSProcessable msg = cms.getSignedContent();

                ArrayList signersCertList = new ArrayList();
                CertStore certs = null;
                try {
                    certs = cms.getCertificatesAndCRLs("Collection", "BC");
                } catch (CMSException ex1) {
                } catch (NoSuchProviderException ex1) {
                } catch (NoSuchAlgorithmException ex1) {
                }

                //Recupero i firmatari.
                SignerInformationStore signers = cms.getSignerInfos();
                Collection c = signers.getSigners();

                log.println(c.size() + " signers found.");
                Iterator it = c.iterator();
                //ciclo tra tutti i firmatari
                int i = 0;
                while (it.hasNext()) {
                    SignerInformation signer = (SignerInformation) it.next();
                    Collection certCollection = null;
                    try {
                        certCollection = certs.getCertificates(signer
                                .getSID());
                    } catch (CertStoreException ex) {
                    }

                    if (certCollection.size() == 1) {
                        //Iterator certIt = certCollection.iterator();
                        //X509Certificate cert = (X509Certificate)
                        // certIt.next();

                        X509Certificate cert = (X509Certificate)
                                               certCollection
                                               .toArray()[0];
                        signersCertList.add(cert);

                    } else {
                        System.out
                                .println(
                                        "There is not exactly one certificate for this signer!");
                    }
                    i++;
                }

            }
        });


        //---- button2 ----
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.insets.left = 20;
        gbc.insets.top = 20;
        gbc.insets.bottom = 20;

        gbc.anchor = GridBagConstraints.CENTER;

        //---- button4 ----
        button4.setText("Esci");
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 5;

        gbc.insets.top = 20;
        gbc.insets.bottom = 20;
        gbc.insets.right = 10;

        gbc.anchor = GridBagConstraints.CENTER;
        button4.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String s = "Vuoi veramente uscire dalla procedura guidata?";
                if (!saved) {
                    s = "Vuoi uscire senza salvare il file firmato?";
                }
                int q = JOptionPane.showConfirmDialog(
                        frame,
                        s,
                        "Attenzione",
                        JOptionPane.YES_NO_OPTION);

                if (q == JOptionPane.YES_OPTION) {
                    frame.hide();
                    System.exit(0);

                }

            }
        });

        panel5.add(button4, gbc);

        //---- button3 ----
        button3.setText("Salva");
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 5;
        gbc.insets.right = 20;
        gbc.insets.top = 20;
        gbc.insets.bottom = 20;
        gbc.anchor = GridBagConstraints.CENTER;
        button3.setEnabled(cms!=null);
                
        button3.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                log.println("Saving signed message");

                String p7mFilePath = fileDaAprire + ".p7m";
                File file = new File(p7mFilePath);

                    try {
                         saved = save(Base64.encode(cms.getEncoded()), file);
                    } catch (IOException ex1) {
                    	JOptionPane.showMessageDialog(null, "Errore di I/O durante il salvataggio di "+p7mFilePath, "Errore", JOptionPane.ERROR_MESSAGE);
                    }

                    if (saved) {
                        log.println("Signed message saved to: "
                                    + file.getAbsolutePath());
                        button3.setEnabled(false);
                        
                        MessageDigest mdigest;
                        String mhash  = "";
						try {
							mdigest = MessageDigest.getInstance("SHA-512");
							mhash = calculateHash(mdigest, p7mFilePath);
						} catch (Exception e2) {
							e2.printStackTrace();
						}
                        
                        /*
                         * Calling the callback url
                         */
                        URL clb = null;
						try {
							clb = new URL(callBackUrl+"&mhash="+mhash);
						} catch (MalformedURLException e1) {
							e1.printStackTrace();
						}
                        BufferedReader in = null;
						try {
							in = new BufferedReader(
							new InputStreamReader(clb.openStream()));
							String inputLine;
							while ((inputLine = in.readLine()) != null)
							    System.out.println(inputLine);
							in.close();

						} catch (IOException e1) {
							e1.printStackTrace();
						}

                    }
            }


        });

        panel5.add(button3, gbc);

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
     * Saves bytearray to file
     *
     * @return true if it saved
     * @param bytes byte[]
     * @param to_file File
     * @throws IOException
     */
    public static boolean save(byte[] bytes, File to_file) throws
            IOException {
        boolean saved = false;
        int q = JOptionPane.YES_OPTION;
        if (to_file.exists()) {
            if (!to_file.canWrite()) {
                abort("Il file non ha i\npermessi di scrittura.");
            }
            // Ask whether to overwrite it
            q = JOptionPane.showConfirmDialog(
                    null,
                    "Il file esiste.\nSovrascriverlo?",
                    "Attenzione",
                    JOptionPane.YES_NO_OPTION);

            // Check the response.  If not a Yes, abort the copy.
            if (q == JOptionPane.NO_OPTION) {
                //non sovrascrivere
                return saved;
            }
        }
        if (q == JOptionPane.YES_OPTION) {

            FileOutputStream to = null; // Stream to write to destination

            ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
            to = new FileOutputStream(to_file); // Create output stream
            byte[] buffer = new byte[4096]; // A buffer to hold file contents
            int bytes_read; // How many bytes in buffer
            // Read a chunk of bytes into the buffer, then write them out,
            // looping until we reach the end of the file (when read() returns -1).
            // Note the combination of assignment and comparison in this while
            // loop.  This is a common I/O programming idiom.
            while ((bytes_read = bais.read(buffer)) != -1) { // Read bytes until EOF
                to.write(buffer, 0, bytes_read); //   write bytes
            }
            to.close();
            //abort("Il file è stato salvato.");
            saved = true;

        }
        return saved;
    }

    /**
     * Method invoked for saving
     */
    
    public void doSave() {
        log.println("Saving signed message");

        String p7mFilePath = fileDaAprire + ".p7m";
        File file = new File(p7mFilePath);

            try {
                 saved = save(Base64.encode(cms.getEncoded()), file);
            } catch (IOException ex1) {
            	JOptionPane.showMessageDialog(null, "Errore di I/O durante il salvataggio di "+p7mFilePath, "Errore", JOptionPane.ERROR_MESSAGE);
            }

            if (saved) {
                log.println("Signed message saved to: "
                            + file.getAbsolutePath());                
                
                MessageDigest mdigest;
                String mhash  = "";
				try {
					mdigest = MessageDigest.getInstance("SHA-512");
					mhash = calculateHash(mdigest, p7mFilePath);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
				
				jso.eval("window.location.href='"+callBackUrl+"&mhash="+mhash+"'");
				

            }
    }

    
    /**
     * A convenience method
     *
     * @param msg String
     */
    private static void abort(String msg) {
        JOptionPane.showMessageDialog(null,
                                      msg,
                                      "Attenzione",
                                      JOptionPane.INFORMATION_MESSAGE);

    }
    
    
    /**
     * hash calculators convenience method
     */

    private static String calculateHash(MessageDigest algorithm,
            String fileName) throws Exception{

        FileInputStream     fis = new FileInputStream(fileName);
        BufferedInputStream bis = new BufferedInputStream(fis);
        DigestInputStream   dis = new DigestInputStream(bis, algorithm);

        // read the file and update the hash calculation
        while (dis.read() != -1);

        // get the hash value as byte array
        byte[] hash = algorithm.digest();

        return byteArray2Hex(hash);
    }

    /**
     * Converts in base 64 i byte in input
     * @param hash
     * @return
     */
    private static String byteArray2Hex(byte[] hash) {
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }


    private FreesignerVerifyFrame2 nuovo;
    private Configuration conf;
    private boolean saved = false;
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
    private JTextField textField2;
    private JButton button1;
    private JPanel panel6;
  //  private JButton button2;
    private JButton button3;
    private JButton button4;
    private JButton button7;
    private JRadioButton DERButton;
    private JRadioButton Base64Button;

    private CMSSignedData cms;
    private ReadCertsTask taskBack;
    private int selectedBack;
    private String callBackUrl;

    private java.io.PrintStream log = null;


}
