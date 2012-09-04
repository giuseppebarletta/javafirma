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
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.tree.*;

import it.treviso.provincia.freesigner.crl.CertificationAuthorities;

import org.bouncycastle.asn1.*;



/**
 * GUI showing certificate details
 *
 * @ Francesco Cendron
 */
public class FreesignerCertFrame extends JFrame {

    /**
     * Constructor this (c, C, false)<br><br>
     * Costruttore: si richiama al this (c, C, false)
     *
     * @param c certificate
     * @param C CertificationAuthorities
     */
    public FreesignerCertFrame(X509Certificate c, CertificationAuthorities C) {

        this(c, C, false);

    }

    /**
     * Constructor
     *
     * @param c certificate
     * @param C CertificationAuthorities
     * @param isDownloadCRLForced true if CRL download is forced
     */
    public FreesignerCertFrame(X509Certificate c, CertificationAuthorities C,
                      boolean isDownloadCRLForced) {

        frame = new JFrame();
        CAroot = C;
        cert = c;
        cv = new CertValidity(c, C);
        cv.setisDownloadCRLForced(isDownloadCRLForced);
        try {
            initComponents();
        } catch (CertificateParsingException ex1) {
        }

    }


    /**
     * Inizialize frame components
     *
     * @throws CertificateParsingException
     */
    private void initComponents() throws CertificateParsingException {

        dialogPane = new JPanel();
        contentPane = new JPanel();
        tabbedPane1 = new JTabbedPane();
        panel1 = new JPanel();
        textPane1 = new JTextPane();
        button1 = new JButton();
        panel2 = new JPanel();
        scrollPane1 = new JScrollPane();
        table1 = new JTable();
        scrollPane3 = new JScrollPane();
        textPane2 = new JTextPane();
        textPane3 = new JTextPane();
        panel3 = new JPanel();
        scrollPane2 = new JScrollPane();
        tree1 = new JTree();
        button2 = new JButton();
        button3 = new JButton();
        panel4 = new JPanel();
        buttonBar = new JPanel();
        okButton = new JButton();
        GridBagConstraints gbc;

        //======== this ========
        Container contentPane2 = getContentPane();
        contentPane2.setLayout(new BorderLayout());

        //======== dialogPane ========
        {
            dialogPane.setBorder(new EmptyBorder(12, 12, 12, 12));

            dialogPane.setLayout(new BorderLayout());

            //======== contentPane ========
            {
                contentPane.setLayout(new GridBagLayout());
                ((GridBagLayout) contentPane.getLayout()).columnWidths = new int[] {
                        0, 0};
                ((GridBagLayout) contentPane.getLayout()).rowHeights = new int[] {
                        0, 0};
                ((GridBagLayout) contentPane.getLayout()).columnWeights = new double[] {
                        1.0, 1.0E-4};
                ((GridBagLayout) contentPane.getLayout()).rowWeights = new double[] {
                        1.0, 1.0E-4};

                //======== tabbedPane1 ========
                {
                    tabbedPane1.setPreferredSize(new Dimension(350, 400));

                    //======== panel1 ========
                    {
                        panel1.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel1.getLayout()).columnWidths = new int[] {
                                0, 0};
                        ((GridBagLayout) panel1.getLayout()).rowHeights = new int[] {
                                0, 0, 0};
                        ((GridBagLayout) panel1.getLayout()).columnWeights = new double[] {
                                1.0, 1.0E-4};
                        ((GridBagLayout) panel1.getLayout()).rowWeights = new double[] {
                                1.0, 1.0, 1.0E-4};

                        //---- textPane1 ----
                        textPane1.setFont(new Font("MS Sans Serif", Font.BOLD,
                                11));
                 textPane1.setEditable(false);
                        String s = new String();

                        if (!cv.getPassed()) {

                            if (!cv.isCRLChecked() ||
                                cv.getCRLerror().length() > 0) {
                                s = s + "\n Verifica CRL non effettuata";
                                if (cv.getCRLerror().length() > 0) {
                                    //c'è stato un errore
                                    JOptionPane.showMessageDialog(frame,
                                            "C'è stato un errore nella verifica CRL.\n" +
                                            cv.getCRLerror(),
                                            "Errore verifica CRL",
                                            JOptionPane.ERROR_MESSAGE);

                                    s = s + "\n " + cv.getCRLerror();
                                }
                            } else {
                                s = s + "Certificato NON valido";
                            }
                        } else {
                            s = s + "Certificato valido.";
                        }

                        textPane1.setText("Informazioni sul certificato\n" +
                                          "\n\n" + s + "\n\n\n\nRilasciato a: " +
                                          getFormattedNameFromDN("" +
                                cert.getSubjectDN()) +
                                          "\n\nRilasciato da: " +
                                          getFormattedNameFromDN("" +
                                cert.getIssuerDN()) +
                                          "\n\nAttivo da: " + cert.getNotBefore());
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        panel1.add(textPane1, gbc);

                        //---- button1 ----
                        button1.setText("Salva certificato");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 1;
                        gbc.anchor = GridBagConstraints.EAST;
                        button1.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                JFileChooser fc = new JFileChooser();

                                File f = new File(
                                        System.getProperty("user.home")
                                        + System.getProperty("file.separator") +

                                        getNameFromDN("" + cert.getSubjectDN()) +
                                        ".der");
                                fc.setSelectedFile(f);
                                int n = fc.showSaveDialog(frame);
                                if (n == JFileChooser.APPROVE_OPTION) {
                                    //****
                                     f = fc.getSelectedFile();
                                    try {
                                        save(cert.getEncoded(), f);
                                    } catch (CertificateEncodingException
                                             ex1) {
                                    } catch (IOException ex1) {
                                    }

                                }

                            }
                        });

                        panel1.add(button1, gbc);
                    }
                    tabbedPane1.addTab("Generale", panel1);

                    //======== panel2 ========
                    {
                        panel2.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel2.getLayout()).columnWidths = new int[] {
                                0, 0};
                        ((GridBagLayout) panel2.getLayout()).rowHeights = new int[] {
                                105, 50, 0};
                        ((GridBagLayout) panel2.getLayout()).columnWeights = new double[] {
                                1.0, 1.0E-4};
                        ((GridBagLayout) panel2.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 1.0E-4};

                        //============table1=========
                        //Riconoscimento KeyUsage
                        String str = new String();
                        DERBitString dbs = new DERBitString(cert.
                                getExtensionValue("2.5.29.15"));

                        String usage = new String();
                        usage = dbs.getString();

                        String hexusage = usage.substring(usage.length() - 2,
                                usage.length());

                        usage = Integer.toBinaryString(Integer.parseInt(
                                hexusage, 16));
                        while (usage.length() < 8) {
                            usage = "0" + usage;
                        }

                        str = "";
                        if ((usage.substring(0, 1)).equals("1")) {
                            str += "digitalSignature ";
                        }
                        if ((usage.substring(1, 2)).equals("1")) {
                            str += "nonRepudiation ";
                        }
                        if ((usage.substring(2, 3)).equals("1")) {
                            str += "keyEncipherment ";
                        }
                        if ((usage.substring(3, 4)).equals("1")) {
                            str += "dataEncipherment ";
                        }
                        if ((usage.substring(4, 5)).equals("1")) {
                            str += "keyAgreement ";
                        }
                        if ((usage.substring(5, 6)).equals("1")) {
                            str += "keyCertSign ";
                        }
                        if ((usage.substring(6, 7)).equals("1")) {
                            str += "cRLSign ";
                        }
                        if ((usage.substring(7, 8)).equals("1")) {
                            str += "encipherOnly ";
                        }
                        // if ((usage.substring(,)).equals("1"))
                        //  str += "decipherOnly " ;

                        String[] columnNames = {"Campo",

                                               "Valore"};
                        final Object[][] data = { {"Versione",
                                                "" + cert.getVersion()},
                                                {"Numero di serie",
                                                "" +
                                                formatAsHexString((cert.
                                getSerialNumber().toByteArray()))}, {"Soggetto",
                                                "" + cert.getSubjectDN()},

                                                {"Valido dal",
                                                "" + cert.getNotBefore()},
                                                {"Valido fino al",
                                                "" + cert.getNotAfter()},
                                                {"Rilasciato da",
                                                "" + cert.getIssuerDN()},
                                {"Algoritmo della firma elettronica",
                                                "" + cert.getSigAlgName()},
                                                {"Chiave pubblica",
                                                "" + cert.getPublicKey()},

                                                {"Punti di distribuzione CRL",
                                                "" +
                                                getCrlDistributionPoint(cert)},

                                                {"Uso chiave",
                                                "" + str + " (" + hexusage +
                                                ")"}

                        };

                        table1 = new JTable(data, columnNames);

                        table1.setSelectionMode(ListSelectionModel.
                                                SINGLE_SELECTION);

                        //Ask to be notified of selection changes.
                        ListSelectionModel rowSM = table1.
                                getSelectionModel();
                        rowSM.addListSelectionListener(new
                                ListSelectionListener() {
                            public void valueChanged(ListSelectionEvent e) {
                                //Ignore extra messages.
                                if (e.getValueIsAdjusting()) {
                                    return;
                                }

                                ListSelectionModel lsm =
                                        (ListSelectionModel) e.getSource();
                                if (lsm.isSelectionEmpty()) {
                                    //no rows are selected
                                } else {
                                    int selectedRow = lsm.getMinSelectionIndex();
                                    //selectedRow is selected
                                                textPane2.setEditable(false);
                                    textPane2.setText("" +
                                            data[selectedRow][1]);
                                }
                            }
                        });

                        //======== scrollPane1 ========
                        {
                            scrollPane1.setViewportView(table1);
                            scrollPane1.setPreferredSize(new Dimension(150, 250));
                        }
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        panel2.add(scrollPane1, gbc);

                        //======== scrollPane3 ========
                        {
                            scrollPane3.setViewportView(textPane2);
                            scrollPane3.setPreferredSize(new Dimension(150, 100));
                        }
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        panel2.add(scrollPane3, gbc);
                    }
                    tabbedPane1.addTab("Dettagli", panel2);

                    //======== panel3 ========
                    {
                        panel3.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel3.getLayout()).columnWidths = new int[] {
                                0, 0, 0, 0};
                        ((GridBagLayout) panel3.getLayout()).rowHeights = new int[] {
                                105, 0, 0, 0, 200, 0};
                        ((GridBagLayout) panel3.getLayout()).columnWeights = new double[] {
                                1.0, 1.0, 1.0, 1.0E-4};
                        ((GridBagLayout) panel3.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 0.0, 0.0, 0.0, 1.0E-4};

                        //======== scrollPane2 ========
                        {

                            //---- tree1 ----
                            DefaultMutableTreeNode leaf =
                                    new DefaultMutableTreeNode(
                                            "" + cert.getSubjectDN());
                            DefaultMutableTreeNode parentOfleaf = new
                                    DefaultMutableTreeNode(
                                            "" + cert.getIssuerDN()); ;

                            X509Certificate certChild = cert;
                            X509Certificate certParent = null;
                            try {
                                certParent = CAroot.getCACertificate(certChild.
                                        getIssuerX500Principal());
                            } catch (GeneralSecurityException ex1) {
                            }
                            if (certParent != null) {
                                while (!certChild.getIssuerDN().equals(
                                        certChild.
                                        getSubjectDN())) {
                                    //finche' la CA non è autofirmata
                                    parentOfleaf = new DefaultMutableTreeNode(
                                            "" + certParent.getSubjectDN());
                                    parentOfleaf.add(leaf);
                                    leaf = parentOfleaf;
                                    certChild = certParent;
                                    try {
                                        certParent = CAroot.getCACertificate(
                                                certChild.
                                                getIssuerX500Principal());
                                    } catch (GeneralSecurityException ex) {
                                    }

                                    } ;

                                    tree1 = new JTree(parentOfleaf);
                                } else { //nel caso il certificato abbia una CA emettitrice
                                    //non presente nella root
                                    tree1 = new JTree(new
                                            DefaultMutableTreeNode(
                                            "" + certChild.getSubjectDN()));
                                }

                                tree1.getSelectionModel().setSelectionMode
                                        (TreeSelectionModel.
                                         SINGLE_TREE_SELECTION);

                                //Listen for when the selection changes.
                                tree1.addTreeSelectionListener(new
                                        TreeSelectionListener() {
                                    public void valueChanged(TreeSelectionEvent
                                            e) {
                                        DefaultMutableTreeNode node = (
                                                DefaultMutableTreeNode)
                                                tree1.
                                                getLastSelectedPathComponent();

                                        if (node == null) {
                                            return;
                                        }
                                        /* React to the node selection. */
                                        Object nodeInfo = node.getUserObject();
                                        if (node.isLeaf()) {
                                            button2.setEnabled(false);
                                        } else {
                                            button2.setEnabled(true);
                                        }

                                    }
                                });

                                JScrollPane treeView = new JScrollPane(tree1);

                                tree1.setVisibleRowCount(4);
                                scrollPane2.setViewportView(tree1);
                            }
                            gbc = new GridBagConstraints();
                            gbc.gridx = 0;
                            gbc.gridy = 0;
                            gbc.gridwidth = 3;
                            gbc.fill = GridBagConstraints.BOTH;
                            gbc.insets.bottom = 5;
                            panel3.add(scrollPane2, gbc);

                            //---- button2 ----
                            button2.setText("Visualizza certificato");
                            gbc = new GridBagConstraints();
                            gbc.gridx = 2;
                            gbc.gridy = 2;
                            gbc.fill = GridBagConstraints.BOTH;
                            gbc.insets.bottom = 5;
                            button2.setEnabled(false);
                            button2.addActionListener(new ActionListener() {
                                public void actionPerformed(ActionEvent e) {
                                    try {
                                        FreesignerCertFrame nuovo = new FreesignerCertFrame(
                                                CAroot.
                                                getCACertificate(cert.
                                                getIssuerX500Principal()),
                                                CAroot);
                                    } catch (GeneralSecurityException ex) {
                                    }
                                }
                            });

                            panel3.add(button2, gbc);

                            //---- button3 ----
                            button3.setText("Download CRL");
                            gbc = new GridBagConstraints();
                            gbc.gridx = 2;
                            gbc.gridy = 3;
                            gbc.fill = GridBagConstraints.BOTH;
                            gbc.insets.bottom = 5;
                            button3.addActionListener(new ActionListener() {
                                public void actionPerformed(ActionEvent e) {

                                    //forzo il download CRL
                                    FreesignerCertFrame nuovo = new FreesignerCertFrame(
                                            cert,
                                            CAroot, true);
                                    frame.hide();
                                }
                            });

                            panel3.add(button3, gbc);

                            //======== panel4 ========
                            {
                                panel4.setBorder(new TitledBorder(
                                        "Dettaglio Verifiche"));
                                panel4.setLayout(new GridBagLayout());
                                ((GridBagLayout) panel4.getLayout()).
                                        columnWidths = new int[] {
                                        0, 0, 0, 0};
                                ((GridBagLayout) panel4.getLayout()).rowHeights = new int[] {
                                        0, 0, 0, 0};
                                ((GridBagLayout) panel4.getLayout()).
                                        columnWeights = new double[] {
                                        1.0, 1.0, 1.0, 1.0E-4};
                                ((GridBagLayout) panel4.getLayout()).rowWeights = new double[] {
                                        1.0, 1.0, 1.0, 1.0E-4};
                            }

                            //======== textPane3 ========
                            {
                                textPane3.setPreferredSize(new Dimension(300,
                                        170));
                textPane3.setEditable(false);

                                String[] s = new String[3];
                                if (!cv.getExpired()) {
                                    s[0] = "-Certificato non scaduto";
                                } else {
                                    s[0] = "-Certificato scaduto";
                                }
                                if (!cv.getPathValid()) {
                                    s[1] =
                                            "-Percorso di certificazione non valido";
                                } else {
                                    s[1] = "-Percorso di certificazione valido";
                                }

                                if (!cv.getRevoked()) {
                                    if (!cv.isCRLChecked() ||
                                        cv.getCRLerror().length() > 0) {
                                        s[2] = "-Verifica CRL non effettuata.";
                                        if (cv.getCRLerror().length() > 0) {
                                            s[2] = s[2] + "\n " +
                                                    cv.getCRLerror();
                                        }

                                    } else {
                                        s[2] = "-Certificato non revocato.";
                                    }

                                } else {
                                    if (cv.isCRLChecked() &&
                                        !(cv.getCRLerror().length() > 0) &&
                                        (cv.getPathValid())) {
                                        s[2] =
                                                "-Certificato revocato " +
                                                cv.getReasonCode();

                                    } else {
                                        s[2] = "-Verifica CRL non effettuata.";
                                        if (cv.getCRLerror().length() > 0) {
                                            s[2] = s[2] + "\n " +
                                                    cv.getCRLerror();
                                        }
                                        if (!(cv.getPathValid())) {
                                            s[2] =
                                                    s[2] +
                                                    "\n CA non presente nella root";
                                        }

                                    }

                                }

                                textPane3.setText(s[0] + "\n\n" + s[1] + "\n\n" +
                                                  s[2]);

                            }
                            gbc = new GridBagConstraints();
                            gbc.gridx = 0;
                            gbc.gridy = 1;
                            gbc.fill = GridBagConstraints.BOTH;
                            panel4.add(textPane3, gbc);

                            gbc = new GridBagConstraints();
                            gbc.gridx = 0;
                            gbc.gridy = 4;
                            gbc.gridwidth = 3;
                            gbc.fill = GridBagConstraints.BOTH;
                            panel3.add(panel4, gbc);
                        }
                        tabbedPane1.addTab("Percorso di certificazione", panel3);
                    }
                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 0;
                    gbc.fill = GridBagConstraints.BOTH;
                    contentPane.add(tabbedPane1, gbc);
                }
                dialogPane.add(contentPane, BorderLayout.CENTER);

                //======== buttonBar ========
                {
                    buttonBar.setBorder(new EmptyBorder(12, 0, 0, 0));
                    buttonBar.setLayout(new GridBagLayout());
                    ((GridBagLayout) buttonBar.getLayout()).columnWidths = new int[] {
                            0, 80};
                    ((GridBagLayout) buttonBar.getLayout()).columnWeights = new double[] {
                            1.0, 0.0};

                    //---- okButton ----
                    okButton.setText("OK");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 1;
                    gbc.gridy = 0;
                    gbc.fill = GridBagConstraints.BOTH;

                    okButton.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {

                            frame.hide();

                        }
                    });

                    buttonBar.add(okButton, gbc);
                }
                dialogPane.add(buttonBar, BorderLayout.SOUTH);
            }
            contentPane2.add(dialogPane, BorderLayout.CENTER);
            frame.setContentPane(contentPane2);
            frame.setSize(300, 150);
            frame.setResizable(false);
            frame.setTitle("Certificato");
            frame.pack();
            Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
            frame.setLocation((d.width - frame.getWidth()) / 2,
                              (d.height - frame
                               .getHeight()) / 2);

            frame.show();

            frame.setVisible(true);

            frame.addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent e) {
                    frame.hide();
                }
            });

        }

        /**
         * Return name and surname of the subject with underscore .<br><br>
         * Restituisce nome e cognome CON UNDERSCORE del subjct certificato in
         * oggetto
         *
         * @param DN certificato da cui estrarre nome e cognome
         * @return la stringa contenente il CN
         */
        private static String getNameFromDN(String DN) {

            int offset = DN.indexOf("CN=");
            //- 16 char di codice fiscale
            int cnStart = DN.indexOf("/", offset);
            int cnEnd = DN.indexOf("/", cnStart + 1);
            String CN;
            if (cnStart != -1 && cnEnd != -1) {
                CN = DN.substring(offset + 3, cnStart) + "_" +
                     DN.substring(cnStart + 1, cnEnd);
            } else {
                CN = DN.substring(offset + 3, DN.length());
            }
            return CN;
        }

        /**
         * Return name and surname of the subject with no underscore .<br><br>
         * Restituisce nome e cognome SENZA UNDERSCORE del subjct certificato in
         * oggetto
         *
         * @param DN certificato da cui estrarre nome e cognome
         * @return la stringa contenente il CN
         */
        private static String getFormattedNameFromDN(String DN) {

            int offset = DN.indexOf("CN=");
            //- 16 char di codice fiscale
            int end = DN.indexOf("/", offset);
            int end2 = DN.indexOf("/", end + 1);
            String CN;
            if ((end != -1) && (end2 != -1)) {
                CN = DN.substring(offset + 3, end) + " " +
                     DN.substring(end + 1, end2);
            } else {
                CN = DN.substring(offset + 3, DN.length());
            }
            return CN;
        }

        private void createNodes(DefaultMutableTreeNode top) {
            DefaultMutableTreeNode category = null;

            category = new DefaultMutableTreeNode("" + cert.getSubjectDN());
            top.add(category);

        }

        private JFrame frame;
        private VerifyTask task;
        private CertificationAuthorities CAroot;
        private CertValidity cv;
        private ReadCertsTask task2;
        private Hashtable risultati;
        private X509Certificate cert;
        private JPanel dialogPane;
        private JPanel contentPane;
        private JTabbedPane tabbedPane1;
        private JPanel panel1;
        private JTextPane textPane1;
        private JTextPane textPane3;
        private JButton button1;
        private JPanel panel2;
        private JScrollPane scrollPane1;
        private JTable table1;
        private JScrollPane scrollPane3;
        private JTextPane textPane2;
        private JPanel panel3;
        private JScrollPane scrollPane2;
        private JTree tree1;
        private JButton button2;
        private JButton button3;
        private JPanel panel4;
        private JPanel buttonBar;
        private JButton okButton;

        /**
         * Return CRL distribution points of the certificate as a String<br><br>
         * Restituisce i CRL DP del certificato specificato in formato Stringa
         *
         * @param certificate X509Certificate
         * @throws CertificateParsingException
         * @return URL []: URL array
         */
        public static String getCrlDistributionPoint(X509Certificate
                certificate) throws
                CertificateParsingException {
            try {
                //trova i DP (OID="2.5.29.31") nel certificato
                DERObject obj = getExtensionValue(certificate, "2.5.29.31");

                if (obj == null) {
                    //nessun DP presente
                    return "Non presenti";
                }
                ASN1Sequence distributionPoints = (ASN1Sequence) obj;

                String s = new String();

                String url;
                int p = 0;

                for (int i = 0; i < distributionPoints.size(); i++) {
                    ASN1Sequence distrPoint = (ASN1Sequence) distributionPoints.
                                              getObjectAt(i);

                    for (int j = 0; j < distrPoint.size(); j++) {
                        ASN1TaggedObject tagged = (ASN1TaggedObject) distrPoint.
                                                  getObjectAt(j);
                        //0 è il tag per il DP
                        if (tagged.getTagNo() == 0) {
                            url = getStringFromGeneralNames(tagged.getObject());
                            if (url != null) {
                                s = s + "[" + (p++) + "]" + url + "\n";

                            }
                        }
                    }

                }

                return s;
            } catch (Exception e) {
                e.printStackTrace();
                throw new CertificateParsingException(e.toString());
            }

        }

        /**
         * Returns DERObject extension if the certificate corresponding to given OID
         * <br><br>Restituisce un estensione DERObject dal certificato, corrispoendente
         * all'OID
         *
         * @param cert certificate
         * @param oid String
         * @throws IOException
         * @return l'estensione
         */
        private static DERObject getExtensionValue(X509Certificate cert,
                String oid) throws
                IOException {
            byte[] bytes = cert.getExtensionValue(oid);
            if (bytes == null) {
                return null;
            }
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(
                    bytes));
            ASN1OctetString otteti = (ASN1OctetString) aIn.readObject();
            aIn = new ASN1InputStream(new ByteArrayInputStream(otteti.getOctets()));
            return aIn.readObject();
        }

        private static String getStringFromGeneralNames(DERObject names) {
            ASN1Sequence namesSequence = ASN1Sequence.getInstance((
                    ASN1TaggedObject)
                    names, false);
            if (namesSequence.size() == 0) {
                return null;
            }
            DERTaggedObject taggedObject
                    = (DERTaggedObject) namesSequence.getObjectAt(0);
            return new String(ASN1OctetString.getInstance(taggedObject, false).
                              getOctets());

        }
        /**
         * Converts a byte array in its exadecimal representation.
         *
         * @param bytes byte[]
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
         * Save a byte array to a destination file.
         *
         * @param bytes byte[]
         * @param to_file File
         * @throws IOException
         */
        public static void save(byte[] bytes, File to_file) throws
                IOException {

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
                    return;
                }
            }
            if (q == JOptionPane.YES_OPTION) {

                FileOutputStream to = null; // Stream to write to destination

                ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
                to = new FileOutputStream(to_file); // Create output stream
                byte[] buffer = new byte[4096]; // A buffer to hold file contents
                int bytes_read; // How many bytes in buffer

                while ((bytes_read = bais.read(buffer)) != -1) { // Read bytes until EOF
                    to.write(buffer, 0, bytes_read); //   write bytes
                }
                to.close();
                abort("Il file è stato salvato.");

            }

        }

        /**
         * A convenience method<br><br>
         *
         * @param msg String
         */
        private static void abort(String msg) {
            JOptionPane.showMessageDialog(null,
                                          msg,
                                          "Attenzione",
                                          JOptionPane.INFORMATION_MESSAGE);

        }

    }
