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
import java.util.List;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.event.*;
import javax.swing.tree.*;

import iaik.pkcs.pkcs11.TokenException;
import it.treviso.provincia.freesigner.crl.*;
import it.trento.comune.j4sign.pcsc.*;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;

import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import javax.crypto.Cipher;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;

// ROB sostituito initCARoot() con initQualifiedCARoot();
/**
 * GUI for configuration.
 * 
 * @author Francesco Cendron
 */
public class FreesignerConfFrame extends JFrame {
    private java.lang.String cryptokiLib = null;

    private CertificationAuthorities CAroot;

    private Configuration conf;

    private X509CertRL CRL;

    private Vector CAInfos;

    private X509Certificate cert;

    private java.io.PrintStream log = null;

    private JFrame frame;

    private JPanel panel16;

    private JLabel label1;

    private JLabel label13;

    private JTabbedPane tabbedPane1;

    private JPanel panel9;

    private JScrollPane caScrollPane;

    private JTree caTree;

    private JTextPane textPane2;

    private JTextPane textPane3;

    private JLabel label4;

    private JTextField textField1;

    private JTextField textFieldCryptoki;

    private JButton button2;

    private JButton button1;

    private JButton button3;

    private JButton button4;

    private JButton button10;

    private JLabel label5;

    private JLabel label3;

    private JTextField textField2;

    // private JLabel label32;
    // private JPasswordField textField30;
    private JTextPane textPane30;

    private JButton button5;

    private JButton button6;

    private JPanel panel10;

    private JScrollPane tokenScrollPane;

    private JTree tokenTree;

    private JLabel label6;

    private JLabel label7;

    private JButton button8;

    private JLabel label8;

    private JButton buttonRicercaToken;

    private JTabbedPane tabbedPane8;

    private JPanel panel11;

    private JRadioButton radioButtonAutodetect;

    private JRadioButton radioButtonSetCryptoki;

    private JRadioButton radioButton1;

    private JRadioButton radioButton2;

    private JRadioButton radioButton3;

    private JPanel panel12;

    private JCheckBox checkBox1;

    private CheckboxGroup cbg;

    private JCheckBox checkBox3;

    private JLabel label9;

    private JTextField textField3;

    private JLabel label10;

    private JLabel label30;

    private JTextField textField5;

    // private JTextField textField4;
    // private JLabel label11;
    private JPanel panel13;

    private JCheckBox checkBox2;

    private JLabel label12;

    private JPanel panel14;

    private JLabel label14;

    private JTextField textField6;

    private JComboBox comboBox1;

    private JLabel label15;

    private JLabel label20;

    private JLabel label21;

    private JLabel label22;

    private JLabel label23;

    private JPanel panel17;

    private JPanel panel20;

    private JButton button7;

    private JCheckBox checkBox4;

    private JButton buttonCaricaCA;

    public FreesignerConfFrame() {
        conf = Configuration.getInstance();

        frame = new JFrame();
        // ROB
        // initCAroot();

        // initQualifiedCARoot();
        loadProperties();
        initComponents();

    }

    // ROB nuovo
    /**
     * Inizialize CA roots from CNIPA signed file
     * 
     */

    private void initQualifiedCARoot() {

        RootsVerifier rv = RootsVerifier.getInstance();
        try {
            CAroot = rv.getRoots(null);
        } catch (Exception ex) {
            log.println("Errore nell'inizializzazione delle CA da file CNIPA: "
                    + ex);
        }

        if (CAroot == null)
            JOptionPane
                    .showMessageDialog(
                            frame,
                            "Controllare che il pacchetto delle CA sia aggiornato, ed eventualmente scaricarlo dal sito del CNIPA.",
                            "ATTENZIONE! Inizializzazione delle CA fallita!",
                            JOptionPane.ERROR_MESSAGE);
        else
            initCRL();
    }



    /**
     * Inizialize CRL with CAs presents in root
     * 
     */

    private void initCRL() {
        CRL = new X509CertRL(CAroot);
    }

    /**
     * Inizialize frame components
     * 
     */
    private void initComponents() {

        panel16 = new JPanel();
        label1 = new JLabel();
        label13 = new JLabel();
        tabbedPane1 = new JTabbedPane();
        panel9 = new JPanel();
        caScrollPane = new JScrollPane();
        caTree = new JTree();
        textPane2 = new JTextPane();
        textPane3 = new JTextPane();
        label4 = new JLabel();
        textField1 = new JTextField();
        textFieldCryptoki = new JTextField();
        button2 = new JButton();
        button1 = new JButton();
        button3 = new JButton();
        button4 = new JButton();
        button10 = new JButton();

        label5 = new JLabel();
        label3 = new JLabel();
        textField2 = new JTextField();
        button5 = new JButton();
        button6 = new JButton();
        panel10 = new JPanel();
        tokenScrollPane = new JScrollPane();
        tokenTree = new JTree();
        label6 = new JLabel();
        label7 = new JLabel();
        button8 = new JButton();
        label8 = new JLabel();
        label20 = new JLabel();
        label21 = new JLabel();
        label22 = new JLabel();
        label23 = new JLabel();

        buttonRicercaToken = new JButton();
        tabbedPane8 = new JTabbedPane();
        panel11 = new JPanel();
        panel20 = new JPanel();
        radioButtonAutodetect = new JRadioButton();
        radioButtonSetCryptoki = new JRadioButton();
        radioButton1 = new JRadioButton();
        radioButton2 = new JRadioButton();
        radioButton3 = new JRadioButton();
        panel12 = new JPanel();
        checkBox1 = new JCheckBox();
        cbg = new CheckboxGroup();
        checkBox3 = new JCheckBox();
        label9 = new JLabel();
        label30 = new JLabel();
        textField3 = new JTextField();
        label10 = new JLabel();
        textField5 = new JTextField();
        // textField4 = new JTextField();
        textPane30 = new JTextPane();
        // label11 = new JLabel();
        panel13 = new JPanel();
        checkBox2 = new JCheckBox();
        label12 = new JLabel();
        panel14 = new JPanel();
        label14 = new JLabel();
        textField6 = new JTextField();
        comboBox1 = new JComboBox();
        label15 = new JLabel();
        panel17 = new JPanel();
        button7 = new JButton();
        // label32 = new JLabel();
        // textField30 = new JPasswordField();
        checkBox4 = new JCheckBox();

        buttonCaricaCA = new JButton();

        GridBagConstraints gbc;

        // ======== this ========
        Container contentPane = getContentPane();
        contentPane.setLayout(new GridBagLayout());
        ((GridBagLayout) contentPane.getLayout()).columnWidths = new int[] { 0,
                0 };
        ((GridBagLayout) contentPane.getLayout()).rowHeights = new int[] { 275,
                0 };
        ((GridBagLayout) contentPane.getLayout()).columnWeights = new double[] {
                1.0, 1.0E-4 };
        ((GridBagLayout) contentPane.getLayout()).rowWeights = new double[] {
                1.0, 1.0E-4 };

        // ======== panel16 ========
        {

            panel16.setLayout(new GridBagLayout());
            ((GridBagLayout) panel16.getLayout()).columnWidths = new int[] { 0,
                    0, 0, 0 };
            ((GridBagLayout) panel16.getLayout()).rowHeights = new int[] { 0,
                    0, 0, 0, 0 };
            ((GridBagLayout) panel16.getLayout()).columnWeights = new double[] {
                    1.0, 1.0E-4 };
            ((GridBagLayout) panel16.getLayout()).rowWeights = new double[] {
                    0.0, 1.0, 1.0, 1.0, 1.0E-4 };

            // ---- label1 ----
            label1.setFont(new Font("MS Sans Serif", Font.BOLD, 11));
            label1.setText("Configurazione");
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.insets.bottom = 5;
            panel16.add(label1, gbc);

            // ---- label13 ----
            label13
                    .setText("Seleziona una scheda per impostare le tue preferenze.");
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.insets.bottom = 5;
            panel16.add(label13, gbc);

            // ======== tabbedPane1 ========
            {
                tabbedPane1.setBackground(null);

                // ======== panel9 ========
                {
                    panel9.setLayout(new GridBagLayout());
                    ((GridBagLayout) panel9.getLayout()).columnWidths = new int[] {
                            55, 100, 130, 30, 30, 70, 0, 0 };
                    ((GridBagLayout) panel9.getLayout()).rowHeights = new int[] {
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                    ((GridBagLayout) panel9.getLayout()).columnWeights = new double[] {
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };
                    ((GridBagLayout) panel9.getLayout()).rowWeights = new double[] {
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0E-4 };

                    // ======== caScrollPane ========
                    {
                        caScrollPane.setAutoscrolls(false);

                        DefaultMutableTreeNode top = new DefaultMutableTreeNode(
                                "Premere 'Carica CA'");

                        caTree = new JTree(top);
                        caTree.setVisibleRowCount(10);

                        caScrollPane
                                .setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                        caScrollPane
                                .setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

                        caScrollPane.setViewportView(caTree);
                        caScrollPane.setPreferredSize(new Dimension(250, 200));
                    }
                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 0;
                    gbc.gridwidth = 2;
                    gbc.gridheight = 6;
                    gbc.anchor = GridBagConstraints.NORTHWEST;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.fill = GridBagConstraints.VERTICAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(caScrollPane, gbc);

                    // ---- buttonCaricaCA ----
                    buttonCaricaCA.setText("Carica CA");
                    buttonCaricaCA.setPreferredSize(new Dimension(150, 25));
                    buttonCaricaCA.addActionListener(new ActionListener() {

                        public void actionPerformed(ActionEvent e) {

                            initCATree();

                            DefaultTreeModel model = (DefaultTreeModel) caTree
                                    .getModel();
                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) model
                                    .getRoot();

                            tokenDetailsPanelRefresh(node);

                            caScrollPane.setViewportView(caTree);
                            caScrollPane.setPreferredSize(new Dimension(250, 200));

                        }
                    });

                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 0;
                    gbc.gridwidth = 2;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(buttonCaricaCA, gbc);

                    // ---- textPane3 ----
                    textPane3.setFont(new Font("", Font.PLAIN, 11));
                    textPane3.setText("Nome CA:");
                    textPane3.setBackground(null);
                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 1;
                    gbc.gridwidth = 4;
                    gbc.anchor = GridBagConstraints.NORTH;
                    gbc.fill = GridBagConstraints.HORIZONTAL;

                    gbc.insets.right = 5;
                    textPane3.setEditable(false);
                    panel9.add(textPane3, gbc);

                    // ---- textPane2 ----
                    textPane2.setFont(new Font("", Font.BOLD, 11));
                    textPane2.setText("");
                    textPane2.setEditable(false);
                    textPane2.setBackground(null);
                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 2;
                    gbc.gridwidth = 4;
                    gbc.anchor = GridBagConstraints.NORTH;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(textPane2, gbc);

                    // ---- label4 ----
                    label4
                            .setText("\nURL da cui effettuare il download della CRL:");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 3;
                    gbc.gridwidth = 3;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(label4, gbc);
                    textField1.setText("");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 3;
                    gbc.gridwidth = 4;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(textField1, gbc);

                    // ---- button2 ----
                    button2.setText("Download CRL");
                    button2.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {

                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) caTree
                                    .getLastSelectedPathComponent();

                            if (node == null) {
                                JOptionPane.showMessageDialog(frame,
                                        "Selezionare un certificato CA.",
                                        "Attenzione",
                                        JOptionPane.WARNING_MESSAGE);

                                return;
                            }
                            /* React to the node selection. */
                            Object nodeInfo = node.getUserObject();
                            if (node.isLeaf()) {
                                CertInfo c = (CertInfo) nodeInfo;
                                CRL.setUseproxy(conf.isUsingProxy(), conf
                                        .getUserName(), conf.getPassWord(),
                                        conf.getHost(), conf.getPort());
                                // forza il download della CRL
                                try {
                                    CRL.update(c.getCertificate(), new Date(),
                                            true);
                                } catch (CertificateException ex1) {
                                } catch (GeneralSecurityException ex1) {
                                }

                                if (CRL.getCRLerror().length() > 0) {
                                    // c'è stato un errore
                                    JOptionPane.showMessageDialog(frame,
                                            "C'è stato un errore nella verifica CRL.\n"
                                                    + CRL.getCRLerror(),
                                            "Errore verifica CRL",
                                            JOptionPane.ERROR_MESSAGE);
                                    // resetta gli errori per poter
                                    // scarirare le altre crl
                                    CRL.resetCRLerror();

                                } else {
                                    JOptionPane.showMessageDialog(frame,
                                            "CRL scaricata.", "Download CRL",
                                            JOptionPane.INFORMATION_MESSAGE);

                                }

                            } else {
                                JOptionPane.showMessageDialog(frame,
                                        "Selezionare un certificato CA.",
                                        "Attenzione",
                                        JOptionPane.WARNING_MESSAGE);

                            }

                        }
                    });

                    gbc = new GridBagConstraints();
                    gbc.gridx = 4;
                    gbc.gridy = 4;
                    gbc.gridwidth = 2;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(button2, gbc);

                    // ---- button1 ----
                    button1.setText("Salva modifiche");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 2;
                    gbc.gridy = 5;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    // panel9.add(button1, gbc);

                    // ---- button3 ----
                    // button3.setText("Rimuovi Certificato");
                    // button3.addActionListener(new ActionListener() {
                    // public void actionPerformed(ActionEvent e) {
                    //
                    // DefaultMutableTreeNode node = (
                    // DefaultMutableTreeNode)
                    // caTree.
                    // getLastSelectedPathComponent();
                    //
                    // if (node == null) {
                    // return;
                    // }
                    // /* React to the node selection. */
                    // Object nodeInfo = node.getUserObject();
                    // if (node.isLeaf()) {
                    // CertInfo c = (CertInfo) nodeInfo;
                    //
                    // CAroot.removeCertificateAuthority(c.
                    // getCertificate().
                    // getSubjectX500Principal());
                    // DefaultTreeModel model = (DefaultTreeModel)
                    // caTree.getModel();
                    // model.removeNodeFromParent(node);
                    // } else {
                    // //siamo in una categoria
                    // }
                    //
                    // }
                    // });
                    //
                    // gbc = new GridBagConstraints();
                    // gbc.gridx = 2;
                    // gbc.gridy = 5;
                    // gbc.gridwidth = 2;
                    // gbc.fill = GridBagConstraints.HORIZONTAL;
                    // gbc.insets.bottom = 5;
                    // gbc.insets.right = 5;
                    // panel9.add(button3, gbc);

                    // ---- button4 ----
                    button4.setText("Dettagli >>");
                    button4.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {

                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) caTree
                                    .getLastSelectedPathComponent();

                            if (node == null) {
                                JOptionPane.showMessageDialog(frame,
                                        "Selezionare un certificato CA.",
                                        "Attenzione",
                                        JOptionPane.WARNING_MESSAGE);

                                return;
                            }
                            /* React to the node selection. */
                            Object nodeInfo = node.getUserObject();
                            if (node.isLeaf()) {
                                CertInfo c = (CertInfo) nodeInfo;

                                FreesignerCertFrame nuovo = new FreesignerCertFrame(
                                        c.getCertificate(), CAroot);

                            } else {
                                JOptionPane.showMessageDialog(frame,
                                        "Selezionare un certificato CA.",
                                        "Attenzione",
                                        JOptionPane.WARNING_MESSAGE);

                                // siamo in una categoria
                            }

                        }
                    });

                    gbc = new GridBagConstraints();
                    gbc.gridx = 4;
                    gbc.gridy = 5;
                    gbc.gridwidth = 2;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel9.add(button4, gbc);

                    /*
                     * ROB: Temporaneamente commentato // ---- label5 ----
                     * label5.setFont(new Font("MS Sans Serif", Font.BOLD, 11));
                     * label5.setText("Importazione Certificato CA"); gbc = new
                     * GridBagConstraints(); gbc.gridx = 0; gbc.gridy = 7;
                     * gbc.gridwidth = 3; gbc.fill = GridBagConstraints.BOTH;
                     * gbc.insets.bottom = 5; gbc.insets.right = 5;
                     * panel9.add(label5, gbc); // ---- label3 ----
                     * label3.setText("Nome file:"); gbc = new
                     * GridBagConstraints(); gbc.gridx = 0; gbc.gridy = 8;
                     * gbc.anchor = GridBagConstraints.EAST; gbc.fill =
                     * GridBagConstraints.VERTICAL; gbc.insets.right = 5;
                     * gbc.insets.bottom = 5; panel9.add(label3, gbc);
                     * 
                     * textField2.setEnabled(false); textField2.setText(""); gbc =
                     * new GridBagConstraints(); gbc.gridx = 1; gbc.gridy = 8;
                     * gbc.gridwidth = 2; gbc.fill = GridBagConstraints.BOTH;
                     * gbc.insets.right = 5; gbc.insets.bottom = 5;
                     * panel9.add(textField2, gbc); // ---- button5 ----
                     * button5.setEnabled(false); button5.setText("Apri");
                     * 
                     * button5.addActionListener(new ActionListener() { public
                     * void actionPerformed(ActionEvent e) { final JFileChooser
                     * fc = new JFileChooser(); int returnVal =
                     * fc.showOpenDialog(null);
                     * 
                     * if (returnVal == JFileChooser.APPROVE_OPTION) { File file =
                     * fc.getSelectedFile();
                     * textField2.setText(file.getAbsolutePath()); // this is
                     * where a real application would open // the file. //
                     * log.append("Opening: " + file.getName() + // ".\n"); }
                     * else { // log.append("Open command cancelled by //
                     * user.\n"); } } });
                     * 
                     * gbc = new GridBagConstraints(); gbc.gridx = 3; gbc.gridy =
                     * 8; gbc.gridwidth = 2; gbc.anchor =
                     * GridBagConstraints.WEST; gbc.insets.right = 5;
                     * gbc.insets.bottom = 5; panel9.add(button5, gbc); // ----
                     * button6 ---- button6.setEnabled(false);
                     * button6.setText("Importa CA");
                     * 
                     * 
                     * button6.addActionListener(new ActionListener() { public
                     * void actionPerformed(ActionEvent e) { if
                     * (textField2.getText().length() > 0) { File inputFile =
                     * new File(textField2.getText()); try { X509Certificate
                     * caCert = readCertFromFile(inputFile);
                     * CAroot.addCertificateAuthority(caCert);
                     * DefaultMutableTreeNode top = ((DefaultMutableTreeNode)
                     * caTree .getModel().getRoot());
                     * 
                     * DefaultMutableTreeNode child = new
                     * DefaultMutableTreeNode( new CertInfo(caCert));
                     * 
                     * DefaultMutableTreeNode father = new
                     * DefaultMutableTreeNode();
                     * 
                     * if (CAInfos.contains(caCert .getIssuerX500Principal()
                     * .toString())) { father = (DefaultMutableTreeNode) top
                     * .getChildAt(1); System.out.println(father.toString()); }
                     * else { father = (DefaultMutableTreeNode) top
                     * .getChildAt(0); } DefaultTreeModel model =
                     * (DefaultTreeModel) caTree .getModel();
                     * 
                     * model.insertNodeInto(child, father, father
                     * .getChildCount());
                     * 
                     * JOptionPane.showMessageDialog(frame, "Certificato di CA
                     * aggiunto!", "Avviso", JOptionPane.INFORMATION_MESSAGE); }
                     * catch (GeneralSecurityException ex) {
                     * JOptionPane.showMessageDialog(frame, "Errore!" + ex,
                     * "Attenzione", JOptionPane.ERROR_MESSAGE); } } else {
                     * JOptionPane .showMessageDialog( frame, "Non è stato
                     * scelto \nnessun certificato da importare!", "Attenzione",
                     * JOptionPane.WARNING_MESSAGE); } } });
                     * 
                     * gbc = new GridBagConstraints(); gbc.gridx = 5; gbc.gridy =
                     * 8; gbc.insets.right = 5; gbc.insets.bottom = 5;
                     * panel9.add(button6, gbc);
                     */

                }

                tabbedPane1.addTab("Elenco Certificati", panel9);

                // ======== panel10 - Gestione Token ========
                {
                    panel10.setLayout(new GridBagLayout());
                    ((GridBagLayout) panel10.getLayout()).columnWidths = new int[] {
                            155, 55, 105, 50, 0 };
                    ((GridBagLayout) panel10.getLayout()).rowHeights = new int[] {
                            0, 0, 0, 0, 0, 0, 0, 0 };
                    ((GridBagLayout) panel10.getLayout()).columnWeights = new double[] {
                            0.0, 0.0, 0.0, 1.0, 1.0E-4 };
                    ((GridBagLayout) panel10.getLayout()).rowWeights = new double[] {
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0E-4 };

                    // ======== tokenScrollPane ========
                    {

                        // ---- tree2 - token e certificati----

                        DefaultMutableTreeNode top = new DefaultMutableTreeNode(
                                "Nessun token rilevato");
                        tokenTree = new JTree(top);
                        // initTokenTree();
                        tokenTree.setVisibleRowCount(10);

                        // ---- button10 ----
                        button10.setText("Apri");
                        button10.setPreferredSize(new Dimension(100, 25));
                        button10.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {

                                DefaultMutableTreeNode node = (DefaultMutableTreeNode) tokenTree
                                        .getLastSelectedPathComponent();

                                if (node == null) {
                                    return;
                                }
                                /* React to the node selection. */
                                Object nodeInfo = node.getUserObject();
                                if (node.isLeaf()) {
                                    CertInfo c = (CertInfo) nodeInfo;
                                    initQualifiedCARoot();
                                    FreesignerCertFrame nuovo = new FreesignerCertFrame(
                                            c.getCertificate(), CAroot);

                                } else {
                                    // siamo in una categoria
                                }

                            }

                        });

                        tokenScrollPane.setViewportView(tokenTree);
                        tokenScrollPane.setPreferredSize(new Dimension(250, 200));
                    }
                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 0;
                    gbc.gridheight = 4;
                    gbc.gridwidth = 2;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel10.add(tokenScrollPane, gbc);
                    // ---- button9 ----
                    buttonRicercaToken.setText("Ricerca Token");
                    buttonRicercaToken.setPreferredSize(new Dimension(150, 25));
                    buttonRicercaToken.addActionListener(new ActionListener() {

                        public void actionPerformed(ActionEvent e) {

                            initTokenTree();

                            DefaultTreeModel model = (DefaultTreeModel) tokenTree
                                    .getModel();
                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) model
                                    .getRoot();

                            tokenDetailsPanelRefresh(node);

                            tokenScrollPane.setViewportView(tokenTree);
                            tokenScrollPane
                                    .setPreferredSize(new Dimension(250, 200));

                        }
                    });

                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 5;
                    gbc.gridwidth = 2;
                    gbc.anchor = GridBagConstraints.CENTER;
                    gbc.insets.right = 5;
                    gbc.insets.top = 5;
                    panel10.add(buttonRicercaToken, gbc);

                    // ======== panel20 ========
                    {
                        panel20.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel20.getLayout()).columnWidths = new int[] {
                                0, 70, 0, 0, 0 };
                        ((GridBagLayout) panel20.getLayout()).rowHeights = new int[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0 };
                        ((GridBagLayout) panel20.getLayout()).columnWeights = new double[] {
                                0.0, 0.0, 0.0, 0.0, 1.0E-4 };
                        ((GridBagLayout) panel20.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0E-4 };

                        // ---- label6 ----
                        label6
                                .setText("Premi ''Ricerca token'' per \nrilevare i token crittografici");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 1;
                        gbc.gridy = 0;
                        gbc.gridwidth = 2;
                        gbc.anchor = GridBagConstraints.NORTHWEST;
                        gbc.insets.bottom = 5;
                        panel20.add(label6, gbc);

                        // ---- radioButton autorilevamento ----
                        radioButtonAutodetect.setText("Autorilevamento");

                        gbc = new GridBagConstraints();
                        gbc.gridx = 1;
                        gbc.gridy = 1;
                        gbc.gridwidth = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        panel20.add(radioButtonAutodetect, gbc);

                        // ---- radioButton imposta Cryptoki ----
                        radioButtonSetCryptoki
                                .setText("Imposta libreria PKCS11");

                        gbc = new GridBagConstraints();
                        gbc.gridx = 2;
                        gbc.gridy = 1;
                        gbc.gridwidth = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel20.add(radioButtonSetCryptoki, gbc);
                        
                        if ( "".equals(conf.getLib().trim())) {
                            textFieldCryptoki.setText("");
                            textFieldCryptoki.setEnabled(false);
                            radioButtonAutodetect.setSelected(true);
                            radioButtonSetCryptoki.setSelected(false);
                        } else {
                            textFieldCryptoki.setText(conf.getLib());
                            textFieldCryptoki.setEnabled(true);
                            radioButtonAutodetect.setSelected(false);
                            radioButtonSetCryptoki.setSelected(true);
                        }

                        gbc = new GridBagConstraints();
                        gbc.gridx = 2;
                        gbc.gridy = 2;
                        gbc.gridwidth = GridBagConstraints.REMAINDER;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel20.add(textFieldCryptoki, gbc);

                        ButtonGroup tokenGroup = new ButtonGroup();
                        tokenGroup.add(radioButtonAutodetect);
                        tokenGroup.add(radioButtonSetCryptoki);

                        radioButtonAutodetect
                                .addActionListener(new ActionListener() {
                                    public void actionPerformed(ActionEvent e) {
                                        textFieldCryptoki.setText("");
                                        textFieldCryptoki.setEnabled(false);
                                    }
                                });
                        radioButtonSetCryptoki
                                .addActionListener(new ActionListener() {
                                    public void actionPerformed(ActionEvent e) {
                                        textFieldCryptoki.setEnabled(true);
                                    }
                                });

                        // ---- label7 ----
                        label7.setText("");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 1;
                        gbc.gridy = 4;
                        gbc.gridwidth = 1;
                        gbc.anchor = GridBagConstraints.WEST;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel20.add(label7, gbc);

                        // ---- label8 ----

                        label8.setText("");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 1;
                        gbc.gridy = 5;
                        gbc.gridwidth = 2;
                        gbc.anchor = GridBagConstraints.WEST;
                        gbc.insets.bottom = 5;
                        panel20.add(label8, gbc);
                    }
                    panel10.add(panel20);

                }
                tabbedPane1.addTab("Gestione Token", panel10);

                // ======== tabbedPane8 ========
                {

                    // ======== panel11 ========
                    {
                        panel11.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel11.getLayout()).columnWidths = new int[] {
                                0, 0, 0, 0 };
                        ((GridBagLayout) panel11.getLayout()).rowHeights = new int[] {
                                0, 0, 0, 0 };
                        ((GridBagLayout) panel11.getLayout()).columnWeights = new double[] {
                                0.0, 0.0, 0.0, 1.0E-4 };
                        ((GridBagLayout) panel11.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 0.0, 1.0E-4 };

                        // ---- radioButton1 ----
                        radioButton1.setText("BASE 64");
                        radioButton1.setSelected("Base64".equals(conf
                                .getPKCS7format()));
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.gridwidth = 3;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        panel11.add(radioButton1, gbc);

                        // ---- radioButton2 ----
                        radioButton2.setText("Binaria");
                        radioButton2.setSelected("DER".equals(conf
                                .getPKCS7format()));
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel11.add(radioButton2, gbc);

                        // ---- radioButton3 ----
                        radioButton3.setSelected("ask".equals(conf
                                .getPKCS7format()));

                        radioButton3.setText("Seleziona ogni volta");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 2;
                        gbc.gridwidth = 3;
                        gbc.fill = GridBagConstraints.BOTH;
                        panel11.add(radioButton3, gbc);

                        ButtonGroup group = new ButtonGroup();
                        group.add(radioButton1);
                        group.add(radioButton2);
                        group.add(radioButton3);

                        radioButton1.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                conf.setPKCS7format("Base64");
                            }
                        });
                        radioButton2.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                conf.setPKCS7format("DER");
                            }
                        });
                        radioButton3.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                conf.setPKCS7format("ask");
                            }
                        });

                    }
                    tabbedPane8.addTab("Formato Busta", panel11);

                    // ======== panel12 ========
                    {
                        panel12.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel12.getLayout()).columnWidths = new int[] {
                                0, 130, 0, 130, 0, 0 };
                        ((GridBagLayout) panel12.getLayout()).rowHeights = new int[] {
                                0, 0, 0, 0 };
                        ((GridBagLayout) panel12.getLayout()).columnWeights = new double[] {
                                0.0, 0.0, 0.0, 0.0, 0.0, 1.0 };
                        ((GridBagLayout) panel12.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 0.0, 1.0E-4 };

                        // ---- utilizzo proxy ----
                        checkBox1.setText("Utilizza Server Proxy");
                        checkBox1.setSelected(conf.isUsingProxy());
                        checkBox1.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                conf.setUsingProxy(checkBox1.isSelected());
                                label30.setEnabled(checkBox1.isSelected());
                                textField3.setEnabled(checkBox1.isSelected());
                                textField5.setEnabled(checkBox1.isSelected());
                                label10.setEnabled(checkBox1.isSelected());

                                // label11.setEnabled(checkBox1.isSelected());
                                // textField4.setEnabled(checkBox1.isSelected());
                                // label32.setEnabled(checkBox1.isSelected());
                                // textField30.setEnabled(checkBox1.isSelected())
                                // ;
                                checkBox4.setEnabled(checkBox1.isSelected());

                            }
                        });
                        label30.setEnabled(checkBox1.isSelected());
                        textField3.setEnabled(checkBox1.isSelected());
                        textField5.setEnabled(checkBox1.isSelected());
                        label10.setEnabled(checkBox1.isSelected());

                        // label11.setEnabled(checkBox1.isSelected());
                        // textField4.setEnabled(checkBox1.isSelected());
                        // label32.setEnabled(checkBox1.isSelected());
                        // textField30.setEnabled(checkBox1.isSelected());
                        checkBox4.setEnabled(checkBox1.isSelected());

                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.gridwidth = 2;
                        gbc.fill = GridBagConstraints.BOTH;

                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel12.add(checkBox1, gbc);

                        // ---- label9 ----
                        label30.setText("Indirizzo server");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel12.add(label30, gbc);
                        textField3.setText(conf.getHost());

                        gbc = new GridBagConstraints();
                        gbc.gridx = 1;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.HORIZONTAL;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel12.add(textField3, gbc);

                        // ---- label10 ----
                        label10.setText("Porta");
                        gbc = new GridBagConstraints();
                        gbc.gridx = 2;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel12.add(label10, gbc);
                        textField5.setText(conf.getPort());
                        gbc = new GridBagConstraints();
                        gbc.gridx = 3;
                        gbc.gridy = 1;
                        gbc.fill = GridBagConstraints.HORIZONTAL;
                        gbc.insets.bottom = 5;
                        panel12.add(textField5, gbc);

                        // ---- utilizzo proxy authentication----
                        checkBox4
                                .setText("Il Proxy richiede utente e password");
                        checkBox4.setSelected(conf.isProxyUsingUserPassword());

                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 2;
                        gbc.gridwidth = 2;
                        gbc.fill = GridBagConstraints.BOTH;

                        gbc.insets.bottom = 5;
                        gbc.insets.right = 5;
                        panel12.add(checkBox4, gbc);

                        // ---- label11 ----
                        /*
                         * label11.setText("Username"); gbc = new
                         * GridBagConstraints(); gbc.gridx = 1; gbc.gridy = 2;
                         * gbc.fill = GridBagConstraints.BOTH; gbc.insets.right =
                         * 5; //panel12.add(label11, gbc);
                         * textField4.setText(conf.getUserName());
                         * 
                         * gbc = new GridBagConstraints(); gbc.gridx = 2;
                         * gbc.gridy = 2; gbc.fill =
                         * GridBagConstraints.HORIZONTAL; gbc.insets.right = 5;
                         * //panel12.add(textField4, gbc);
                         * 
                         * //---- label32 ---- label32.setText("Password"); gbc =
                         * new GridBagConstraints(); gbc.gridx = 3; gbc.gridy =
                         * 2; gbc.fill = GridBagConstraints.VERTICAL;
                         * gbc.insets.bottom = 5; gbc.insets.right = 5;
                         * //panel12.add(label32, gbc);
                         * 
                         * //gi� decriptata
                         * textField30.setText(conf.getPassWord());
                         * textField30.setFont(new Font("", Font.PLAIN, 11));
                         * gbc = new GridBagConstraints(); gbc.gridx = 4;
                         * gbc.gridy = 2; gbc.fill =
                         * GridBagConstraints.HORIZONTAL; gbc.insets.bottom = 5;
                         * //panel12.add(textField30, gbc);
                         */
                    }
                    tabbedPane8.addTab("Connessione", panel12);

                    // ======== panel13 ========
                    {
                        panel13.setLayout(new GridBagLayout());
                        ((GridBagLayout) panel13.getLayout()).columnWidths = new int[] {
                                0, 0, 0 };
                        ((GridBagLayout) panel13.getLayout()).rowHeights = new int[] {
                                0, 0, 0, 0 };
                        ((GridBagLayout) panel13.getLayout()).columnWeights = new double[] {
                                0.0, 0.0, 1.0E-4 };
                        ((GridBagLayout) panel13.getLayout()).rowWeights = new double[] {
                                0.0, 0.0, 0.0, 1.0E-4 };

                        // ---- checkBox2 ----
                        checkBox2.setSelected(conf.getCRLupdate());
                        checkBox2.setText("Verifica CRL sempre");
                        checkBox2.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                conf.setCRLupdate(checkBox2.isSelected());

                            }
                        });

                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 2;
                        gbc.gridwidth = 2;
                        gbc.fill = GridBagConstraints.BOTH;
                        panel13.add(checkBox2, gbc);

                        // ---- label12 ----
                        textPane30
                                .setText("Segnando questa casella, la verifica della CRL avverrà sempre.\nLa verifica della validità di un certificato non è completa se non si verifica la revoca del certificato.\nNon segnare questa casella, è utile quando non si è connessi in rete.  ");
                        textPane30.setEditable(false);
                        textPane30.setBackground(null);
                        gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.gridwidth = 2;
                        gbc.fill = GridBagConstraints.BOTH;
                        gbc.insets.bottom = 5;
                        panel13.add(textPane30, gbc);
                    }
                    tabbedPane8.addTab("Verifica CRL", panel13);
                }
                tabbedPane1.addTab("Preferenze", tabbedPane8);

                // ======== panel14 ========
                {
                    panel14.setLayout(new GridBagLayout());
                    ((GridBagLayout) panel14.getLayout()).columnWidths = new int[] {
                            0, 0, 0, 0 };
                    ((GridBagLayout) panel14.getLayout()).rowHeights = new int[] {
                            0, 0, 0, 0 };
                    ((GridBagLayout) panel14.getLayout()).columnWeights = new double[] {
                            0.0, 1.0, 1.0, 1.0E-4 };
                    ((GridBagLayout) panel14.getLayout()).rowWeights = new double[] {
                            0.0, 0.0, 0.0, 1.0E-4 };

                    // ---- label14 ----
                    label14.setText("Indirizzo presso cui scaricare:");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 0;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel14.add(label14, gbc);
                    gbc = new GridBagConstraints();
                    gbc.gridx = 1;
                    gbc.gridy = 0;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.bottom = 5;
                    gbc.insets.right = 5;
                    panel14.add(textField6, gbc);
                    gbc = new GridBagConstraints();
                    gbc.gridx = 1;

                    gbc.gridy = 2;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.right = 5;
                    panel14.add(comboBox1, gbc);

                    // ---- label15 ----
                    label15.setText("Controlla se aggiornamenti presenti");
                    gbc = new GridBagConstraints();
                    gbc.gridx = 0;
                    gbc.gridy = 2;
                    gbc.fill = GridBagConstraints.BOTH;
                    gbc.insets.right = 5;
                    panel14.add(label15, gbc);
                }
                // tabbedPane1.addTab("Opzioni di aggiornamento", panel14);
            }
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 2;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.insets.bottom = 5;
            panel16.add(tabbedPane1, gbc);

            // ======== panel17 ========
            {
                panel17.setLayout(new GridBagLayout());
                ((GridBagLayout) panel17.getLayout()).columnWidths = new int[] {
                        0, 0, 0, 0 };
                ((GridBagLayout) panel17.getLayout()).rowHeights = new int[] {
                        0, 0 };
                ((GridBagLayout) panel17.getLayout()).columnWeights = new double[] {
                        1.0, 1.0, 1.0, 1.0E-4 };
                ((GridBagLayout) panel17.getLayout()).rowWeights = new double[] {
                        0.0, 1.0E-4 };

                // ---- button7 ----
                button7.setText("Salva e chiudi");
                button7.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        conf.setHost(textField3.getText());
                        conf.setPort(textField5.getText());
                        conf.setProxyUsingUserPassword(checkBox4.isSelected());
                        if (radioButtonAutodetect.isSelected())
                            conf.setLib("");
                        else
                            conf.setLib(textFieldCryptoki.getText().trim());

                        /*
                         * conf.setUserName(textField4.getText());
                         * 
                         * 
                         * PasswordCrypting k = new PasswordCrypting(); String s =
                         * k.encrypt(textField30.getPassword());
                         * 
                         * conf.setPassWord(s);
                         */

                        frame.hide();
                        // System.out.println("Saving zip with CA...");

                        try {
                            // CAroot.save();
                            conf.save();
                        } catch (Exception ex) {
                            System.out.println("Error saving... : " + ex);
                        }

                    }
                });

                gbc = new GridBagConstraints();
                gbc.gridx = 2;
                gbc.gridy = 0;
                gbc.insets.bottom = 5;
                panel17.add(button7, gbc);
            }
            gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.fill = GridBagConstraints.BOTH;
            panel16.add(panel17, gbc);
        }
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.BOTH;
        contentPane.add(panel16, gbc);

        frame.setContentPane(contentPane);
        frame.setTitle("Configurazione");
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
                frame.hide();
            }
        });

    }

    /**
     * Initialize token tree (every token has its certificates as leaves)<br>
     * <br>
     * Inizializza l'albero dei token presenti (ogni token ha come foglie i suoi
     * certificati)
     * 
     */

    private void initTokenTree() {
        DefaultMutableTreeNode top = new DefaultMutableTreeNode(
                "Token crittografici");

        tokenTree = new JTree(top);

        String cryptoki = null;

        if (!radioButtonAutodetect.isSelected()) {
            cryptoki = textFieldCryptoki.getText().trim();
            if ("".equals(cryptoki))
                JOptionPane.showMessageDialog(this,
                        "Inserire il nome della libreria.", "Attenzione",
                        JOptionPane.WARNING_MESSAGE);

        }

        //If autodetect (cryptoki == null) or cryptoki name is provideded
        if (!"".equals(cryptoki))
            try {

                ReadCertTaskFrame rctf = new ReadCertTaskFrame(this, cryptoki,
                        false);
                // ReadCertTaskFrame rctf = new ReadCertTaskFrame(this,
                // slotInfos,
                // false);

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CMSException e) {
                e.printStackTrace();
            }
    }

    public JTree gettokenTree() {
        return tokenTree;
    }

    private void initCATree() {

        initQualifiedCARoot();

        DefaultMutableTreeNode top = new DefaultMutableTreeNode("Certificati");
        /*
         * DefaultMutableTreeNode CAd = new DefaultMutableTreeNode( "CA firma
         * digitale"); DefaultMutableTreeNode CAe = new DefaultMutableTreeNode(
         * "CA firma elettronica");
         */
        DefaultMutableTreeNode CAd = new DefaultMutableTreeNode(
                "CA firma digitale (qualificate CNIPA)");

        // top.add(CAe);
        top.add(CAd);

        caTree = new JTree(top);

        createCANodes(top);

        expandAll(caTree, true);
        caTree.setEditable(true);
        caTree.getSelectionModel().setSelectionMode(
                TreeSelectionModel.SINGLE_TREE_SELECTION);

        // Listen for when the selection changes.
        caTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) caTree
                        .getLastSelectedPathComponent();

                if (node == null) {
                    return;
                }
                // React to the node selection.
                Object nodeInfo = node.getUserObject();
                if (node.isLeaf()) {
                    CertInfo c = (CertInfo) nodeInfo;
                    displayCert(c);

                } else {
                    // siamo in una categoria
                }

            }
        });

        // DefaultMutableTreeNode top =
        // new DefaultMutableTreeNode(
        // "Token crittografici");
        //
        // tokenTree = createTreeAndTokenNodes(top);
        // expandAll(tokenTree, true);
        // tokenTree.setEditable(true);
        // tokenTree.getSelectionModel().setSelectionMode
        // (TreeSelectionModel.
        // SINGLE_TREE_SELECTION);
        // if (top.isLeaf()) {
        //
        // top.setUserObject("Nessun Token rilevato.");
        //
        // }
        //
        // //Listen for when the selection changes.
        // tokenTree.addTreeSelectionListener(new
        // TreeSelectionListener() {
        // public void valueChanged(TreeSelectionEvent
        // e) {
        // DefaultMutableTreeNode node = (
        // DefaultMutableTreeNode)
        // tokenTree.
        // getLastSelectedPathComponent();
        //
        // tokenDetailsPanelRefresh(node);
        //
        // }
        // });
        // tokenTree.setVisibleRowCount(10);

    }

    /**
     * If expand is true, expands all nodes in the tree. Otherwise, collapses
     * all nodes in the tree.
     * 
     * @param tree
     *            JTree
     * @param expand
     *            boolean
     */
    public void expandAll(JTree tree, boolean expand) {
        TreeNode root = (TreeNode) tree.getModel().getRoot();

        // Traverse tree from root
        expandAll(tree, new TreePath(root), expand);
    }

    private void expandAll(JTree tree, TreePath parent, boolean expand) {
        // Traverse children
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0) {
            for (Enumeration e = node.children(); e.hasMoreElements();) {
                TreeNode n = (TreeNode) e.nextElement();
                TreePath path = parent.pathByAddingChild(n);
                expandAll(tree, path, expand);
            }
        }

        // Expansion or collapse must be done bottom-up
        if (expand) {
            tree.expandPath(parent);
        } else {
            tree.collapsePath(parent);
        }
    }

    /**
     * Set the content of the panel that shows token or certificate details
     * according to selected node<br>
     * <br>
     * Setta il contenuto del pannello che presenta a seconda del node
     * selezionato i dettagli del token o del certificato.
     * 
     * @param node
     *            selected node (it might be root, a token or a certificate)
     */
    public void tokenDetailsPanelRefresh(DefaultMutableTreeNode node) {
        // according to node selected

        if (node.isRoot()) {
            panel20.remove(button10);
            panel20.remove(checkBox3);

            label20.setText("");
            label21.setText("");
            label22.setText("");
            label23.setText("");
            label6.setText("");
            label7.setText("");
            label8.setText("");
            label9.setText("");
            return;

        }
        if (node == null) {

            return;
        }
        /* React to the node selection. */
        Object nodeInfo = node.getUserObject();
        if (node.isLeaf()) {
            label20.setText(" ");
            label21.setText(" ");
            label22.setText(" ");
            label23.setText(" ");
            label6.setText(" ");
            label7.setText(" ");
            label8.setText(" ");
            label9.setText(" ");

            CertInfo c = (CertInfo) nodeInfo;
            displayCertOfSlot(c);
        } else {

            CardInReaderInfo c = (CardInReaderInfo) nodeInfo;

            displaySlot(c);

        }

    }

    /**
     * Read X509 certificate from given file<br>
     * <br>
     * Legge il certificato X509 dal file specificato
     * 
     * @param inputFile
     *            File
     * @return X509Certificate
     */
    public X509Certificate readCertFromFile(File inputFile) {
        X509Certificate caCert = null;
        Security.removeProvider("BC");
        // Estrazione certificato da sequenza byte
        FileInputStream is = null;
        try {
            is = new FileInputStream(inputFile);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCert = (X509Certificate) cf.generateCertificate(is);
            return caCert;
        } catch (FileNotFoundException ex) {
        } catch (CertificateException ex) {
            JOptionPane
                    .showMessageDialog(
                            frame,
                            "Errore!\nQuesto file non è un certificato in formato corretto.\n",
                            "Attenzione", JOptionPane.ERROR_MESSAGE);

        }
        return null;
    }

    /**
     * Returns the contents of the file in a byte array (DER encoding).
     * 
     * @param file
     *            File
     * @throws IOException
     * @return byte[]
     */
    public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);

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

    /**
     * Converts DN to CN
     * 
     * @param DN
     *            String
     * @return String
     */
    private String toCNName(String DN) {

        int offset = DN.indexOf("CN=");
        int end = DN.indexOf(",", offset);
        String CN;
        if (end != -1) {
            CN = DN.substring(offset + 3, end);
        } else {
            CN = DN.substring(offset + 3, DN.length());
        }
        CN = CN.substring(0, CN.length());
        return CN;

    }

    /**
     * Class CertInfo keeps information about name and certificate to help
     * visualization of certificate in configuration panel<br>
     * <br>
     * Classe CertInfo che mantiene le informazione nome e certificato per
     * agevolare la visualizzazione del certificato nel pannello di
     * configurazione
     * 
     */

    public class CertInfo {
        public String certName;

        public X509Certificate c;

        /**
         * Constructor (null)
         * 
         */

        public CertInfo() {
            certName = null;
            c = null;
        }

        /**
         * Constructor
         * 
         * @param x
         *            X509Certificate
         */
        public CertInfo(X509Certificate x) {
            certName = toCNName("" + x.getSubjectDN());
            c = x;
        }

        public String toString() {
            return certName;
        }

        public X509Certificate getCertificate() {
            return c;
        }

        public void setCertificate(X509Certificate x) {
            c = x;
        }

        public void setName(String s) {
            certName = s;
        }

    }

    /**
     * Creates CA nodes: it makes difference between two types of CA, one whose
     * X500 names are contained in file CA.properties are "strong" CA, the other
     * isn't. In italian law, this distinction is made as "CA di firma digitale"
     * and "CA di firma elettronica" <br>
     * <br>
     * Crea i nodi delle CA sotto il nodo top, distinguendo tra CA di firma
     * digitale e di firma elettronica
     * 
     * @param top
     *            root node
     */
    private void createCANodes(DefaultMutableTreeNode top) {

        if (CAroot == null)
            return;

        Collection s = CAroot.getCA();
        Iterator it = s.iterator();
        while (it.hasNext()) {
            X509Certificate cert = (X509Certificate) it.next();
            DefaultMutableTreeNode child = new DefaultMutableTreeNode(
                    new CertInfo(cert));

            DefaultMutableTreeNode father = new DefaultMutableTreeNode();

            father = (DefaultMutableTreeNode) top.getChildAt(0);
            father.add(child);

        }

    }

    /**
     * Create present tokens tree (every token has its certificates as leaves)<br>
     * <br>
     * Crea l'albero dei token presenti (ogni token ha come foglie i suoi
     * certificati)
     * 
     * @param top
     *            root node
     * @return JTree
     */
    public void createTreeAndTokenNodes(ArrayList slotInfos) {

        /**
         * la libreria cryptoki (fornita dall'utente o autorilevata via PKCS11)
         * viene usata per trovare le informazioni sugli slot presenti; in
         * seguito viene effettuata su ogni slot la ricerca dei certificati. Si
         * tenga presente che alcune carte sono multislot (Es: slot virtuali in
         * opensc-pkcs11 )
         */

        int indexToken = 0;
        CardInfo ci = null;
        Iterator it = slotInfos.iterator();
        DefaultTreeModel model = (DefaultTreeModel) tokenTree.getModel();

        DefaultMutableTreeNode top = (DefaultMutableTreeNode) model.getRoot();

        while (it.hasNext()) {

            CardInReaderInfo cIr = (CardInReaderInfo) it.next();
            String currReader = cIr.getReader();

            // System.out.println("\nReader:"
            // + currReader);

            DefaultMutableTreeNode child = new DefaultMutableTreeNode(cIr);

            model.insertNodeInto(child, top, top.getChildCount());
            indexToken = ((CardInReaderInfo) child.getUserObject())
                    .getIndexToken();

            ci = cIr.getCard();
            if (ci != null) {

                // ReadCertsTask rt = new ReadCertsTask(cIr);
                // Collection certsOnToken =
                // rt.getCertsOnToken().getCerts();
                ArrayList certsOnToken = cIr.getCerts();

                if (certsOnToken != null) {

                    if (certsOnToken.isEmpty()) {
                        System.out.println("certsOnToken vuoto");
                        CertInfo c = new CertInfo();
                        c.setName("Carta presente ma vuota");
                        DefaultMutableTreeNode certOnToken = new DefaultMutableTreeNode(
                                c);
                        model.insertNodeInto(certOnToken, child, child
                                .getChildCount());

                    }
                    Iterator certIt = certsOnToken.iterator();
                    while (certIt.hasNext()) {

                        X509Certificate cert = (X509Certificate) certIt.next();
                        CertInfo c = new CertInfo(cert);

                        DefaultMutableTreeNode certOnToken = new DefaultMutableTreeNode(
                                c);
                        model.insertNodeInto(certOnToken, child, child
                                .getChildCount());

                    }

                    System.out.println("Informations found for this card:");
                    System.out.println("Description:\t"
                            + ci.getProperty("description"));
                    System.out.println("Manufacturer:\t"
                            + ci.getProperty("manufacturer"));
                    System.out.println("ATR:\t\t" + ci.getProperty("atr"));
                    System.out.println("Criptoki:\t" + ci.getProperty("lib"));

                    // rt.libFinalize();
                    indexToken++;

                }

            } else {
                System.out.println("No card in reader '" + currReader + "'!");
                CertInfo c = new CertInfo();
                c.setName("Nessuna carta");
                DefaultMutableTreeNode certOnToken = new DefaultMutableTreeNode(
                        c);
                model.insertNodeInto(certOnToken, child, child.getChildCount());

            }
        }
        expandAll(tokenTree, true);
        tokenTree.setEditable(true);
        tokenTree.getSelectionModel().setSelectionMode(
                TreeSelectionModel.SINGLE_TREE_SELECTION);
        if (top.isLeaf()) {

            top.setUserObject("Nessun Token rilevato.");

        }

        // Listen for when the selection changes.
        tokenTree.addTreeSelectionListener(new TreeSelectionListener() {
            public void valueChanged(TreeSelectionEvent e) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) tokenTree
                        .getLastSelectedPathComponent();

                tokenDetailsPanelRefresh(node);

            }
        });
        tokenTree.setVisibleRowCount(10);

    }

    /**
     * Display CA certificate details (name and crl distribution points)<br>
     * <br>
     * Visualizza i dettagli del certificato nei relativi campi (metodo per cert
     * CA) Visualizza nome e crl distribution points
     * 
     * @param certInfo
     *            object containing info about certificate
     */
    private void displayCert(CertInfo certInfo) {
        X509Certificate c = certInfo.getCertificate();
        String subjectDN = c.getSubjectDN().toString();
        if(subjectDN.length() > 40)
            textPane2.setText(subjectDN.substring(0, 40) + "...");
        else
            textPane2.setText(subjectDN);

            

        try {
            textField1.setColumns(15);
            textField1.setText(getCrlDistributionPoint(c));
        } catch (CertificateParsingException ex) {
        }

    }

    /**
     * Display details of certificate contained in slot<br>
     * <br>
     * Visualizza i dettagli del certificato nei relativi campi nome e numero di
     * serie.
     * 
     * @param certInfo
     *            object containing info about certificate
     */
    private void displayCertOfSlot(CertInfo certInfo) {
        if (certInfo.getCertificate() != null) {
            panel20.remove(checkBox3);

            X509Certificate c = certInfo.getCertificate();

            GridBagConstraints gbc = new GridBagConstraints();
            label23.setText("Certificato:");
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 5;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label23, gbc);

            label20.setForeground(Color.black);

            String s = toCNName(c.getSubjectDN().toString());

            short maxDisplayLength = 50;
            boolean truncate = s.length() > 50;

            label20.setText(s.substring(0, Math.min(60, s.length()))
                    + (truncate ? "..." : ""));
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 6;
            gbc.gridwidth = 3;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label20, gbc);

            label21.setText("con numero di serie: "
                    + formatAsHexString((c.getSerialNumber().toByteArray())));
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 7;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label21, gbc);

            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 8;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.insets.bottom = 5;
            gbc.insets.right = 5;
            panel20.add(button10, gbc);
        } else {
            panel20.remove(button10);
            panel20.remove(checkBox3);
            GridBagConstraints gbc = new GridBagConstraints();
            label23.setText("Nessun certificato presente.");
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 5;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label23, gbc);

        }

    }

    /**
     * Display details of selected token<br>
     * <br>
     * Visualizza i dettagli del token selezionato
     * 
     * @param tokenInfo
     *            object containing info about selected token
     */
    private void displaySlot(CardInReaderInfo tokenInfo) {
        final String currReader = tokenInfo.getReader();
        final String currLib = tokenInfo.getLib();
        final int indexToken = tokenInfo.getIndexToken();
        CardInfo ci = new CardInfo();
        ci = tokenInfo.getCard();
        panel20.remove(button10);
        panel20.remove(checkBox3);
        GridBagConstraints gbc = new GridBagConstraints();
        label23.setText("Lettore: ");
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets.bottom = 5;
        panel20.add(label23, gbc);

        label6.setText(currReader);
        gbc = new GridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets.bottom = 5;
        panel20.add(label6, gbc);
        if (ci != null) {

            label20.setForeground(Color.black);

            label20.setText("Descrizione: ");
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 6;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label20, gbc);
            label21.setText("Produttore:");
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 7;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label21, gbc);
            label22.setText("Libreria:");
            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 8;
            gbc.gridwidth = 1;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label22, gbc);

            label7.setText(ci.getProperty("description"));
            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = 6;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label7, gbc);
            label8.setText(ci.getProperty("manufacturer"));
            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = 7;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label8, gbc);
            label9.setText(ci.getProperty("lib"));
            gbc = new GridBagConstraints();
            gbc.gridx = 2;
            gbc.gridy = 8;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label9, gbc);

        } else {
            System.out.println("No card in reader '" + currReader + "'!");
            label20.setForeground(Color.red);
            label20.setText("Nessuna carta inserita!");

            gbc = new GridBagConstraints();
            gbc.gridx = 1;
            gbc.gridy = 6;
            gbc.gridwidth = 2;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets.bottom = 5;
            panel20.add(label20, gbc);

            label21.setText("");
            label22.setText("");

            label7.setText("");
            label8.setText("");
            label9.setText("");

        }
        // ---- checkBox3 ----
        checkBox3 = new JCheckBox();
        checkBox3.setSelected((currReader).equals(conf.getReader()));
        // inizializzarlo con il valore dell'oggetto di configurazione
        checkBox3.setText("Utilizza come predefinito");
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        panel20.add(checkBox3, gbc);

        checkBox3.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                conf.setReader(currReader);
                if (currLib != null) {
                    conf.setLib(currLib);
                }

            }
        });

    }

    /**
     * Return CRL distribution points of the certificate as a String<br>
     * <br>
     * Restituisce i CRL DP del certificato specificato in formato Stringa
     * 
     * @param certificate
     *            X509Certificate
     * @throws CertificateParsingException
     * @return URL []: URL array
     */

    private static String getCrlDistributionPoint(X509Certificate certificate)
            throws CertificateParsingException {
        try {
            // trova i DP (OID="2.5.29.31") nel certificato
            DERObject obj = getExtensionValue(certificate, "2.5.29.31");

            if (obj == null) {
                // nessun DP presente
                return null;
            }
            ASN1Sequence distributionPoints = (ASN1Sequence) obj;

            String s = new String();
            String url;
            int p = 0;

            for (int i = 0; i < distributionPoints.size(); i++) {
                ASN1Sequence distrPoint = (ASN1Sequence) distributionPoints
                        .getObjectAt(i);

                for (int j = 0; j < distrPoint.size(); j++) {
                    ASN1TaggedObject tagged = (ASN1TaggedObject) distrPoint
                            .getObjectAt(j);
                    // 0 � il tag per il DP
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
     * Returns DERObject extension if the certificate corresponding to given OID<br>
     * <br>
     * Restituisce un estensione DERObject dal certificato, corrispoendente
     * all'OID
     * 
     * @param cert
     *            certificate
     * @param oid
     *            String
     * @throws IOException
     * @return l'estensione
     */

    private static DERObject getExtensionValue(X509Certificate cert, String oid)
            throws IOException {
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
        ASN1Sequence namesSequence = ASN1Sequence.getInstance(
                (ASN1TaggedObject) names, false);
        if (namesSequence.size() == 0) {
            return null;
        }
        DERTaggedObject taggedObject = (DERTaggedObject) namesSequence
                .getObjectAt(0);
        return new String(ASN1OctetString.getInstance(taggedObject, false)
                .getOctets());

    }

    /**
     * Load CA "one type" properties from "CA.properties" where X500 CA names
     * are stored<br>
     * <br>
     * Carica le properties di CA. Nel file CA.properties sono contenuti i nomi
     * X500 delle CA di firma digitale
     */

    private void loadProperties() {

        System.out.println("Loading CA properties...");

        Properties prop = new Properties();
        InputStream propertyStream = null;
        File dir1 = new File(".");
        String curDir = null;
        try {
            curDir = dir1.getCanonicalPath();
        } catch (IOException ex1) {
        }
        // zip contenente le CA
        String CApropPath =
        // System.getProperty("user.home")
        curDir + System.getProperty("file.separator") + "conf"
                + System.getProperty("file.separator") + "CA.properties";

        try {
            propertyStream = new FileInputStream(CApropPath);
        } catch (FileNotFoundException ex) {
        }

        if (propertyStream != null) {
            try {

                prop.load(propertyStream);
            } catch (IOException e2) {
                System.out.println(e2);
            }
            // prop.list(System.out);
        }

        Iterator i = prop.keySet().iterator();
        String currKey = null;
        String value = null;
        // loading propertis in a vector of CAInfos
        CAInfos = new Vector();
        while (i.hasNext()) {
            currKey = (String) i.next();

            value = (String) prop.get(currKey);
            CAInfos.addElement(value);
        }

    }

    /**
     * Sets the cryptoki library name.
     * 
     * @param newCryptokiLib
     *            String
     */
    private void setCryptokiLib(java.lang.String newCryptokiLib) {
        cryptokiLib = newCryptokiLib;
    }

    /**
     * Returns the cryptoki library name.
     * 
     * @return java.lang.String
     */
    public java.lang.String getCryptokiLib() {
        return cryptokiLib;

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

}
