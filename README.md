Javafirma Applet
================

Questo programma è stato sviluppato per permettere la firma digitale di documenti all'interno di una procedura web, nel nostro caso il software di gestione dei procedimenti amministrativi interno alla Provincia di Treviso

E' basato sul software freesigner e su j4sign, sviluppati dal servizio Sistema Informativo del Comune di Trento e disponibile al sito <http://j4sign.sourceforge.net/>.

Installazione
--------

Una volta scaricati i sorgenti è necessario creare un keystore per la firma del jar con il comando:

keytool -genkey -keyalg RSA -alias ALIAS -keystore sign_javafirma.keystore -storepass PASSWORD -validity 365 -keysize 2048

dove ALIAS e PASSWORD sono dei valori scelti da voi che andranno inseriti nel file buildjar.xml alla riga 23 dove si parla di alias e password per la firma del jar.


Utilizzo
--------

Esempi su come utilizzare l'applet si trovano nella cartella demo.

Licenza
--------

Anche quando non specificato nel sorgente, il software è licenziato con licenza GPLv2.

Javafirma Applet
================

This software has been developed for signing documents digitally in a web application, in our case the internal management software of Provincia di Treviso

It's based on the software freesigner and j4sign, developed by Servizio Sistema Informativo of the Municipality of Trento and available at the site <http://j4sign.sourceforge.net>

Installation
------------

Once downloaded the sources, you need to creare a keystore for the jar signing operation with the command:

keytool -genkey -keyalg RSA -alias ALIAS -keystore sign_javafirma.keystore -storepass PASSWORD -validity 365 -keysize 2048

where ALIAS and PASSWORD are values choosen by the user that then will be inserted in the file buildjar.xml at line 23, where there is the directive about the signing.

Usage
-----
Demo html files on how to use the applet are in the directory demo/.

License
--------

Even if not specified in the source code, the software il licensed with license GPLv2.
