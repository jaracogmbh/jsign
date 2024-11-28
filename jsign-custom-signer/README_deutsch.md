# Projekt für einen Custom Signer Provider

## Übersicht

Dieses Projekt implementiert einen Custom Signing Service, der es ermöglicht, eine Datei über eine externe API zu signieren. Die externe APIl iefert  das Certifikat und die Signatur zurück. Die Signatur wird dann in die Datei eingefügt und die signierte Datei wird zurückgegeben. Der Custom Signer Provider ist kompatibel mit dem ``jsign`` Programm.

## Idee hinter dem Projekt

Die Grundidee bei diesem Projekt ist es einen eigenen Signing Service zu implementieren, der das Signieren von Dateien individuell an die Bedürfnisse des Nutzers anpassen kann. In diesem Fall wird eine externe API verwendet, die das Signieren von Dateien übernimmt. Diese Custom Signing Service sollen kompatibel mit den ``jsign`` Programm sein, sodass dieser die Custom Signing Service beim Ausführen des Signierungsprozesses verwenden kann.

Im ``jsign`` wird dann nur eine Schnittstelle zur Verfügung gestellt, die es ermöglicht, diese Custom Signing Service zu verwenden.


## Kompatibilität
Der ``jsign-custom-signer`` ist nicht kompatibel mit ``Java 1.8``. Es wird mindestens ``Java 11`` benötigt.

## Eingabeparameter
Für die Ausführung des ``jsign-custom-signer`` müssen folgende jsign Parameter gesetzt sein:

- ``storetype``: ``CUSTOMPROVIDER``
- ``keystore``: API Endpunkt
- ``storepass``: ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>``
- Pfad zur Datei, die signiert werden soll
- ``alias``: hier muss ein Wert gesetzt werden.


### ``storetype`` Parameter
Der ``storetype`` Parameter ist ein String, der den Typ des KeyStores angibt. In diesem Fall ist der Typ ``CUSTOMPROVIDER``. Dieser Parameter ist notwendig, damit das Programm weiß, dass es sich um den ``Custom Provider Service`` handelt.

### ```storepass``` Parameter
Der ``storepass`` Parameter ist ein String, der die folgenden Informationen enthält:
- ``signature algorithm``: Signatur Algorithmus
- ``mgf1 algorithm``: MGF1 Algorithmus
- ``salt length``: Salt Länge für dem MGF1 Algorithmus
    - hier ist nur ein gültiger Zahlenwert als Eingabe erlaubt
- ``non decorate signature``: Non Decorate Signature
    - hier werden nur folgende Werte als Eingabe akzeptier:
        - ``true``, ``false``,  ``TRUE``, ``FALSE``, ``0``, ``1``
- ``group``: die Gruppenbezeichnung der ITS Gruppe
- ``service id``: Service ID des ITS Services
- ``user``: Benutzer Identifikation
- ``auth``: Authentifizierung für die Basic Authentifizierung über die HTTP Header

#### Aufbau des ``storepass`` Parameters
Da relativ viele Informationen in einem String übergeben werden müssen, ist es wichtig, dass die Informationen in der richtigen Reihenfolge und mit dem richtigen Trennzeichen übergeben werden. Das Trennzeichen ist der ``|``. Die Reihenfolge der Informationen ist wie folgt:

```
<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>
```
Auperdem ist zu beachten, dass leere Werte (``||``) nicht erlaubt sind. Hier wird dann ein Fehler geworfen und das Programm wird beendet. Auch müssen alle Werte gesetzt werden.

#### Beispiel für den ``storepass`` Parameter
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user|password12345
```

### KeyStore Parameter

Sowohl das Certifikat als auch die Signature werden über eine API ermittelt bzw. erstellt. Der Endpunkt wird über den Parameter ``keysotre`` übergeben. Der Endpunkt ist dabei nur der Hostname und der Port (Oder die Domain). Der Pfad der Endpunkte für die Zertifikate und Signaturen sind im Programm festgelegt.

Der andere Teil des ``keystore`` Parameters ist der vollständige Klassenname der Custom Signing Service Klasse. Mit dem Klassennamen wird der Custom Signing Service im ``jsign`` Programm instanziiert.

#### Beispiel für den ``keystore`` Parameter
``` 
http://localhost:8089|net.jsign.service.ExternalSigningService
```

### ``JAR`` Datei für den Custom Signing Service und ``jsign``

Wenn ein Custom Signing Service verwendet wird, wird die ``JAR`` Datei des Custom Signing Service über den Classpath an das ``jsign`` Programm übergeben. Dafür müssen wir eine ``FAT JAR`` Datei erstellen, die alle Abhängigkeiten des Custom Signing Service enthält.

Das gleiche gilt auch für das ``jsign`` Programm. Das ``jsign`` Programm muss auch als ``FAT JAR`` Datei sein.

### Ausführung über die Kommando Zeile

- Beispiel Linux:

```
java -cp "jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar:jaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar" net.jsign.JsignCLI --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore "http://localhost:8089|net.jsign.service.ExternalSigningService" --alias test --storetype CUSTOMPROVIDER psftp.exe
```

- Beispiel Windows:

```
java -cp "jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar;jaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar" net.jsign.JsignCLI --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore "http://localhost:8089|net.jsign.service.ExternalSigningService" --alias test --storetype CUSTOMPROVIDER psftp.exe
```

## Ausführung mit ``jarsigner`` über die Kommando Zeile

Da ``jsign`` keine ``.JAR`` Dateien signieren kann, wird ``jarsigner`` in Kommbination mit ``jsign`` verwendet. Dadurch wird die ``.JAR`` Datei signiert und die Signatur wird über ``jsign`` an den ``Custom Provider Service`` übergeben.

- Beispiel Linux:

```
 jarsigner -J-cp -Jjsign-7.0-SNAPSHOT.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```

- Beispiel Windows:

```
jarsigner -J-cp -Jjaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar;jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089|net.jsign.service.ExternalSigningService" -keystore NONE -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test
```


### Bemerkungen bei der Ausführung mit ``jarsigner``:
- zu beachten:
    - der `keystore` Parameter muss auf ``NONE`` gesetzt werden
    - der Endpunkt wird über den ``providerArg`` Parameter übergeben
        - dieser Parameter ist notwendig, damit ``jarsigner`` weiß, dass es sich um den ``Custom Provider Service`` handelt.
        - außerdem ist dieser Parameter nicht nativ in ``jsign`` vorhanden, sonder nur in Kombination mit ``jarsigner``.
- Zusätzliche Flags:
    - ``sigalg``: Signatur Algorithmus
    - ``digestalg``: Digest Algorithmus
    - diese beiden Flags müssen gesetzt werden, da ``jarsigner`` sonst nicht den richtigen Algorithmus für die Signature benutzt.
- letzter Parameter ist der ``alias``. Dieser muss zwingend an letzter Stelle stehen.
- Wenn wir in ``Jarsigner`` keinen ``tsurl`` Flag angeben, bekommen wir eine Warnung. Da die API das erstellen der Signatur übernimmt, ist es nicht notwendig den ``tsurl`` Flag zu setzen, weshalb die Warnung ignoriert werden kann.

## Ausführen mit ``Environment Variable`` zum testen

- Beispiel Linux:
    
```
CKM_PASS=password123456 java -cp "jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar:jaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar" net.jsign.JsignCLI --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user" --keystore "http://localhost:8089|net.jsign.service.ExternalSigningService" --alias test --storetype CUSTOMPROVIDER psftp.exe
```


