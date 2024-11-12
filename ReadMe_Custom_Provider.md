# Custome Provider Service für das Signieren von Dateien über eine REST API

## Ausführung über jsign

Für die Ausführung des ``Custom Provider Service`` müssen folgende jsign Parameter gesetzt sein:

- ``storetype``: ``CUSTOMPROVIDER``
- ``keystore``: API Endpunkt
- ``storepass``: ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>``
  - Es ist bei den einzelnen Parameter folgendes zu beachten:
    - ``non decorate signature``: ``true`` oder ``false`` oder ``TRUE`` oder ``FALSE`` oder ``0`` oder ``1``
    - ``sal length``müss numerisch sein
    - leere Werte wie ``||`` sind nicht erlaubt
- Pfad zur Datei, die signiert werden soll
- ``alias``: hier muss ein Wert gesetzt werden.

## Ausführung über die Kommando Zeile
- Beispiel:

```
java -jar jsign-7.0-SNAPSHOT.jar --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore http://localhost:8089 --alias test --storetype CUSTOMPROVIDER psftp.exe 
```
## Ausführung mit ``jarsigner`` über die Kommando Zeile

Da ``jsign`` keine ``.JAR`` Dateien signieren kann, wird ``jarsigner`` in Kommbination mit ``jsign`` verwendet. Dadurch wird die ``.JAR`` Datei signiert und die Signatur wird über ``jsign`` an den ``Custom Provider Service`` übergeben.

- Beispiel:

```
 jarsigner -J-cp -Jjsign-7.0-SNAPSHOT.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```

### Bemerkung: 
- Zusätzliche Parameter:
    - sigalg: Signatur Algorithmus
    - digestalg: Digest Algorithmus
- letzter Parameter ist der ``alias``
- Wenn wir in ``Jarsigner`` keinen ``tsurl`` Flag angeben, bekommen wir eine Warnung. Da die REST API das erstellen der Signatur übernimmt, ist es nicht notwendig den ``tsurl`` Flag zu setzen. Dadurch kann ``Jarsigner`` aber nicht verifizieren, ob die Signatur gültig ist, da es keine Zeitstempel gibt, die er überprüfen kann.