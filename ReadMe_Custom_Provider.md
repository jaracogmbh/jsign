# Custome Provider Signing Service für das Signieren von Dateien über eine API
## Zielsetzung
Es soll ein Custom Provider Signing Service entwickelt werden, der Dateien über eine externe API signiert. Der Service soll alle erforderlichen Informationen zum Signieren über die Kommandozeile erhalten. Mit diesen Informationen werden das benötigte Zertifikat und die Signatur über die API abgerufen. Das Signieren erfolgt somit vollständig über die externe API.
## Versionshistorie
Das Projekt basiert auf der ``jsign`` Version ``7.0-SNAPSHOT`` von [ebourg](https://github.com/ebourg/jsign) . Diese Version wurde erweitert, um den Custom Provider Signing Service zu implementieren. Die aktuelle Projektversion ist ``1.0.0``.

## Kompatibilität
Der Custom Provider Signing Service ist nicht kompatibel mit ``Java 1.8``. Es wird mindestens ``Java 11`` benötigt.

## Änderungen am Open-Source-Code
Folgende Änderungen wurden am ursprünglichen ``jsign``-Code vorgenommen:
### Anpassungen
1. Provider-Registrierung in der ``SigningServiceJcaProvider``-Klasse:
    - Ermöglicht dynamische Registrierung neuer Provider.
2. Einführung eines neuen ``KeyStoreType``: ``CUSTOMPROVIDER``:
   - Identifiziert den ``Custom Provider Signing Service``.
   - Implementiert die Methoden ``validate`` und ``getProvider``.
3. Deaktivierung der Signatur-Verifizierung im ``AuthenticodeSigner``:
   - Da die Signatur über eine externe API erstellt wird, ist eine Verifizierung nicht erforderlich.
4. Erweiterung der signaturbezogenen Klassen um Exceptions:
   - Verbessert das Fehlerhandling.
   - 
### Neue Funktionen
1. Implementierung des ``CustomProviderSigningService``:
   - Führt das Signieren von Dateien über die API durch.
   - Implementiert das ``SigningService``-Interface.
2. DTO-Klassen für API-Kommunikation:
   - Repräsentieren die JSON-Objekte der API.
3. Service-Klassen für API-Kommunikation:
   - Verantwortlich für HTTP-Anfragen an die API.
4. Testklassen:
   - Sicherstellen der Funktionalität durch Tests.

## Funktionsweise

1. Der Custom Provider Signing Service wird über die Kommandozeile mit den erforderlichen Parametern gestartet.
2. Der storetype-Parameter gibt an, welchen Provider der ``KeyStoreType`` verwenden soll (hier CUSTOMPROVIDER).
    - Alle Eingabeparameter werden validiert.
    - Der entsprechende Provider wird initialisiert.
3. Der ``CustomProviderSigningService`` signiert die Datei über die API:
    - Abruf des Zertifikats:
        - Die Service-Klasse sendet einen HTTP GET-Request mit Basic Authentication an die API.
        - Die API liefert das benötigte Zertifikat zurück.
    - Signieren der Datei:
        - Die Service-Klasse sendet einen HTTP POST-Request mit Basic Authentication und einem Request          Body, der die Eingabeparameter enthält.
        - Die API liefert die Signatur zurück.

## Ausführung
### Ausführung über jsign

Folgende Parameter müssen für den Custom Provider Signing Service gesetzt werden:

- ``storetype``: ``CUSTOMPROVIDER``
- ``keystore``: API-Endpunkt
- ``storepass``: 
  - ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>[|<auth>]``
- Pfad zur zu signierenden Datei.
- ``alias``: Beliebiger Wert.
- ``tsaurl``: URL für den Zeitstempel
- Umgebungsvariable ``CKM_PASS``: Passwort für die Authentifizierung.

#### Authentifizierung
Zwei Möglichkeiten der Authentifizierung für die API:
1. Über den ``storepass``-Parameter (Passwort als letzter Parameter).
2. Über die Umgebungsvariable ``CKM_PASS``:
   - Das Passwort wird aus der Environment-Variable ausgelesen und nicht im ``storepass``-Parameter übergeben.

#### Parameterdetails
##### ``storetype``
Der Parameter bestimmt den Typ des KeyStores (hier ``CUSTOMPROVIDER``) und ist essenziell, damit das Programm den richtigen Provider erkennt.

##### ```storepass``` 
Der Parameter enthält mehrere Informationen, getrennt durch |:
- ``signature algorithm``: Signatur Algorithmus.
- ``mgf1 algorithm``: MGF1 Algorithmus.
- ``salt length``: Salt Länge für dem MGF1 Algorithmus (nur Zahlenwerte erlaubt).
- ``non decorate signature``: Werte: ``true``, ``false``,  ``TRUE``, ``FALSE``, ``0``, ``1`` sind erlaubt.
- ``group``: die Gruppenbezeichnung der ITS-Gruppe.
- ``service id``: Service ID des ITS-Services.
- ``user``: BBenutzerkennung.
- (Optional): ``auth``: Authentifizierung für die Basic Authentifizierung über die HTTP Header

**Achtung**: Es ist wichtig die Informationen in der richtigen Reihenfolge anzugeben. Leere Werte (``||``) sind nicht erlaubt.

**Beispiel**:
- Ohne Authentifizierung:
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user
```

- Mit Authentifizierung:
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user|password12345
```

##### ``keystore``
Über den ``keystore``-Parameter wird der API-Endpunkt (Hostname und Port/Domain) angegeben.Der Pfad der Endpunkte für die Zertifikate und Signaturen sind im Programm festgelegt. 

#### Beispiele für Kommandozeile

- Ohne Authentifizierung:
```
java -jar jsign-1.0.0.jar --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user" --keystore http://localhost:8089 --alias test --storetype CUSTOMPROVIDER --tsaurl http://timestamp.digicert.com psftp.exe 
```

- Mit Authentifizierung:
```
java -jar jsign-1.0.0.jar --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore http://localhost:8089 --alias test --storetype CUSTOMPROVIDER --tsaurl http://timestamp.digicert.com psftp.exe 
```
### Ausführung mit ``jarsigner`` 

Da ``jsign`` keine ``.JAR`` Dateien signieren kann, wird ``jarsigner`` in Kombination mit ``jsign`` verwendet. Dadurch wird die ``.JAR`` Datei signiert und die Signatur wird über ``jsign`` an den ``Custom Provider Signing Service`` übergeben.

#### Beispiele für Kommandozeile

- Ohne Authentifizierung:
```
 jarsigner -J-cp -Jjsign-1.0.0.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -tsa http://timestamp.digicert.com -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```
- Mit Authentifizierung:
```
 jarsigner -J-cp -Jjsign-1.0.0.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -tsa http://timestamp.digicert.com -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```

#### Wichtige Hinweise für ``jarsigner``: 
- ``keystore``: Muss auf NONE gesetzt werden.
- ``providerArg``: Endpunkt für den Custom Provider Signing Service.
- Zusätzliche Flags:
  - ``sigalg``: Signaturalgorithmus.
  - ``digestalg``: Digest-Algorithmus.
- ``alias``: Muss zwingend an letzter Stelle stehen.