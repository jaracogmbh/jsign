# Custome Provider Signing Service für das Signieren von Dateien über eine API
## Zielsetzung
Es soll ein ``Custom Provider Signing Service`` entwickelt werden, der Dateien mittels einer externen API signiert. Der Service soll all die benötigten Informationen zum Signieren über die Kommandozeile erhalten. Mit diesen Informationen wird dann einmal das benötigte Zertifikat und einmal die Signatur über die API ermittelt. Das Signieren wird somit über eine externe API durchgeführt.
## Versionshistorie
Unser Projekt baut auf der ``jsign Version 7.0-SNAPSHOT`` von [ebourg](https://github.com/ebourg/jsign) auf. Diese Version wurde von uns erweitert, um den ``Custom Provider Signing Service`` zu implementieren. Unser Projekt wird auf die Version ``1.0.0`` gesetzt.

## Kompatibilität
Der ``Custom Provider Signing Service`` ist nicht kompatibel mit ``Java 1.8``. Es wird mindestens ``Java 11`` benötigt.

## Was hat sich geänder im Opensource Code
Es wurden folgende Änderungen am Originalcode von ``jsign`` vorgenommen:
### Änderungen
- Änderung der Provider Registierung in der ``SigningServiceJcaProvider`` Klasse.
  - damit ein neuer Provider registiert werden kann, wurde die Klasse so geändert, dass dynamisch neue Provider registriert werden könnenyou
- Einführung eines neuen ``KeyStoreType``: ``CUSTOMPROVIDER``.
  - damit das Programm weiß, dass es sich um den ``Custom Provider Signing Service`` handelt, wurde ein neuer ``KeyStoreType`` eingeführt.
  - dieser implementiert die führ den ``KeyStoreType`` benötigten Methoden ``validate`` und ``getProvider``.
- Verifizierung der signierten Datei im ``AuthenticodeSigner`` wurde abgeschaltet.
  - da die Signatur über eine externe API erstellt wird, ist es einerseits nicht notwendig die Signatur zu verifizieren und andererseits hat nur die API die benötigten Informatonen, um diesen zu verifizieren welche nicht für ``jsign`` zur Verfügung stehen.
- Klassen, die im Zusammenhang mit den Signieren stehen, wurden um Exceptions erweitert.
  - damit Fehlermeldungen besser verarbeitet werden können, wurden die Klassen um Exceptions erweitert.
  
### Neu hinzugefügt
- Implementierung des ``CustomProviderSigningService``.
  - dieser Service ist für das Signieren der Dateien über die API zuständig.
  - er implementiert das ``SigningService`` Interface.
- DTO Klassen für die API Kommunikation.
  - es wurden DTO Klassen erstellt, die die ``JSON`` Objekte der API repräsentieren.
- Service Klassen für die API Kommunikation.
  - es wurden Service Klassen erstellt, die die Kommunikation mit der API übernehmen.
- Test Klassen.

## Funktionsweise
1. Über die Kommandozeile wird der ``Custom Provider Signing Service`` mit den benötigten Parametern gestartet.
2. Über den ``storetype`` Parameter, weiß der ``KeyStoreType``, welchen Provider er verwenden soll. In diesem Fall ist es der ``CUSTOMPROVIDER``.
   - hier wird die Eingabe aller Parameter validiert.
   - dann wird der benötigte Provider mit den richtigen ``SigningService`` initiliert.
3. im ``CustomProviderSigningService`` wird die Datei über die API signiert.
   - dazu wird zu erst das benötigte Zertifikat über die API ermittelt.
     - dafür wird von der Service Klasse ein ``HTTP GET`` Request mit ``Basic Authentication`` an die API gesendet.
     - die API leifert dann ein Zertifikat zurück.
   - dann wird die Datei über die API signiert.
     - die Service Klasse sendet ein ``HTTP POST`` Request mit ``Basic Authentication`` und einen ``Request Body`` bestehend aus den Eingabeparametern an die API.
     - die API liefert dann die Signatur zurück.

## Ausführung
## Ausführung über jsign

Für die Ausführung des ``Custom Provider Signing Service`` müssen folgende jsign Parameter gesetzt sein:

- ``storetype``: ``CUSTOMPROVIDER``
- ``keystore``: API Endpunkt
- ``storepass``: ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>`` oder ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>``
- Pfad zur Datei, die signiert werden soll
- ``alias``: hier muss ein Wert gesetzt werden.
- ``tsaurl``: URL für den Zeitstempel
- ``CKM_PASS`` Environment Variable: Passwort für die Authentifizierung

### Authentifizierung mit ``CKM_PASS`` Environment Variable
Es gibt zwei Möglichkeiten, wie die Authentifizierung für die API erfolgen kann:
1. Über den ``storepass`` Parameter
   - dort kann das Passwort als letzten Parameter direkt mit übergeben werden
2. Über die ``CKM_PASS`` Environment Variable
   - das Passwort wird in der ``CKM_PASS`` Environment Variable gesetzt.
   - das Passwort wird dann automatisch aus der Environment Variable gelesen und für die Authentifizierung verwendet.
   - das Passwort wird dann nicht mehr im ``storepass`` Parameter übergeben.

### ``storetype`` Parameter
Der ``storetype`` Parameter ist ein String, der den Typ des KeyStores angibt. In diesem Fall ist der Typ ``CUSTOMPROVIDER``. Dieser Parameter ist notwendig, damit das Programm weiß, dass es sich um den ``Custom Provider Signing Service`` handelt.

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
- (Optional) ``auth``: Authentifizierung für die Basic Authentifizierung über die HTTP Header

#### Aufbau des ``storepass`` Parameters
Da relativ viele Informationen im ``storepass`` übergeben werden müssen, ist es wichtig, dass die Informationen in der richtigen Reihenfolge und mit dem richtigen Trennzeichen übergeben werden. Das Trennzeichen ist der ``|``. Die Reihenfolge der Informationen ist wie folgt:

- Ohne Authentifizierung:
```
<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>
```
- Mit Authentifizierung:
```
<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>
```
Auperdem ist zu beachten, dass leere Werte (``||``) nicht erlaubt sind. Hier wird dann ein Fehler geworfen und das Programm wird beendet. Auch müssen alle Werte gesetzt werden.

#### Beispiel für den ``storepass`` Parameter
- Ohne Authentifizierung:
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user
```

- Mit Authentifizierung:
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user|password12345
```

### Endpunkt
Sowohl das Zertifikat als auch die Signature werden über eine API ermittelt bzw. erstellt. Der Endpunkt wird über den Parameter ``keysotre`` übergeben. Der Endpunkt ist dabei nur der Hostname und der Port (Oder die Domain). Der Pfad der Endpunkte für die Zertifikate und Signaturen sind im Programm festgelegt. 

### Ausführung über die Kommando Zeile
- Beispiel:

- Ohne Authentifizierung:
```
java -jar jsign-1.0.0.jar --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user" --keystore http://localhost:8089 --alias test --storetype CUSTOMPROVIDER --tsaurl http://timestamp.digicert.com psftp.exe 
```

- Mit Authentifizierung:
```
java -jar jsign-1.0.0.jar --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore http://localhost:8089 --alias test --storetype CUSTOMPROVIDER --tsaurl http://timestamp.digicert.com psftp.exe 
```
### Ausführung mit ``jarsigner`` über die Kommando Zeile

Da ``jsign`` keine ``.JAR`` Dateien signieren kann, wird ``jarsigner`` in Kommbination mit ``jsign`` verwendet. Dadurch wird die ``.JAR`` Datei signiert und die Signatur wird über ``jsign`` an den ``Custom Provider Signing Service`` übergeben.

- Beispiel:

- Ohne Authentifizierung:
```
 jarsigner -J-cp -Jjsign-1.0.0.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -tsa http://timestamp.digicert.com -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```
- Mit Authentifizierung:
```
 jarsigner -J-cp -Jjsign-1.0.0.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089" -keystore NONE -tsa http://timestamp.digicert.com -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test 
```

#### Bemerkungen bei der Ausführung mit ``jarsigner``: 
- zu beachten:
  - der `keystore` Parameter muss auf ``NONE`` gesetzt werden
  - der Endpunkt wird über den ``providerArg`` Parameter übergeben
    - dieser Parameter ist notwendig, damit ``jarsigner`` weiß, dass es sich um den ``Custom Provider Signing Service`` handelt.
    - außerdem ist dieser Parameter nicht nativ in ``jsign`` vorhanden, sonder nur in Kombination mit ``jarsigner``.
- Zusätzliche Flags:
    - ``sigalg``: Signatur Algorithmus
    - ``digestalg``: Digest Algorithmus
    - diese beiden Flags müssen gesetzt werden, da ``jarsigner`` sonst nicht den richtigen Algorithmus für die Signature benutzt.
- letzter Parameter ist der ``alias``. Dieser muss zwingend an letzter Stelle stehen.