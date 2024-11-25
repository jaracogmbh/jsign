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