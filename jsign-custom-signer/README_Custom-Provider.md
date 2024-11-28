# Projekt für einen Custom Signer Provider

## Overview
This Project creates a Custom Signing Service that allows us to sign a file via an external API. The external API provides the certificate and the signature. The signature is then inserted into the file and the signed file is returned. The custom signing service is compatible with the ``jsign`` program.


## Idea behind the Project

The basic idea of this project is to implement a custom signing service that can sign files individually to the user's needs. In this case, an external API is used to sign files. These custom signing services should be compatible with the ``jsign`` program so that it can use the custom signing service when signing files.

In ``jsign`` an entry point is provided that allows the use of these custom signing services.

## Compatibility

The ``jsign-custom-signer`` is not compatible with ``Java 1.8``. At least ``Java 11`` is required.

## Input Parameters 

This section describes the input parameters that are required to run the Custom Provider Service.

- ``storetype``: ``CUSTOMPROVIDER``
- ``keystore``: ``<API Endpoint>|<full class name of the Custom Signing Service class>``
- ``storepass``: ``<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>``
- Path to the file that is to be signed
- ``alias``: a value must be set here.

### ``storetype`` Parameter

The ``storetype`` parameter is a string that specifies the type of the keystore that is used. In this case, the type is ``CUSTOMPROVIDER``. This parameter is necessary so that the program knows to use the custom signing service.

### ```storepass``` Parameter

The ``storepass`` parameter is a string that contains the following information:
- ``signature algorithm``: Signature Algorithm
- ``mgf1 algorithm``: MGF1 Algorithm
- ``salt length``: Salt length for the MGF1 Algorithm
   - only a valid number is allowed as input
- ``non decorate signature``: Non Decorate Signature
  - only the following values are accepted as input:
     - ``true``, ``false``,  ``TRUE``, ``FALSE``, ``0``, ``1``
- ``group``: the group name of the ITS group
- ``service id``: Service ID of the ITS service
- ``user``: User identification
- ``auth``: Authentication for the Basic Authentication via the HTTP Header

#### Structure of the ``storepass`` Parameters

Since a lot of information must be passed in a string, it is important that the information is passed in the correct order and with the correct delimiter. The delimiter is the ``|``. The order of the information is as follows:

```
<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>
```

In addition, it should be noted that empty values (``||``) are not allowed. An error will be thrown and the program will be terminated. Also, all values must be set.

#### Example for the ``storepass`` parameter
``` 
SHA256WithRSA|SHA-256|32|true|itsGroup|1234|user|password12345
```

### KeyStore Parameter

Both the certificate and the signature are determined or created via an API. The endpoint is passed via the ``keystore`` parameter. The endpoint is only the hostname and the port (or the domain). The path of the endpoints for the certificates and signatures are fixed in the program. 

The other part of the ``keystore`` parameter is the full class name of the Custom Signing Service class. With the class name the Custom Signing Service is instantiated in the ``jsign`` program.

#### Example for the ``keystore`` parameter
``` 
http://localhost:8089|net.jsign.service.ExternalSigningService
```

### ``JAR`` File for the Custom Signing Service and ``jsign``

When using a custom signing service, the ``JAR`` file of the custom signing service will be passed to the ``jsign`` program via classpath. For that to work we need to create a ``FAT JAR`` file that contains all the dependencies of the custom signing service.

The same applies to the ``jsign`` program. The ``jsign`` program must also be passed as a ``FAT JAR``.

### Running via the Command Line

- Example Linux:

```
java -cp "jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar:jaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar" net.jsign.JsignCLI --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore "http://localhost:8089|net.jsign.service.ExternalSigningService" --alias test --storetype CUSTOMPROVIDER psftp.exe
```

- Example Windows:

```
java -cp "jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar;jaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar" net.jsign.JsignCLI --storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" --keystore "http://localhost:8089|net.jsign.service.ExternalSigningService" --alias test --storetype CUSTOMPROVIDER psftp.exe
```

## Running with ``jarsigner`` via the Command Line

Since ``jsign`` cannot sign ``.JAR`` files, ``jarsigner`` is used in combination with ``jsign``. This signs the ``.JAR`` file and the signature is passed to the custom Signing Service via ``jsign``.

- Example Linux:

```
jarsigner -J-cp -Jjaraco-jsign-1.0.0-SNAPSHOT-jar-with-dependencies.jar:jsign-custom-signer-1.0.0-SNAPSHOT-jar-with-dependencies.jar  -J--add-modules -Jjava.net.http -storepass "SHA256WithRSA|SHA-256|0|true|itsGroup|1234|user|password12345" -storetype CUSTOMPROVIDER -providerClass net.jsign.jca.JsignJcaProvider -providerArg "http://localhost:8089|net.jsign.service.ExternalSigningService" -keystore NONE -sigalg SHA256withRSA -digestalg SHA-256 application_original.jar test
```

- Example Windows:

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

- to be noted:
  - the `keystore` parameter must be set to ``NONE``
  - the endpoint and class name are passed via the ``providerArg`` parameter
    - this parameter is necessary so that ``jarsigner`` knows that it is the Custom Signing Service
  - also this parameter is only available in combination with ``jarsigner`` and not natively in ``jsign``
  - Additional Flags:
    - ``sigalg``: Signature Algorithm
    - ``digestalg``: Digest Algorithm
    - these two flags must be set, otherwise ``jarsigner`` will not use the correct algorithm for the signature
  - the last parameter is the ``alias``. This must be set at the last position.
  - If we do not specify a ``tsurl`` flag in ``Jarsigner``, we get a warning. Since the API takes care of creating the signature, it is not necessary to set the ``tsurl`` flag, so the warning can be ignored.



