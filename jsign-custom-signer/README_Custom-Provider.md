# Projekt für einen Custom Signer Provider

## Overview
This Project creates a Custom Signing Service that allows us to sign a file via an external API. The external API provides the certificate and the signature. The signature is then inserted into the file and the signed file is returned. The Custom Signer Provider is compatible with the ``jsign`` program.


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

The ``storetype`` parameter is a string that specifies the type of the KeyStore. In this case, the type is ``CUSTOMPROVIDER``. This parameter is necessary so that the program knows that it is the ``Custom Provider Service``.

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
Da relativ viele Informationen in einem String übergeben werden müssen, ist es wichtig, dass die Informationen in der richtigen Reihenfolge und mit dem richtigen Trennzeichen übergeben werden. Das Trennzeichen ist der ``|``. Die Reihenfolge der Informationen ist wie folgt:

```
<signature algorithm>|<mgf1 algorithm>|<salt length>|<non decorate signature>|<group>|<service id>|<user>|<auth>
```
Auperdem ist zu beachten, dass leere Werte (``||``) nicht erlaubt sind. Hier wird dann ein Fehler geworfen und das Programm wird beendet. Auch müssen alle Werte gesetzt werden.

Since relatively many information must be passed in a string, it is important that the information is passed in the correct order and with the correct delimiter. The delimiter is the ``|``. The order of the information is as follows:

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

## Was muss in ``jsign`` geändert werden?

Um zu ermöglichen, dass Custom Signing Provider in ``jsign`` verwendet werden können, mussten einige Änderungen im ``jsign-crypto`` Projekt vorgenommen werden.

1. Registrierung der Provider zur Laufzeit.
    - Um einen eigenen Provider verwenden zu können, muss dieser registiert werden. Dafür wurde die Klasse ``SigningServiceJcaProvider``, so geändert dass die Provider zur Laufzeit registriert werden können.
2. Hinzunahme eines Weiteren Typen im ``KeyStoreType`` Enum
    - Der ``KeyStoreType`` Enum wurde um einen weiteren Typen erweitert. ``CUSTOMPROVIDER`` soll den Typen für einen Custom Provider Service darstellen. Mit diesem Typen kann der ``jsign`` Programm erkennen, dass ein Custom Provider verwendet wird.
3. ``CustomProviderSigningInterface`` und ``CustomProviderInstantiationService``
    - Um einen Custom Provider verwenden zu können, muss dieser das ``CustomProviderSigningInterface`` implementieren. Dieses Interface ist für die Validierung und das Erstellen des Custom Digning Providers zuständig. Der ``CustomProviderInstantiationService`` ist für die Instanzierung des Custom Providers zuständig.

### Instanziierung von Custom Singning Services
Die Instanziierung der Custom Signing Services erfolgt über die ``CustomProviderInstantiationService`` Klasse. Die Klasse verwendet die Reflection API, um die Custom Signing Services zu instanzieren. Das bedeutet die Custom Signing Service werden über den Namen der Klasse instanziiert.

Alle Custom Signing Services müssen das ``CustomProviderSigningInterface`` implementieren und einen Konstruktor mit zwei String Parametern haben. 

### Running via the Command Line

- Example:

```
```





