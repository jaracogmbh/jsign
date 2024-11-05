# CustomProviderService API signing implementation

## Build

To build the project:

```
mvn clean install -Djapicmp.skip=true -DskipTests=true -Dmaven.javadoc.skip=true -Dproguard.skip=true
```

## Mock API Setup

To use CustomProviderService, set up the mock signing service API locally with Node.js:

```javascript
const express = require("express");
const app = express();
const port = 8080;

const mockPrivateKey = {
  id: "mock-server-key-id",
  key: "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEArw8+yj4U8yKk5mP0\n--TRUNCATED--\n-----END PRIVATE KEY-----"
};

const mockCertificateChain = {
  certChain: [
    "1 cert",
    "2 cert", 
    "3 cert"
  ]
};

const mockSignature = {
  signature: "dGVzdC1zaWduYXR1cmU="
};

app.get("/getPrivateKey", (req, res) => {
  res.json(mockPrivateKey);
});

app.get("/getCertificateChain", (req, res) => {
  res.json(mockCertificateChain);
});

app.post("/sign", (req, res) => {
  res.json(mockSignature);
});

app.listen(port, () => {
  console.log(`Mock signing service running at http://localhost:${port}`);
});
```

## Signing Command

With everything set up, use this command to sign your JAR file:

```
jarsigner \
  -J-cp -J../jsign/target/jsign-7.0-SNAPSHOT.jar \
  -providerClass net.jsign.jca.JsignJcaProvider \
  -providerArg http://localhost:8080 \
  -keystore NONE \
  -storetype CUSTOMPROVIDER \
  -storepass someAPIkey123 \
  -verbose \
  ./html.jar default
```

## Generating a Dummy Signing Chain

Dummy signing chain need to be implemented in the API response (`1 cert`,`2 cert`,`3 cert`). 
To generate a dummy signing chain for testing, use the `generate_dummy_signing_chain.sh` script in the example directory and place it manually in the API.
