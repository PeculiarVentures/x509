import * as path from "path";
import * as assert from "assert";
import * as x509 from "../src";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
  name: "ECDSA",
  hash: "SHA-256",
  namedCurve: "P-256",
};

const theTestX509CertificateGeneratorVector = [
  {
    certContents: {
      serialNumber: "01",
      name: "CN=Test, O=Дом",
      subject: "CN=Test, O=Дом",
      issuer: "CN=Test, O=Дом",
      notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
      notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
      signingAlgorithm: alg,
      extensions: [
        new x509.BasicConstraintsExtension(true, 2, true),
        new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        new x509.CertificatePolicyExtension([
          "1.2.3.4.5",
          "1.2.3.4.5.6",
          "1.2.3.4.5.6.7",
        ]),
      ]
    },

    testDate: new Date(Date.UTC(2040, 0, 1, 8, 0, 1)),   // UTCTime 2040-01-01 08:00:01 UTC
    testAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 1)),  // UTCTime 2040-01-02 08:00:01 UTC
    testBefore: new Date(Date.UTC(2020, 0, 1, 0, 0, 1)), // UTCTime 2020-01-01 00:00:01 UTC

    certPem:
      `-----BEGIN CERTIFICATE-----
MIIBmjCCAT+gAwIBAgIBATAKBggqhkjOPQQDAjAgMQ0wCwYDVQQDEwRUZXN0MQ8w
DQYDVQQKDAbQlNC+0LwwHhcNMjAwMTAxMDgwMDAwWhcNNDAwMTAyMDgwMDAwWjAg
MQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKDAbQlNC+0LwwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQYR3iB8GEm6pKJ9OJZRg7BJz6gePT+GGxwZZgLJEPEo3G1U318
Y/37xzjsmd+xR+Kuz46UBvXkua7LQq3pTacBo2owaDASBgNVHRMBAf8ECDAGAQH/
AgECMBwGA1UdJQEB/wQSMBAGBioDBAUGBwYGUwQFBgcIMA4GA1UdDwEB/wQEAwIB
BjAkBgNVHSAEHTAbMAYGBCoDBAUwBwYFKgMEBQYwCAYGKgMEBQYHMAoGCCqGSM49
BAMCA0kAMEYCIQDskjb7BN3ppaQKIZdJJ5617PoFFfluQ3NuGPj6ljK7vAIhAKRc
4iVJsJUDSiCw1upeannIYgmJcKWmLBKjGmOyLa+O
-----END CERTIFICATE-----`,
    certDer: "3082019a3082013fa003020102020101300a06082a8648ce3d0403023020310d300b0603550403130454657374310f300d060355040a0c06d094d0bed0bc301e170d3230303130313038303030305a170d3430303130323038303030305a3020310d300b0603550403130454657374310f300d060355040a0c06d094d0bed0bc3059301306072a8648ce3d020106082a8648ce3d0301070342000418477881f06126ea9289f4e259460ec1273ea078f4fe186c7065980b2443c4a371b5537d7c63fdfbc738ec99dfb147e2aecf8e9406f5e4b9aecb42ade94da701a36a306830120603551d130101ff040830060101ff020102301c0603551d250101ff0412301006062a03040506070606530405060708300e0603551d0f0101ff04040302010630240603551d20041d301b300606042a030405300706052a03040506300806062a0304050607300a06082a8648ce3d0403020349003046022100ec9236fb04dde9a5a40a219749279eb5ecfa0515f96e43736e18f8fa9632bbbc022100a45ce22549b095034a20b0d6ea5e6a79c862098970a5a62c12a31a63b22daf8e",
    privateKey: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104201823f412a803f2cfbae8574e00fb8993b17683057e099e6b9fd0e2d7da40c97ca1440342000418477881f06126ea9289f4e259460ec1273ea078f4fe186c7065980b2443c4a371b5537d7c63fdfbc738ec99dfb147e2aecf8e9406f5e4b9aecb42ade94da701",
    publicKey: "3059301306072a8648ce3d020106082a8648ce3d0301070342000418477881f06126ea9289f4e259460ec1273ea078f4fe186c7065980b2443c4a371b5537d7c63fdfbc738ec99dfb147e2aecf8e9406f5e4b9aecb42ade94da701",
    signatureDer: "3046022100ec9236fb04dde9a5a40a219749279eb5ecfa0515f96e43736e18f8fa9632bbbc022100a45ce22549b095034a20b0d6ea5e6a79c862098970a5a62c12a31a63b22daf8e",
    signature: "ec9236fb04dde9a5a40a219749279eb5ecfa0515f96e43736e18f8fa9632bbbca45ce22549b095034a20b0d6ea5e6a79c862098970a5a62c12a31a63b22daf8e",
  },
  {
    certContents: {
      serialNumber: "01",
      name: [
        { CN: [{ universalString: "Test" }] },
        { O: [{ utf8String: "Дом" }] },
        { L: [{ ia5String: "EU" }] },
        { C: [{ printableString: "UK" }] },
        { ST: [{ bmpString: "England" }] },
      ],
      subject: [
        { CN: [{ universalString: "Test" }] },
        { O: [{ utf8String: "Дом" }] },
        { L: [{ ia5String: "EU" }] },
        { C: [{ printableString: "UK" }] },
        { ST: [{ bmpString: "England" }] },
      ],
      issuer: [
        { CN: [{ universalString: "Test" }] },
        { O: [{ utf8String: "Дом" }] },
        { L: [{ ia5String: "EU" }] },
        { C: [{ printableString: "UK" }] },
        { ST: [{ bmpString: "England" }] },
      ],
      notBefore: new Date(Date.UTC(2020, 0, 1, 0, 0, 0)), // UTCTime 2020-01-01 00:00:00 UTC
      notAfter: new Date(Date.UTC(2039, 11, 31, 23, 59, 59)),  // UTCTime 2039-12-31 23:59:59 UTC
      signingAlgorithm: alg,
    },

    testDate: new Date(Date.UTC(2020, 0, 1, 0, 0, 1)),   // UTCTime 2020-01-01 00:00:01 UTC
    testAfter: new Date(Date.UTC(2040, 0, 1, 0, 0, 0)),  // UTCTime 2040-01-01 00:00:00 UTC
    testBefore: new Date(Date.UTC(219, 0, 1, 0, 0, 0)),  // UTCTime 2019-01-01 00:00:00 UTC

    certPem:
      `-----BEGIN CERTIFICATE-----
MIIBsDCCAVWgAwIBAgIBATAKBggqhkjOPQQDAjBfMRkwFwYDVQQDHBAAAABUAAAA
ZQAAAHMAAAB0MQ8wDQYDVQQKDAbQlNC+0LwxCzAJBgNVBAcWAkVVMQswCQYDVQQG
EwJVSzEXMBUGA1UECB4OAEUAbgBnAGwAYQBuAGQwHhcNMjAwMTAxMDAwMDAwWhcN
MzkxMjMxMjM1OTU5WjBfMRkwFwYDVQQDHBAAAABUAAAAZQAAAHMAAAB0MQ8wDQYD
VQQKDAbQlNC+0LwxCzAJBgNVBAcWAkVVMQswCQYDVQQGEwJVSzEXMBUGA1UECB4O
AEUAbgBnAGwAYQBuAGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATTQ7lhblKy
W57HwCVLzQOTDxHdf8ZN1QTOk251sg6qUlHPN0Yhr5ukrrhzZ9AdYPBGHnJXUsAf
VvBLnvOwW7+PowIwADAKBggqhkjOPQQDAgNJADBGAiEAlsqFQK35bWk9uqPNu4kS
Bfp5lfmhMuxCDqYsA6LdNHMCIQCni/xiuUKJUszyDs5CU8HSd7E8XtvCH5bSVZPh
dbm0dg==
-----END CERTIFICATE-----`,
    certDer: "308201b030820155a003020102020101300a06082a8648ce3d040302305f3119301706035504031c1000000054000000650000007300000074310f300d060355040a0c06d094d0bed0bc310b3009060355040716024555310b300906035504061302554b3117301506035504081e0e0045006e0067006c0061006e0064301e170d3230303130313030303030305a170d3339313233313233353935395a305f3119301706035504031c1000000054000000650000007300000074310f300d060355040a0c06d094d0bed0bc310b3009060355040716024555310b300906035504061302554b3117301506035504081e0e0045006e0067006c0061006e00643059301306072a8648ce3d020106082a8648ce3d03010703420004d343b9616e52b25b9ec7c0254bcd03930f11dd7fc64dd504ce936e75b20eaa5251cf374621af9ba4aeb87367d01d60f0461e725752c01f56f04b9ef3b05bbf8fa3023000300a06082a8648ce3d040302034900304602210096ca8540adf96d693dbaa3cdbb891205fa7995f9a132ec420ea62c03a2dd3473022100a78bfc62b9428952ccf20ece4253c1d277b13c5edbc21f96d25593e175b9b476",
    privateKey: "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420706a3781c771ef2d067b655335e2eac8aeee1b268800d0e9769c7adeea56b2d1a14403420004d343b9616e52b25b9ec7c0254bcd03930f11dd7fc64dd504ce936e75b20eaa5251cf374621af9ba4aeb87367d01d60f0461e725752c01f56f04b9ef3b05bbf8f",
    publicKey: "3059301306072a8648ce3d020106082a8648ce3d03010703420004d343b9616e52b25b9ec7c0254bcd03930f11dd7fc64dd504ce936e75b20eaa5251cf374621af9ba4aeb87367d01d60f0461e725752c01f56f04b9ef3b05bbf8f",
    signatureDer: "304602210096ca8540adf96d693dbaa3cdbb891205fa7995f9a132ec420ea62c03a2dd3473022100a78bfc62b9428952ccf20ece4253c1d277b13c5edbc21f96d25593e175b9b476",
    signature: "96ca8540adf96d693dbaa3cdbb891205fa7995f9a132ec420ea62c03a2dd3473a78bfc62b9428952ccf20ece4253c1d277b13c5edbc21f96d25593e175b9b476",
  },
];

let testCertSelfSignCounter = 1;
function testCertSelfSign(testEntry: any) {

  it(`Test X509CertificateGenerator.create self-signed #${testCertSelfSignCounter++}`, async () => {

    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    assert.ok(keys.publicKey);
    assert.ok(keys.privateKey);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      keys: keys,

      ...testEntry.certContents,
    });
    const ok = await cert.verify({ date: testEntry.testDate });
    assert.strictEqual(ok, true);
  });
}

let testCertPreSignedCounter = 1;
function testCertPreSigned(testEntry: any) {

  it(`Test X509CertificateGenerator.create pre-signed #${testCertPreSignedCounter++}`, async () => {

    const signature = Buffer.from(testEntry.signature, "hex");
    const extractable = true;
    const publicKeyRaw = Buffer.from(testEntry.publicKey, "hex");
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyRaw,
      alg,
      extractable,
      ["verify"]
    );
    assert.ok(publicKey);

    const cert = await x509.X509CertificateGenerator.create({
      publicKey: publicKey,
      signature: signature,

      ...testEntry.certContents,
    });

    assert.equal(cert.toString("hex"), testEntry.certDer);
    assert.equal(cert.toString("pem"), testEntry.certPem);

    const ok = await cert.verify({ date: testEntry.testDate });
    assert.strictEqual(ok, true, "certificate is not valid");

    const validAfter = await cert.verify({ date: testEntry.testAfter });
    assert.strictEqual(validAfter, false, "certificate is valid after");

    const validBefore = await cert.verify({ date: testEntry.testBefore });
    assert.strictEqual(validBefore, false, "certificate is valid before");

  });
}


describe(path.basename(__filename), () => {
  theTestX509CertificateGeneratorVector.forEach(testEntry => {
    testCertSelfSign(testEntry);
    testCertPreSigned(testEntry);
  });
});