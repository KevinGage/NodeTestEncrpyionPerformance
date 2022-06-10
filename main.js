const nacl = require("tweetnacl");
const util = require("tweetnacl-util");

// Create some data to work with
const mySecretMessage = {
  name: "server1",
  id: "1234567",
  Devices: [
    {
      localId: "123",
      remoteId: "432",
      Checks: [
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
      ],
    },
    {
      localId: "123",
      remoteId: "432",
      Checks: [
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
      ],
    },
    {
      localId: "123",
      remoteId: "432",
      Checks: [
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
      ],
    },
    {
      localId: "123",
      remoteId: "432",
      Checks: [
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
        {
          localId: "34563546",
          remoteId: "234324",
          lastUpdated: "1/1/2022",
          lastResult: "Ok......",
        },
      ],
    },
  ],
};

// Generate new private/public key pair
// Sending servers keys
console.time("generate-sending-server-keys");
const server1KeyPair = nacl.box.keyPair();
console.timeEnd("generate-sending-server-keys");

//Receiving servers keys
console.time("generate-receiving-server-keys");
const server2KeyPair = nacl.box.keyPair();
console.timeEnd("generate-receiving-server-keys");

console.time("encrypting-and-signing-message");
// convert message to int array
const msg = util.decodeUTF8(JSON.stringify(mySecretMessage));

// encrypt and sign data with senders private key and receivers public key
// nacl.box(message, nonce, theirPublicKey, mySecretKey)
const nonce = nacl.randomBytes(nacl.box.nonceLength);
const encryptedAndSigned = nacl.box(
  msg,
  nonce,
  server2KeyPair.publicKey,
  server1KeyPair.secretKey
);

// attach nonce to message
const fullMessage = new Uint8Array(nonce.length + encryptedAndSigned.length);
fullMessage.set(nonce);
fullMessage.set(encryptedAndSigned, nonce.length);

const base64FullMessage = util.encodeBase64(fullMessage);

console.timeEnd("encrypting-and-signing-message");

console.log("encoded encrypted signed message");

console.time("veifying-sig-and-decrypting-message");
// decode
const decoded = util.decodeBase64(base64FullMessage);

const decodedNonce = decoded.slice(0, nacl.box.nonceLength);
const decodedMessage = decoded.slice(
  nacl.box.nonceLength,
  base64FullMessage.length
);

// verify signature and decrypt.
// nacl.box.open(box, nonce, theirPublicKey, mySecretKey)
// returns null if either fails
const decrypted = nacl.box.open(
  decodedMessage,
  decodedNonce,
  server1KeyPair.publicKey,
  server2KeyPair.secretKey
);

// Convert bytes back to UTF8
const base64DecryptedMessage = util.encodeUTF8(decrypted);

// Parse string back to object
const originalData = JSON.parse(base64DecryptedMessage);

console.timeEnd("veifying-sig-and-decrypting-message");

console.log(originalData);
