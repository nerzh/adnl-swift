# adnl-swift

Create ADNL handshakes, encrypt and decrypt messages, and work with packets and peer keys in Swift. Your application provides the TCP connection and message payloads.

## Quick start: handshake and messages

This example exchanges messages between a client and server in memory, without a network connection.

```swift
import Foundation
import adnl_swift

// Demo seed only. Load your own securely generated 32-byte seed in an application.
let serverSeed = Data(repeating: 0x11, count: 32)
let serverPublicKey = try Ed25519Wrapper.getPublicKey(privateKey: serverSeed)

let client = try ADNLCipher(
    peerPubKey: serverPublicKey.base64EncodedString(),
    mode: .client
)

// Send these bytes first when using a TCP connection.
let handshake = try ADNLHandshake.adnlHandshake(
    keys: client.keys,
    params: client.params,
    address: client.address
)

// On the server, accept the complete handshake using the server's private seed.
let server = try ADNLHandshake.adnlHandshakeAssets(
    handshake,
    secretKey: serverSeed.base64EncodedString()
)

let message = Data("Hello from the client".utf8)
let encryptedMessage = try client.encryptor.adnlSerializeMessage(data: message)
let receivedMessage = try server.decryptor.adnlDeserializeMessage(data: encryptedMessage)
print(String(decoding: receivedMessage, as: UTF8.self))

let reply = Data("Hello from the server".utf8)
let encryptedReply = try server.encryptor.adnlSerializeMessage(data: reply)
let receivedReply = try client.decryptor.adnlDeserializeMessage(data: encryptedReply)
print(String(decoding: receivedReply, as: UTF8.self))
```

Keep the same cipher for the lifetime of each connection and process data in order. For TCP, collect the complete 256-byte handshake before accepting it; keep any following bytes for message processing.

`adnlDeserializeMessage(data:)` expects exactly one complete encrypted packet. Use the next example when TCP reads contain partial packets or several packets together.

## Receiving messages in chunks

Continuing with `client` and `server` from the quick start, send two more messages and simulate two TCP reads:

```swift
var encryptedStream = try client.encryptor.adnlSerializeMessage(data: Data("One".utf8))
encryptedStream.append(
    try client.encryptor.adnlSerializeMessage(data: Data("Two".utf8))
)

var receiveBuffer = Data()
let chunks = [encryptedStream.prefix(7), encryptedStream.dropFirst(7)]

for chunk in chunks {
    receiveBuffer.append(try server.decryptor.update(chunk))

    while let packet = try ADNLPacket.parse(data: receiveBuffer) {
        print(String(decoding: packet.payload, as: UTF8.self))
        receiveBuffer.removeFirst(packet.length)
    }
}
// Prints "One" and "Two".
```

In your TCP reader, retain `receiveBuffer` between reads and feed each received chunk to `update` once. Set an application-specific buffer size limit. Parsing returns `nil` while a packet is incomplete and throws for invalid data.

## Creating and reading packets

Use `ADNLPacket` to work with packets before encryption:

```swift
let packet = ADNLPacket(payload: Data("Example payload".utf8))
let serializedPacket = packet.data

if let parsed = try ADNLPacket.parse(data: serializedPacket) {
    print(String(decoding: parsed.payload, as: UTF8.self))
}
```

`packet.length` tells you how many bytes to remove from a receive buffer. For normal message sending, pass the payload directly to `adnlSerializeMessage(data:)`, which creates the packet for you.

## Keys and addresses

Using `serverPublicKey` from the quick start, generate local keys for a peer and obtain the peer's ADNL address:

```swift
let keys = try ADNLKeys(peerPublicKey: serverPublicKey)
let localPublicKey = keys.public
let sharedSecret = keys.sharedSecret

let address = try ADNLAddress(publicKey: serverPublicKey)
print(address.hash.base64EncodedString())
```

To use your own identity, pass a stored 32-byte private seed. For example, the server identity from the quick start can derive keys for the client:

```swift
let serverKeys = try ADNLKeys(
    privateKey: serverSeed,
    peerPublicKey: client.keys.public
)
```

Key and address initializers accept `Data` or hexadecimal/Base64 strings. Private seeds and public keys must be 32 bytes.

## Encrypting raw data

Use `AESADNL` when you need encryption without packet creation. Create separate encryptor and decryptor instances with matching keys and IVs:

```swift
let params = ADNLAESParams()
let rawEncryptor = try AESADNL(key: params.txKey, iv: params.txNonce, mode: .encryptor)
let rawDecryptor = try AESADNL(key: params.txKey, iv: params.txNonce, mode: .decryptor)

var encryptedData = try rawEncryptor.update(Data("Hello, ".utf8))
encryptedData.append(try rawEncryptor.update(Data("world!".utf8), isLast: true))

let decryptedData = try rawDecryptor.update(encryptedData)
print(String(decoding: decryptedData, as: UTF8.self))
// Prints "Hello, world!".
```

`update` accepts `Data` or `[UInt8]` and preserves the stream position between calls. It returns all processed bytes immediately; `updateFinish()` returns empty `Data`.
