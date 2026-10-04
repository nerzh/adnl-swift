# adnl-swift

Swift building blocks for **ADNL over TCP**: peer keys and addresses, the initial handshake, AES-CTR session encryption, and packet serialization.

The library operates on `Foundation.Data`. Your application supplies the TCP connection and the application-level payload encoding. It does not open sockets, discover peers, serialize TON TL queries, or implement a complete lite client, UDP ADNL, or RLDP.

## Contents

- [Requirements and installation](#requirements-and-installation)
- [Quick start: client and server in memory](#quick-start-client-and-server-in-memory)
- [Connecting to a real peer](#connecting-to-a-real-peer)
- [Keys and addresses](#keys-and-addresses)
- [Handshake](#handshake)
- [Session parameters and cipher directions](#session-parameters-and-cipher-directions)
- [Packets](#packets)
- [Receiving a TCP stream](#receiving-a-tcp-stream)
- [Low-level AES](#low-level-aes)
- [Error handling](#error-handling)
- [API reference](#api-reference)
- [Troubleshooting and current limitations](#troubleshooting-and-current-limitations)
- [Building](#building)

## Requirements and installation

The package requires Swift **6.2+** and declares **macOS 11+** and **iOS 13+**. SwiftExtensionsPack is pinned to **2.9.0** on all platforms. Swift 5 language mode is retained for this library.

The SwiftPM product is named **`adnl-swift`**, while the Swift module is imported with an underscore:

```swift
import Foundation
import adnl_swift
```

### Clone the package

Clone this repository into your workspace:

```bash
git clone https://github.com/nerzh/adnl-swift.git
```

The manifest uses remote dependencies and requires no machine-specific path changes.

### Add the local package to a SwiftPM application

With `adnl-swift` next to your application directory, an executable application's `Package.swift` can look like this:

```swift
// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ADNLDemo",
    platforms: [.macOS(.v11)],
    dependencies: [
        .package(path: "../adnl-swift")
    ],
    targets: [
        .executableTarget(
            name: "ADNLDemo",
            dependencies: [
                .product(name: "adnl-swift", package: "adnl-swift")
            ]
        )
    ]
)
```

Place the quick-start example below in `Sources/ADNLDemo/main.swift`, then run `swift run` from the application directory.

For Xcode, add the checkout as a **local package dependency** and link the `adnl-swift` product to your app target.

### Remote integration

The repository can be referenced by branch:

```swift
.package(url: "https://github.com/nerzh/adnl-swift.git", branch: "master")
```

A remote integration uses the published repository state, not local changes. Until these fixes are published, use this local checkout. For reproducible remote builds, pin a revision containing the fixes.

### Dependencies

| Package | Requirement in this repository | Purpose |
| --- | --- | --- |
| `nerzh/swift-extensions-pack` | Exactly `2.9.0` | Stateful AES-CTR, Ed25519, SHA-256, random bytes, encodings, byte order, and error helpers |

SwiftExtensionsPack brings `bytehubio/ed25519` and `apple/swift-crypto` transitively. The resolved versions are recorded in `Package.resolved`.

## Quick start: client and server in memory

This complete example creates a client handshake, accepts it on the server, sends an empty acknowledgement, and exchanges application data in both directions. It uses only the library and Foundation; no network connection is needed.

The fixed server seed is **only for this demonstration**. A real server should load its own securely generated 32-byte Ed25519 seed. The client creates fresh key material and session parameters automatically.

```swift
import Foundation
import adnl_swift

// Use a fixed server identity only for this local demonstration.
let serverSeed = Data(repeating: 0x11, count: 32)
let serverSecret = serverSeed.base64EncodedString()
let serverPublicKey = try Ed25519Wrapper.getPublicKey(privateKey: serverSeed)

// A client needs the server's raw Ed25519 public key, encoded as hex or Base64.
let client = try ADNLCipher(
    peerPubKey: serverPublicKey.base64EncodedString(),
    mode: .client
)

// Send these 256 bytes directly to the server before any encrypted packets.
let handshake = try ADNLHandshake.adnlHandshake(
    keys: client.keys,
    params: client.params,
    address: client.address
)
assert(handshake.count == 256)

// Accept the handshake and restore the same parameters with server directions.
let server = try ADNLHandshake.adnlHandshakeAssets(
    handshake,
    secretKey: serverSecret
)

// The server can acknowledge the handshake with an encrypted empty packet.
let acknowledgement = try server.encryptor.adnlSerializeMessage(data: Data())
let acknowledgedPayload = try client.decryptor.adnlDeserializeMessage(
    data: acknowledgement
)
assert(acknowledgedPayload.isEmpty)

let request = Data("Hello from the client".utf8)
let encryptedRequest = try client.encryptor.adnlSerializeMessage(data: request)
let receivedRequest = try server.decryptor.adnlDeserializeMessage(
    data: encryptedRequest
)
assert(receivedRequest == request)
print("Server received:", String(decoding: receivedRequest, as: UTF8.self))

let reply = Data("Hello from the server".utf8)
let encryptedReply = try server.encryptor.adnlSerializeMessage(data: reply)
let receivedReply = try client.decryptor.adnlDeserializeMessage(
    data: encryptedReply
)
assert(receivedReply == reply)
print("Client received:", String(decoding: receivedReply, as: UTF8.self))
```

Expected output:

```text
Server received: Hello from the client
Client received: Hello from the server
```

Here, each decryption call receives exactly one complete encrypted packet. Real TCP reads do not preserve these boundaries. Use the [stream receiver](#receiving-a-tcp-stream) below for socket input.

The text payloads demonstrate transport only. A TON lite server expects correctly serialized protocol messages, not these strings.

## Connecting to a real peer

Your transport integration should follow this sequence:

1. Obtain the peer's host, TCP port, and **32-byte Ed25519 public key** from your application's configuration.
2. Open a TCP connection with your chosen networking implementation.
3. Create one `ADNLCipher(peerPubKey:mode: .client)` for that connection.
4. Build `ADNLHandshake.adnlHandshake(...)` and write all 256 bytes directly to the connection. The handshake already encrypts its session parameters; do not wrap it in an `ADNLPacket` or encrypt it with the session encryptor.
5. Pass subsequent incoming bytes to a stream receiver that owns this cipher's decryptor. An empty payload can represent the handshake acknowledgement or a keepalive; it is not an application reply.
6. Encode your application message, call `client.encryptor.adnlSerializeMessage(data:)`, and write the resulting bytes in order.
7. Decode the received packet payload using your application protocol.

On the server, accumulate **exactly the first 256 bytes** before calling `adnlHandshakeAssets(_:secretKey:)`. If a socket read also contains later bytes, retain that suffix and feed it to the returned cipher's stream receiver. The library neither reads from nor writes to your socket, and it does not automatically send an acknowledgement.

Handle partial writes, timeouts, disconnections, and application request/response matching in your transport layer. If a write fails after encryption, close the connection rather than encrypting the same payload again on the existing session: the encryptor has already advanced.

Keep each connection's encryption and decryption operations ordered, for example on a serial queue or inside an actor. Create a fresh cipher and handshake when reconnecting.

## Keys and addresses

### Input formats

String initializers use `SwiftExtensionsPack` to decode hexadecimal or Base64 text. The underlying bytes have these meanings:

| Input | Required bytes | Meaning |
| --- | --- | --- |
| `privateKey`, `serverSecret`, `secretKey` | 32 | Raw Ed25519 private seed |
| `peerPublicKey`, `peerPubKey`, address `publicKey` | 32 | Raw Ed25519 public key |
| `paramsData` | 160 | Serialized AES session parameters |

The private input is not a mnemonic, PEM document, or 64-byte expanded private key. A peer public key is not its IP address, ADNL address hash, or TON wallet address.

All public key and seed entry points validate the decoded 32-byte length and throw a descriptive error for short or oversized inputs.

### Derive an ADNL address

```swift
import Foundation
import adnl_swift

// Demonstration identity; replace it with a real peer's public key.
let demoSeed = Data(repeating: 0x22, count: 32)
let peerPublicKey = try Ed25519Wrapper.getPublicKey(privateKey: demoSeed)

let address = try ADNLAddress(publicKey: peerPublicKey)
let sameAddress = try ADNLAddress(
    publicKey: peerPublicKey.base64EncodedString()
)

assert(address.hash == sameAddress.hash)
assert(address.hash.count == 32)
print("ADNL address (Base64):", address.hash.base64EncodedString())
```

`ADNLAddress` accepts `Data`, `[UInt8]`, or a string. Its `hash` is computed as:

```text
SHA256([0xc6, 0xb4, 0x13, 0x48] + publicKey)
```

### Generate local key material or supply a seed

Continuing with `peerPublicKey` from the previous example:

```swift
// Generate a new local private seed internally.
let ephemeralKeys = try ADNLKeys(peerPublicKey: peerPublicKey)
assert(ephemeralKeys.public.count == 32)
assert(ephemeralKeys.sharedSecret.count == 32)

// Use a caller-managed seed when the local identity must be reproducible.
let localSeed = Data(repeating: 0x33, count: 32) // Demonstration only.
let stableKeys = try ADNLKeys(
    privateKey: localSeed,
    peerPublicKey: peerPublicKey
)
assert(stableKeys.peerPublic == peerPublicKey)
```

`ADNLKeys` exposes `public`, `peerPublic`, and `sharedSecret`. It does not expose the private seed generated by its convenience initializer. If you need to preserve an identity, generate and store the seed in your application, then pass it explicitly.

Keep private seeds, shared secrets, and session parameters out of application logs.

## Handshake

`ADNLHandshake.adnlHandshake(keys:params:address:)` creates a 256-byte request:

| Offset | Size | Contents |
| --- | --- | --- |
| `0..<32` | 32 bytes | Receiver's ADNL address hash |
| `32..<64` | 32 bytes | Sender's Ed25519 public key |
| `64..<96` | 32 bytes | SHA-256 of the plaintext session parameters |
| `96..<256` | 160 bytes | Encrypted session parameters |

With `handshake` from the quick start, inspect its fields using:

```swift
let request = try ADNLHandshake.adnlParseHandshake(handshake)
assert(request.shortLocalNodeId.count == 32)
assert(request.senderPubKey.count == 32)
assert(request.checkSum.count == 32)
assert(request.encryptedData.count == 160)
```

`adnlParseHandshake(_:)` validates the total length and splits the fields. It does **not** decrypt the parameters or authenticate the request.

For server-side acceptance, use `adnlHandshakeAssets(_:secretKey:)`, as in the quick start. This method:

1. Parses the request and derives key material from the server seed and sender public key.
2. Checks that the receiver address matches the server identity.
3. Decrypts the session parameters and verifies their SHA-256 checksum.
4. Returns an `ADNLCipher` configured in `.server` mode.

The handshake uses its own temporary AES cipher. Creating it does not consume bytes from the session encryptor or decryptor.

## Session parameters and cipher directions

`ADNLAESParams()` generates 160 random bytes. You can also restore parameters with `try ADNLAESParams(data)` or `try ADNLAESParams(encodedString)`; these initializers require exactly 160 decoded bytes.

| Property | Byte range | Size |
| --- | --- | --- |
| `rxKey` | `0..<32` | 32 bytes |
| `txKey` | `32..<64` | 32 bytes |
| `rxNonce` | `64..<80` | 16 bytes |
| `txNonce` | `80..<96` | 16 bytes |
| `padding` | `96..<160` | 64 bytes |
| `hash` | SHA-256 of all `bytes` | 32 bytes |

The `rx` and `tx` names describe the **client's** perspective:

| Mode | Outgoing encryption | Incoming decryption |
| --- | --- | --- |
| `.client` | `txKey` / `txNonce` | `rxKey` / `rxNonce` |
| `.server` | `rxKey` / `rxNonce` | `txKey` / `txNonce` |

`ADNLCipher` offers three initializers:

```swift
// Fresh local key material and fresh session parameters.
let automatic = try ADNLCipher(
    peerPubKey: peerPublicKey.base64EncodedString(),
    mode: .client
)

// Caller-managed local seed and fresh session parameters.
let explicitIdentity = try ADNLCipher(
    serverSecret: localSeed.base64EncodedString(),
    peerPubKey: peerPublicKey.base64EncodedString(),
    mode: .client
)

// Caller-supplied seed and parameters, for controlled setup or fixtures.
let params = ADNLAESParams()
let explicitParameters = try ADNLCipher(
    serverSecret: localSeed.base64EncodedString(),
    peerPubKey: peerPublicKey.base64EncodedString(),
    paramsData: Data(params.bytes).base64EncodedString(),
    mode: .client
)
```

These examples use `peerPublicKey` and `localSeed` from [Keys and addresses](#keys-and-addresses). Despite its name, `serverSecret` means the **local private seed** and is also used in client mode.

For a server accepting an actual connection, obtain the parameters from `adnlHandshakeAssets`. Constructing independent client and server ciphers with fresh parameters will produce unrelated streams.

An `ADNLCipher` is a struct, but its encryptor and decryptor are class instances. Copying the struct shares those mutable cipher objects; it does not create a separate session or a snapshot you can rewind.

## Packets

`ADNLPacket` represents a plaintext ADNL TCP packet. It adds framing and a checksum, but does not encrypt the payload.

```swift
import Foundation
import adnl_swift

let payload = Data("Example payload".utf8)
let packet = ADNLPacket(payload: payload)
let serialized = packet.data

assert(packet.nonce.count == 32)
assert(packet.hash.count == 32)
assert(packet.length == payload.count + 68)
assert(serialized.count == packet.length)

if let parsed = try ADNLPacket.parse(data: serialized) {
    assert(parsed.payload == payload)
    assert(parsed.nonce == packet.nonce)
}

// An empty payload still produces a complete 68-byte packet.
let emptyPacket = ADNLPacket(payload: Data())
assert(emptyPacket.length == 68)

// A prefix of a valid packet is incomplete, so parsing returns nil.
let incomplete = try ADNLPacket.parse(data: Data(serialized.prefix(10)))
assert(incomplete == nil)
```

### Wire layout before session encryption

| Field | Size | Meaning |
| --- | --- | --- |
| Length | 4 bytes | Little-endian `UInt32`: `payload.count + 64` |
| Nonce | 32 bytes | Random per-packet bytes |
| Payload | Variable | Application data |
| Hash | 32 bytes | `SHA256(nonce + payload)` |

`packet.size` contains the four encoded length bytes. `packet.length` is the total byte count, including that four-byte field. The whole serialized packet, including its length, is encrypted on the connection.

The default initializer generates a 32-byte nonce and remains nonthrowing. An explicit `nonce:` is useful for fixtures: use `try ADNLPacket(payload: payload, nonce: nonce)`. This initializer throws unless the nonce is exactly 32 bytes.

### Convenience methods versus raw updates

| Method | Input | Output |
| --- | --- | --- |
| `encryptor.adnlSerializeMessage(data:)` | Application payload | Encrypted framed packet |
| `encryptor.update(_:)` | Already prepared plaintext bytes | Encrypted bytes |
| `decryptor.adnlDeserializeMessage(data:)` | One complete encrypted packet | Application payload |
| `decryptor.update(_:)` | Next bytes of the encrypted stream | Plaintext stream bytes |

Do not pass `packet.data` to `adnlSerializeMessage`: that would frame an already framed packet. To encrypt `packet.data`, use `encryptor.update(packet.data)`.

`ADNLPacket.parse(data:)` returns the first complete packet and does not return or retain any trailing bytes. It returns `nil` for incomplete valid framing and throws when the advertised body is shorter than 64 bytes or the checksum does not match. Packet and handshake parsers accept `Data` slices with nonzero indices. Applications should enforce their own maximum packet size.

## Receiving a TCP stream

A TCP read may contain part of one packet or several packets together. `adnlDeserializeMessage(data:)` does not maintain a framing buffer: it decrypts the supplied bytes, tries to parse one packet, and throws if that packet is incomplete. Trailing packets are not preserved.

For socket input, decrypt each chunk **once**, retain the plaintext, validate its length prefix, and extract all complete packets. The following application-side helper uses the existing `ADNLDecryptor.update` and `ADNLPacket.parse` APIs. It is example code, not a type exported by the library.

```swift
import Foundation
import adnl_swift

enum ADNLStreamReadError: Error {
    case invalidLength(UInt32)
    case unexpectedIncompletePacket
}

final class ADNLStreamReader {
    private let decryptor: ADNLDecryptor
    private var plaintext = Data()

    // Application policy: at most 1 MiB for nonce + payload + checksum.
    private let maximumBodyLength: UInt32 = 1_048_576

    init(decryptor: ADNLDecryptor) {
        self.decryptor = decryptor
    }

    func receive(_ encryptedChunk: Data) throws -> [Data] {
        plaintext.append(try decryptor.update(encryptedChunk))
        var payloads: [Data] = []

        while plaintext.count >= 4 {
            let bodyLength = UInt32(plaintext[0])
                | (UInt32(plaintext[1]) << 8)
                | (UInt32(plaintext[2]) << 16)
                | (UInt32(plaintext[3]) << 24)

            guard bodyLength >= 64, bodyLength <= maximumBodyLength else {
                throw ADNLStreamReadError.invalidLength(bodyLength)
            }

            let frameLength = 4 + Int(bodyLength)
            guard plaintext.count >= frameLength else {
                break
            }

            let frame = Data(plaintext.prefix(frameLength))
            guard let packet = try ADNLPacket.parse(data: frame) else {
                throw ADNLStreamReadError.unexpectedIncompletePacket
            }

            payloads.append(packet.payload)

            // Rebase Data indices before inspecting the next length prefix.
            plaintext = Data(plaintext.dropFirst(frameLength))
        }

        return payloads
    }
}
```

With `client` and `server` from the quick start, the following simulates a fragmented TCP read followed by a read containing the remainder and another packet:

```swift
let reader = ADNLStreamReader(decryptor: client.decryptor)

var wireBytes = try server.encryptor.adnlSerializeMessage(data: Data("One".utf8))
wireBytes.append(
    try server.encryptor.adnlSerializeMessage(data: Data("Two".utf8))
)

let firstPayloads = try reader.receive(Data(wireBytes.prefix(7)))
assert(firstPayloads.isEmpty)

let remainingPayloads = try reader.receive(Data(wireBytes.dropFirst(7)))
assert(remainingPayloads == [Data("One".utf8), Data("Two".utf8)])
```

Keep one reader for the lifetime of each incoming stream. After handing a decryptor to it, route all subsequent incoming ciphertext through that reader. Reprocessing a chunk or also calling `adnlDeserializeMessage` on it advances the AES state twice.

The 1 MiB bound is an example application policy, not a limit enforced by the library. Bound socket read sizes and apply timeouts as well. If decoding throws, close the connection and discard its cipher and buffered bytes. If the connection ends with an incomplete frame, treat that frame as truncated.

The helper returns empty payloads too, so your application can distinguish transport acknowledgements/keepalives from application messages.

## Low-level AES

`AESADNL` wraps `SEPCrypto.AESCTR` from SwiftExtensionsPack with no padding. Use it when you need raw encryption without ADNL packet framing:

```swift
import Foundation
import adnl_swift

let aesParams = ADNLAESParams()
let encryptor = try AESADNL(
    key: aesParams.txKey,
    iv: aesParams.txNonce,
    mode: .encryptor
)
let decryptor = try AESADNL(
    key: aesParams.txKey,
    iv: aesParams.txNonce,
    mode: .decryptor
)

let plaintext = Data("Raw AES-CTR example".utf8)
var ciphertext = try encryptor.update(plaintext)
ciphertext.append(try encryptor.updateFinish())

var recovered = try decryptor.update(ciphertext)
recovered.append(try decryptor.updateFinish())
assert(recovered == plaintext)
```

`update` accepts `Data` or `[UInt8]`. The optional `isLast` argument and throwing `updateFinish()` signature are retained for compatibility. CTR emits all bytes immediately: `isLast` does not change processing, and `updateFinish()` returns empty `Data` without resetting the stream. Keep the connection's encryptor/decryptor between packets. The public `cipher` property now has type `SEPCrypto.AESCTR`.

Raw AES-CTR does not add a packet checksum or verify message integrity. Prefer the framed packet APIs for ADNL messages.

## Error handling

Public throwing APIs can propagate `ADNLError`, dependency encoding errors, and cryptographic errors. `ADNLError` exposes `title` and `reason`.

```swift
import Foundation
import adnl_swift

do {
    // Deliberately invalid: a handshake must contain exactly 256 bytes.
    _ = try ADNLHandshake.adnlParseHandshake(Data())
} catch let error as ADNLError {
    print(error.title)
    print(error.reason)
} catch {
    print("ADNL operation failed:", error)
}
```

| Situation | Current behavior |
| --- | --- |
| AES parameters are not 160 bytes | Throws `ADNLError` |
| Handshake is not exactly 256 bytes | Throws `ADNLError` |
| Handshake receiver address does not match the server seed | Throws `ADNLError` |
| Decrypted session parameters do not match the handshake checksum | Throws `ADNLError` |
| A complete packet has the wrong hash | Throws `ADNLError` |
| A packet is incomplete | `ADNLPacket.parse` returns `nil` |
| Convenience decryption receives an incomplete packet | Throws after consuming cipher input |
| A string cannot be decoded or a crypto operation fails | May throw a dependency error |

Invalid key lengths, explicit nonce lengths, and undersized packet bodies produce recoverable errors. Incomplete valid packets return `nil`; incomplete handshakes throw because that API expects a complete 256-byte request.

## API reference

| Type | Main API | Role |
| --- | --- | --- |
| `ADNLCipher` | `keys`, `params`, `address`, `encryptor`, `decryptor`; `TCPCipherMode.client` / `.server` | Groups one session's assets |
| `ADNLKeys` | Initializers with a peer public key and optional local seed; `public`, `peerPublic`, `sharedSecret` | Local public key and peer-specific shared secret |
| `ADNLAddress` | `init(publicKey:)`, `publicKey`, `hash` | ADNL peer address derivation |
| `ADNLAESParams` | Random, `Data`, and string initializers; `bytes`, `hash`, directional keys/nonces, `padding` | Session parameter generation and restoration |
| `ADNLHandshake` | `adnlHandshake`, `adnlParseHandshake`, `adnlHandshakeAssets` | Build, inspect, and accept a handshake |
| `ADNLHandshake.HandshakeRequest` | `shortLocalNodeId`, `senderPubKey`, `checkSum`, `encryptedData` | Parsed handshake fields |
| `ADNLPacket` | `init(payload:)`, throwing `init(payload:nonce:)`, `parse(data:)`, `payload`, `nonce`, `hash`, `size`, `data`, `length` | Plaintext packet framing |
| `ADNLEncryptor` | `init(key:iv:)`, `update`, `adnlSerializeMessage` | Stateful outgoing stream |
| `ADNLDecryptor` | `init(key:iv:)`, `update`, `adnlDeserializeMessage` | Stateful incoming stream |
| `AESADNL` | `init(key:iv:mode:)`, `update`, `updateFinish`; `Mode.encryptor` / `.decryptor` | Raw AES-CTR wrapper |
| `Ed25519Wrapper` | `getPublicKey(privateKey:)`, `getSharedKey(privateKey:publicKey:)` | Low-level key operations |
| `ADNLError` | `title`, `reason` | Library error information |

`Ed25519Wrapper` also exposes throwing `convertEd25519ToX25519(ed25519PrivateKey:)` and `edwardsToMontgomery(bytesData:)`. The latter now returns a real 32-byte Montgomery coordinate. Pass the original Edwards public key to `getSharedKey`; its C backend converts internally. Normal integrations can use `ADNLKeys` directly.

The package also exports a debug printing helper, `pe(_:)`; it is not needed for the ADNL workflow.

## Troubleshooting and current limitations

- **SwiftPM reports an unsupported tools version:** use Swift 6.2 or newer, as required by the updated dependency graph.
- **`No such module 'adnl-swift'`:** import `adnl_swift`, and ensure the target depends on the `adnl-swift` product.
- **Handshake address validation fails:** check that the client's peer public key belongs to the server seed passed to `adnlHandshakeAssets`.
- **Packet hash errors:** check cipher directions, session parameters, byte order, and whether any ciphertext was skipped, replayed, or decrypted twice. Retain the same cipher objects throughout a connection.
- **Convenience decryption fails on socket reads:** use a persistent stream receiver. Socket read boundaries are not ADNL packet boundaries.
- **The first received payload is empty:** handle it as transport-level data; an empty ADNL packet is valid.
- **Two copies of `ADNLCipher` interfere:** the copies share reference-type encryptors/decryptors. Create a new session instead of copying a cipher to obtain independent state.

The library currently has no built-in transport, stream framing buffer, application packet-size limit, or synchronization for concurrent cipher access. Integrations need to supply those surrounding behaviors where required.

## Building

```bash
swift package resolve
swift build
swift test
```

The package builds a library, so `swift run` must be used in a consumer executable such as `ADNLDemo`, not in this repository.

### Example verification

The regression suite was compiled and run with Swift 6.4 on macOS arm64 using the dependencies in `Package.resolved`. Its 27 tests exercise in-memory handshakes and bidirectional exchanges, malformed packets, key/nonce/IV lengths, Data slices, invalid coordinates and zero shared secrets, checksum rejection, fragmented/coalesced input, AES-CTR continuity, finalization compatibility, and counter exhaustion. Ed25519/conversion/shared-secret fixtures were independently checked with libsodium 1.0.20; AES-CTR uses NIST reference vectors for all three key lengths and a final-counter vector checked with OpenSSL 3.5.4. No live TON peer, funds transfer, or iOS/Linux runtime test is involved.

For protocol context, the [TON reference TCP connection implementation](https://github.com/ton-blockchain/ton/blob/master/adnl/adnl-ext-connection.cpp) shows stream framing and the client/server cipher directions. The examples above document this repository's public Swift API and should be validated against the peers your application will use.
