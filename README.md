# adnl-swift

An ADNL client with a built-in TCP transport powered by Apple SwiftNIO, for Linux and Apple platforms.

## Send and receive a message

Use the peer's host, port, and public key. `payload` is your encoded ADNL application message.

```swift
import Foundation
import adnl_swift

let client = try ADNLClient(
    host: host,
    port: port,
    peerPublicKey: publicKey
)

try await client.connect()

do {
    try await client.send(payload)
    if let response = try await client.receive() {
        // Decode or handle the response bytes here.
        print(response)
    }
    await client.close()
} catch {
    await client.close()
    throw error
}
```

The public key can be `Data`, a hexadecimal string, or a Base64 string. `connect()` completes the handshake and consumes the server's acknowledgement. `send` and `receive` handle encryption and packets for you.

## Receive multiple messages

Keep the connected client and call `receive()` for each complete message. TCP reads may split or combine packets; the client handles this automatically.

```swift
while let message = try await client.receive() {
    // Handle one complete payload. Empty payloads are also returned.
    print(message)
}
await client.close()
```

`receive()` returns `nil` when the peer closes cleanly, and throws for invalid or truncated packets. One send and one receive can run at the same time; keep successive sends and successive receives sequential. Closing or cancelling an active operation closes the connection. Create a new client to reconnect.

## Additional

### Connection options

The default connection timeout is 10 seconds and includes the handshake. The default maximum payload size is 16 MiB minus 64 bytes. You can override both:

```swift
let client = try ADNLClient(
    host: host,
    port: port,
    peerPublicKey: publicKey,
    connectionTimeout: 15,
    maximumPayloadSize: 1024 * 1024
)
```

### Use your own transport

You can implement your own TCP transport, or adapt an existing connection, by conforming to `ADNLTransport`. Then pass your implementation to the client:

```swift
let client = try ADNLClient(
    host: host,
    port: port,
    peerPublicKey: publicKey,
    transport: MyTransport()
)

try await client.connect()
```

Your `MyTransport` implementation must be `Sendable` and provide these methods:

```swift
func connect(host: String, port: Int) async throws
func send(_ data: Data) async throws
func receive() async throws -> Data?
func close() async
```

The transport must preserve byte order and write all bytes passed to `send`. Return a nonempty chunk from `receive`, or `nil` at EOF. `close` must be safe to repeat and promptly unblock pending operations, including a connection attempt. Reading and writing must be able to proceed concurrently.

The transport only moves bytes; the client handles ADNL. A UDP socket cannot directly replace this ordered stream transport.

The lower-level `ADNLCipher`, `ADNLHandshake`, `ADNLPacket`, `ADNLKeys`, `ADNLAddress`, and `AESADNL` APIs remain available for manual integration.
