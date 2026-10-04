import Foundation

/// A reliable, ordered, bidirectional byte stream for one ADNL connection.
public protocol ADNLTransport: Sendable {
    func connect(host: String, port: Int) async throws

    /// Write all bytes in order. Completion does not imply receipt by the peer.
    func send(_ data: Data) async throws

    /// Return a nonempty chunk, or nil at EOF. Chunk boundaries are arbitrary.
    func receive() async throws -> Data?

    /// Close permanently and promptly unblock pending connect, send, and receive calls.
    /// Must be safe to call more than once and while another operation is suspended.
    func close() async
}
