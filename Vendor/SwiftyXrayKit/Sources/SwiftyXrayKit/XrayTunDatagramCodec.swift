import Darwin
import Foundation

/// Encodes the packet format consumed by Xray's Darwin TUN implementation.
/// Each datagram is one complete packet: a four-byte big-endian address-family
/// header followed by one IPv4 or IPv6 packet.
public enum XrayTunDatagramCodec {
    public static let headerLength = 4
    public static let maximumDatagramLength = headerLength + 40 + Int(UInt16.max)

    public static func encode(packet: Data, protocolNumber: NSNumber) -> Data? {
        let family = protocolNumber.uint32Value
        guard family == UInt32(AF_INET) || family == UInt32(AF_INET6),
              expectedPacketLength(packet, family: family) == packet.count else {
            return nil
        }

        var frame = Data(capacity: headerLength + packet.count)
        frame.append(UInt8(truncatingIfNeeded: family >> 24))
        frame.append(UInt8(truncatingIfNeeded: family >> 16))
        frame.append(UInt8(truncatingIfNeeded: family >> 8))
        frame.append(UInt8(truncatingIfNeeded: family))
        frame.append(packet)
        return frame
    }

    public static func decode(_ frame: Data) -> (packet: Data, protocolNumber: NSNumber)? {
        guard frame.count > headerLength else { return nil }
        let family = UInt32(frame[frame.startIndex]) << 24
            | UInt32(frame[frame.startIndex + 1]) << 16
            | UInt32(frame[frame.startIndex + 2]) << 8
            | UInt32(frame[frame.startIndex + 3])
        guard family == UInt32(AF_INET) || family == UInt32(AF_INET6) else { return nil }

        let packet = Data(frame.dropFirst(headerLength))
        guard expectedPacketLength(packet, family: family) == packet.count else { return nil }
        return (packet, NSNumber(value: family))
    }

    private static func expectedPacketLength(_ packet: Data, family: UInt32) -> Int? {
        if family == UInt32(AF_INET) {
            guard packet.count >= 20, packet[packet.startIndex] >> 4 == 4 else { return nil }
            let headerLength = Int(packet[packet.startIndex] & 0x0F) * 4
            let totalLength = Int(packet[packet.startIndex + 2]) << 8
                | Int(packet[packet.startIndex + 3])
            guard headerLength >= 20, totalLength >= headerLength else { return nil }
            return totalLength
        }

        guard packet.count >= 40, packet[packet.startIndex] >> 4 == 6 else { return nil }
        let payloadLength = Int(packet[packet.startIndex + 4]) << 8
            | Int(packet[packet.startIndex + 5])
        return 40 + payloadLength
    }
}
