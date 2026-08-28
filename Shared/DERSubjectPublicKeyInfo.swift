import Foundation
import Security

enum DERError: Error {
    case malformed
    case unexpectedTag
}

private struct DERTLV {
    let tag: UInt8
    let fullData: Data
    let valueData: Data
}

private struct DERReader {
    let data: Data
    var offset = 0

    mutating func peekTag() throws -> UInt8 {
        guard offset < data.count else { throw DERError.malformed }
        return data[offset]
    }

    mutating func read(expectedTag: UInt8? = nil) throws -> DERTLV {
        let start = offset
        guard offset + 2 <= data.count else { throw DERError.malformed }

        let tag = data[offset]
        offset += 1
        if let expectedTag, tag != expectedTag { throw DERError.unexpectedTag }

        let firstLength = Int(data[offset])
        offset += 1
        let valueLength: Int
        if firstLength & 0x80 == 0 {
            valueLength = firstLength
        } else {
            let byteCount = firstLength & 0x7f
            guard byteCount > 0, byteCount <= 4, offset + byteCount <= data.count else {
                throw DERError.malformed
            }
            var length = 0
            for _ in 0..<byteCount {
                length = (length << 8) | Int(data[offset])
                offset += 1
            }
            valueLength = length
        }

        let valueStart = offset
        let valueEnd = valueStart + valueLength
        guard valueLength >= 0, valueEnd <= data.count else { throw DERError.malformed }
        offset = valueEnd
        return DERTLV(
            tag: tag,
            fullData: data.subdata(in: start..<valueEnd),
            valueData: data.subdata(in: valueStart..<valueEnd)
        )
    }
}

enum DERSubjectPublicKeyInfo {
    static func extract(from certificate: SecCertificate) throws -> Data {
        let certificateData = SecCertificateCopyData(certificate) as Data
        var certificateReader = DERReader(data: certificateData)
        let certificateSequence = try certificateReader.read(expectedTag: 0x30)

        var sequenceReader = DERReader(data: certificateSequence.valueData)
        let tbsCertificate = try sequenceReader.read(expectedTag: 0x30)
        var tbsReader = DERReader(data: tbsCertificate.valueData)

        if try tbsReader.peekTag() == 0xa0 {
            _ = try tbsReader.read()
        }
        for _ in 0..<5 {
            _ = try tbsReader.read()
        }
        return try tbsReader.read(expectedTag: 0x30).fullData
    }
}

