//
//  Copyright © 2022 xcodereleases.com
//  MIT license - see LICENSE.md
//

import CommonCrypto
import Foundation

struct Hashcash {

    // Apple's variant: no Rand nonce, counter as decimal string. Format: version:bits:date:resource::counter
    func mint(resource: String, bits: UInt = 10, date: String? = nil) -> String? {
        let ver = "1"

        let ts: String
        if let date = date {
            ts = date
        } else {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyMMddHHmmss"
            ts = formatter.string(from: Date())
        }

        let challenge = "\(ver):\(bits):\(ts):\(resource):"

        var counter = 0
        while true {
            guard let digest = "\(challenge):\(counter)".sha1LeadingZeroBits else {
                return nil
            }
            if digest >= bits {
                return "\(challenge):\(counter)"
            }
            counter += 1
        }
    }

}

private extension String {

    var sha1LeadingZeroBits: UInt? {
        let data = Data(utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        let bigEndianValue = digest.withUnsafeBufferPointer {
            ($0.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 1) { $0 })
        }.pointee
        let value = UInt32(bigEndian: bigEndianValue)
        return UInt(value.leadingZeroBitCount)
    }

}
