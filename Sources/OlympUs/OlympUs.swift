//
//  Copyright © 2022 xcodereleases.com
//  MIT license - see LICENSE.md
//

import Combine
import CommonCrypto
import Crypto
import Foundation
import Prompt
import Rainbow
import SRP
import XCIFoundation

public enum OlympUsError: Error {

    case missingSessionKey
    case signInRequestFailed
    case requestAuthentication
    case requestSmsFailed
    case deviceTrustFailed
    case olympusSessionFailed
    case downloadAuthFailed
    case sessionInvalid
    case invalidHashcash
    case srpInitFailed
    case srpInvalidServerKey
    case srpError(String)

}

public enum OlympUsState: CaseIterable, CustomStringConvertible {
    case validatingExistingSession
    case requestingServiceKey
    case signingIn
    case requestingAuth
    case sendingSecurityCode
    case requestingTrust
    case gettingSession
    case gettingDownloadAuth

    public var description: String {
        switch self {
        case .validatingExistingSession:
            return "Validating existing session"
        case .requestingServiceKey:
            return "Requesting service key"
        case .signingIn:
            return "Signing in with credentials"
        case .requestingAuth:
            return "Requesting authentication"
        case .sendingSecurityCode:
            return "Sending security code"
        case .requestingTrust:
            return "Requesting trust"
        case .gettingSession:
            return "Requesting download session"
        case .gettingDownloadAuth:
            return "Requesting download auth info"
        }
    }
}

public enum ValidationType {
    case securityCode(String)
    case verificationCode(Int, String)
}

private struct SecurityCode: Codable {
    let code: String
}

private struct VerifyPhoneRequest: Codable {
    struct TrustedNumber: Codable {
        let id: Int
    }

    let phoneNumber: VerifyPhoneRequest.TrustedNumber
    var mode = "sms"
    var securityCode: SecurityCode? = nil
}

private struct VerifyTrustedDeviceRequest: Codable {
    let securityCode: SecurityCode
}

extension ValidationType {
    var verificationURL: URL {
        switch self {
        case .securityCode:
            return URL(string: "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode")!
        case .verificationCode:
            return URL(string: "https://idmsa.apple.com/appleauth/auth/verify/phone/securitycode")!
        }
    }

    var body: Data {
        switch self {
        case let .securityCode(code):
            let body = VerifyTrustedDeviceRequest(securityCode: SecurityCode(code: code))
            return try! JSONEncoder().encode(body)
        case let .verificationCode(phoneId, code):
            let body = VerifyPhoneRequest(
                phoneNumber: VerifyPhoneRequest.TrustedNumber(id: phoneId),
                securityCode: SecurityCode(code: code)
            )
            return try! JSONEncoder().encode(body)
        }
    }
}

public class URLSessionDelegateProxy: NSObject, URLSessionDownloadDelegate {
    public private(set) var proxies: [URLSessionDownloadDelegate] = []

    public func add(proxy: URLSessionDownloadDelegate) {
        proxies.append(proxy)
    }

    public func remove(proxy: URLSessionDownloadDelegate) {
        proxies.removeAll { delegate in
            delegate.isEqual(proxy)
        }
    }

    public func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didFinishDownloadingTo location: URL
    ) {
        proxies.forEach { proxy in
            proxy.urlSession(session, downloadTask: downloadTask, didFinishDownloadingTo: location)
        }
    }

    public func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        proxies.forEach { proxy in
            proxy.urlSession?(
                session,
                downloadTask: downloadTask,
                didWriteData: bytesWritten,
                totalBytesWritten: totalBytesWritten,
                totalBytesExpectedToWrite: totalBytesExpectedToWrite
            )
        }
    }

    public func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didResumeAtOffset fileOffset: Int64,
        expectedTotalBytes: Int64
    ) {
        proxies.forEach { proxy in
            proxy.urlSession?(
                session,
                downloadTask: downloadTask,
                didResumeAtOffset: fileOffset,
                expectedTotalBytes: expectedTotalBytes
            )
        }
    }

    public func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        proxies.forEach { proxy in
            proxy.urlSession?(session, didBecomeInvalidWithError: error)
        }
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        proxies.forEach { proxy in
            proxy.urlSession?(session, task: task, didCompleteWithError: error)
        }
    }
}

extension OlympUs.AuthenticationAssets: Codable {}

public class OlympUs {
    private var disposeBag = Set<AnyCancellable>()
    private let logger: Logger

    public private(set) var state: OlympUsState? {
        didSet {
            displayState()
        }
    }

    public let session: URLSession

    public init(logger: Logger, session: URLSession) {
        self.logger = logger
        self.session = session
        restoreCookies()
    }

    private func displayState() {
        guard let state = state, let index = OlympUsState.allCases.firstIndex(of: state) else { return }
        let message = "[\(index)/\(OlympUsState.allCases.count - 1)] \(state.description)"
        logger.log(message, onSameLine: state != OlympUsState.allCases.first!)
    }

    // MARK: - Step 0: request a service key a.k.a. widget key -

    struct ServiceKeyResponse: Codable {
        var authServiceKey: String
    }

    public func storedAuthenticationAssets(for account: String) -> AuthenticationAssets? {
        let item = KeychainPasswordItem(
            service: "xcinfo.session",
            account: account
        )
        do {
            let codedAssets = try item.readData()
            return try JSONDecoder().decode(AuthenticationAssets.self, from: codedAssets)
        } catch {
            return nil
        }
    }

    @discardableResult
    private func storeAuthenticationAssets(assets: AuthenticationAssets, for account: String) -> Bool {
        let item = KeychainPasswordItem(
            service: "xcinfo.session",
            account: account
        )
        do {
            let data = try JSONEncoder().encode(assets)
            try item.saveData(data, overwriteExisting: true)
            return true
        } catch {
            return false
        }
    }

    public func validateSession(for account: String) -> Future<Void, OlympUsError> {
        Future { promise in
            self.state = .validatingExistingSession
            guard let assets = self.storedAuthenticationAssets(for: account) else {
                promise(.failure(.sessionInvalid))
                return
            }
            self.getOlympusSession(assets: assets, for: account)
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        self.logger.verbose("Session invalid. Starting authentication.")
                        promise(.failure(.sessionInvalid))
                    }
                }, receiveValue: { _ in
                    self.logger.verbose("Reusing valid session.")
                    promise(.success(()))
                })
                .store(in: &self.disposeBag)
        }
    }

    private var sessionKeyURL = URL(string: "https://appstoreconnect.apple.com/olympus/v1/app/config")!
    public func getServiceKey(for account: String) -> Future<String, OlympUsError> {
        Future { promise in
            self.state = .requestingServiceKey
            if let serviceKey = self.storedAuthenticationAssets(for: account)?.serviceKey {
                promise(.success(serviceKey))
            } else {
                var components = URLComponents(url: self.sessionKeyURL, resolvingAgainstBaseURL: false)!
                components.queryItems = [URLQueryItem(name: "hostname", value: "itunesconnect.apple.com")]
                self.session
                    .dataTaskPublisher(for: components.url!)
                    .map { $0.data }
                    .decode(type: ServiceKeyResponse.self, decoder: JSONDecoder())
                    .sink(receiveCompletion: { completion in
                        if case .failure = completion {
                            promise(.failure(.missingSessionKey))
                        }
                    }, receiveValue: { response in
                        promise(.success(response.authServiceKey))
                    })
                    .store(in: &self.disposeBag)
            }
        }
    }

    // MARK: - Step 1: sign in (SRP) -

    private enum SRPAuthProtocol: String, Codable {

        case s2k
        case s2k_fo

    }

    private struct SRPInitRequest: Encodable {

        let a: String
        let accountName: String
        let protocols: [SRPAuthProtocol]

    }

    private struct SRPInitResponse: Decodable {

        let iteration: Int
        let salt: String
        let b: String
        let c: String
        let `protocol`: String?

    }

    private struct SRPCompleteRequest: Encodable {

        let accountName: String
        let c: String
        let m1: String
        let m2: String
        let rememberMe: Bool

    }

    private struct SignInResponse: Codable {

        var authType: String?

    }

    private let signInURL = URL(string: "https://idmsa.apple.com/appleauth/auth/signin")!
    private let srpInitURL = URL(string: "https://idmsa.apple.com/appleauth/auth/signin/init")!
    private let srpCompleteURL = URL(string: "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=false")!

    public struct AuthenticationAssets {

        var serviceKey: String?
        var scnt: String?
        var asid: String?
        var authenticationType: String?

    }

    public func signIn(
        accountName: String,
        password: String,
        serviceKey: String
    ) -> Future<AuthenticationAssets, OlympUsError> {
        Future { promise in
            self.state = .signingIn
            self.session.configuration.httpCookieStorage?.removeCookies(since: Date(timeIntervalSinceReferenceDate: 0))

            let srpClient = SRPClient(configuration: SRPConfiguration<SHA256>(.N2048))
            let clientKeys = srpClient.generateKeys()
            let clientPublicKey = clientKeys.public

            self.loadHashcash(accountName: accountName, serviceKey: serviceKey)
                .flatMap { hashcash -> Future<(SRPInitResponse, String), OlympUsError> in
                    self.srpInit(
                        serviceKey: serviceKey,
                        accountName: accountName,
                        clientPublicKey: Data(clientPublicKey.bytes).base64EncodedString()
                    )
                    .map { ($0, hashcash) }
                    .eraseToAnyPublisher()
                    .asFuture()
                }
                .flatMap { initResponse, hashcash -> Future<AuthenticationAssets, OlympUsError> in
                    do {
                        return try self.completeSRPSignIn(
                            srpClient: srpClient,
                            clientKeys: clientKeys,
                            clientPublicKey: clientPublicKey,
                            initResponse: initResponse,
                            accountName: accountName,
                            password: password,
                            serviceKey: serviceKey,
                            hashcash: hashcash
                        )
                    } catch let error as OlympUsError {
                        return Future { $0(.failure(error)) }
                    } catch {
                        return Future { $0(.failure(.srpError(error.localizedDescription))) }
                    }
                }
                .sink(receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        promise(.failure(error))
                    }
                }, receiveValue: { assets in
                    promise(.success(assets))
                })
                .store(in: &self.disposeBag)
        }
    }

    // MARK: - SRP Helpers -

    private func loadHashcash(accountName: String, serviceKey: String) -> Future<String, OlympUsError> {
        Future { promise in
            var request = URLRequest(url: self.signInURL)
            request.httpMethod = "GET"
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue(serviceKey, forHTTPHeaderField: "X-Apple-Widget-Key")

            self.session
                .dataTaskPublisher(for: request)
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.invalidHashcash))
                    }
                }, receiveValue: { output in
                    guard
                        let httpResponse = output.response as? HTTPURLResponse,
                        let bitString = httpResponse.allHeaderFields["X-Apple-HC-Bits"] as? String,
                        let bits = UInt(bitString),
                        let challenge = httpResponse.allHeaderFields["X-Apple-HC-Challenge"] as? String,
                        let hashcash = Hashcash().mint(resource: challenge, bits: bits)
                    else {
                        promise(.failure(.invalidHashcash))
                        return
                    }
                    promise(.success(hashcash))
                })
                .store(in: &self.disposeBag)
        }
    }

    private func srpInit(
        serviceKey: String,
        accountName: String,
        clientPublicKey: String
    ) -> Future<SRPInitResponse, OlympUsError> {
        Future { promise in
            var request = URLRequest(url: self.srpInitURL)
            request.httpMethod = "POST"
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
            request.addValue(serviceKey, forHTTPHeaderField: "X-Apple-Widget-Key")

            let body = SRPInitRequest(
                a: clientPublicKey,
                accountName: accountName,
                protocols: [.s2k, .s2k_fo]
            )
            request.httpBody = try? JSONEncoder().encode(body)

            self.session
                .dataTaskPublisher(for: request)
                .map { $0.data }
                .decode(type: SRPInitResponse.self, decoder: JSONDecoder())
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.srpInitFailed))
                    }
                }, receiveValue: { response in
                    promise(.success(response))
                })
                .store(in: &self.disposeBag)
        }
    }

    private func completeSRPSignIn(
        srpClient: SRPClient<SHA256>,
        clientKeys: SRPKeyPair,
        clientPublicKey: SRPKey,
        initResponse: SRPInitResponse,
        accountName: String,
        password: String,
        serviceKey: String,
        hashcash: String
    ) throws -> Future<AuthenticationAssets, OlympUsError> {
        guard let decodedB = Data(base64Encoded: initResponse.b) else {
            throw OlympUsError.srpInvalidServerKey
        }
        guard let decodedSalt = Data(base64Encoded: initResponse.salt) else {
            throw OlympUsError.srpInvalidServerKey
        }

        let isFallback = initResponse.protocol == "s2k_fo"
        guard let encryptedPassword = pbkdf2(
            password: password,
            saltData: decodedSalt,
            keyByteCount: 32,
            prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            rounds: initResponse.iteration,
            skipPreHash: isFallback
        ) else {
            throw OlympUsError.srpError("PBKDF2 key derivation failed")
        }

        let sharedSecret = try srpClient.calculateSharedSecret(
            password: encryptedPassword,
            salt: [UInt8](decodedSalt),
            clientKeys: clientKeys,
            serverPublicKey: SRPKey([UInt8](decodedB))
        )

        let m1 = srpClient.calculateClientProof(
            username: accountName,
            salt: [UInt8](decodedSalt),
            clientPublicKey: clientPublicKey,
            serverPublicKey: SRPKey([UInt8](decodedB)),
            sharedSecret: SRPKey(sharedSecret.bytes)
        )

        let m2 = srpClient.calculateServerProof(
            clientPublicKey: clientPublicKey,
            clientProof: m1,
            sharedSecret: SRPKey([UInt8](sharedSecret.bytes))
        )

        return srpComplete(
            serviceKey: serviceKey,
            hashcash: hashcash,
            accountName: accountName,
            c: initResponse.c,
            m1: Data(m1).base64EncodedString(),
            m2: Data(m2).base64EncodedString()
        )
    }

    private func srpComplete(
        serviceKey: String,
        hashcash: String,
        accountName: String,
        c: String,
        m1: String,
        m2: String
    ) -> Future<AuthenticationAssets, OlympUsError> {
        Future { promise in
            var request = URLRequest(url: self.srpCompleteURL)
            request.httpMethod = "POST"
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
            request.addValue(serviceKey, forHTTPHeaderField: "X-Apple-Widget-Key")
            request.addValue(hashcash, forHTTPHeaderField: "X-Apple-HC")

            let body = SRPCompleteRequest(
                accountName: accountName,
                c: c,
                m1: m1,
                m2: m2,
                rememberMe: false
            )
            request.httpBody = try? JSONEncoder().encode(body)

            var authenticationAssets = AuthenticationAssets(serviceKey: serviceKey)

            self.session
                .dataTaskPublisher(for: request)
                .tryMap { output -> AuthenticationAssets in
                    guard let httpResponse = output.response as? HTTPURLResponse else {
                        throw OlympUsError.signInRequestFailed
                    }

                    if let scnt = httpResponse.allHeaderFields["scnt"] as? String,
                       let asid = httpResponse.allHeaderFields["X-Apple-ID-Session-Id"] as? String
                    {
                        authenticationAssets.scnt = scnt
                        authenticationAssets.asid = asid
                    }

                    switch httpResponse.statusCode {
                    case 200, 409:
                        if let signInResponse = try? JSONDecoder().decode(SignInResponse.self, from: output.data) {
                            authenticationAssets.authenticationType = signInResponse.authType
                        }
                        return authenticationAssets
                    case 401:
                        throw OlympUsError.signInRequestFailed
                    default:
                        throw OlympUsError.srpError("Unexpected sign-in response: HTTP \(httpResponse.statusCode)")
                    }
                }
                .sink(receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        promise(.failure(error as? OlympUsError ?? .signInRequestFailed))
                    }
                }, receiveValue: { assets in
                    promise(.success(assets))
                })
                .store(in: &self.disposeBag)
        }
    }

    private func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    private func pbkdf2(
        password: String,
        saltData: Data,
        keyByteCount: Int,
        prf: CCPseudoRandomAlgorithm,
        rounds: Int,
        skipPreHash: Bool = false
    ) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        let hashedPasswordData = skipPreHash ? passwordData : sha256(data: passwordData)

        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            let keyBuffer = derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return saltData.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return hashedPasswordData.withUnsafeBytes { hashedPasswordBytes -> Int32 in
                    let passwordBuffer = hashedPasswordBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer,
                        hashedPasswordData.count,
                        saltBuffer,
                        saltData.count,
                        prf,
                        UInt32(rounds),
                        keyBuffer,
                        derivedCount
                    )
                }
            }
        }
        return derivationStatus == kCCSuccess ? derivedKeyData : nil
    }

    // MARK: - Step 2: request auth -

    private let authURL = URL(string: "https://idmsa.apple.com/appleauth/auth")!
    private let verifyPhoneURL = URL(string: "https://idmsa.apple.com/appleauth/auth/verify/phone")!
    public struct TrustedNumber: Codable {
        let numberWithDialCode: String
        let pushMode: String
        let obfuscatedNumber: String
        let id: Int
    }

    public struct CodeDescription: Codable {
        let length: Int
        let tooManyCodesSent: Bool
        let tooManyCodesValidated: Bool
        let securityCodeLocked: Bool
    }

    private struct RequestAuthResponse: Codable {
        let trustedPhoneNumbers: [TrustedNumber]
        let securityCode: CodeDescription
    }

    enum HttpMethod: String {
        case get = "GET"
        case post = "POST"
        case put = "PUT"
    }

    public func requestAuthentication(assets: AuthenticationAssets) -> Future<ValidationType, OlympUsError> {
        Future { promise in
            self.state = .requestingAuth
            self.session
                .dataTaskPublisher(for: self.request(forURL: self.authURL, assets: assets, method: .post))
                .map { $0.data }
                .decode(type: RequestAuthResponse.self, decoder: JSONDecoder())
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.requestAuthentication))
                    }
                }, receiveValue: { response in
                    let requiredCodeLength = response.securityCode.length
                    self.logger.log("\nTwo-factor authentication is enabled for your account.")
                    self.logger
                        .log(
                            "Please enter a \(requiredCodeLength) digit verification code generated on one of your trusted devices."
                        )
                    self.logger.log("Type '\("sms".magenta)' to receive a verification code on a trusted phone number.")
                    let input = ask("Apple ID Verification Code: ", type: String.self) { settings in
                        settings.addInvalidCase("Invalide code length") { value in
                            value != "sms" && requiredCodeLength != value.count
                        }
                    }
                    switch input {
                    case "sms":
                        let phoneId = choose("Please choose your trusted device: ", type: Int.self) { settings in
                            for number in response.trustedPhoneNumbers {
                                settings.addChoice(number.numberWithDialCode) { number.id }
                            }
                        }
                        var request = self.request(forURL: self.verifyPhoneURL, assets: assets, method: .put)
                        let body = VerifyPhoneRequest(phoneNumber: VerifyPhoneRequest.TrustedNumber(id: phoneId))
                        let data = try? JSONEncoder().encode(body)
                        request.httpBody = data

                        self.session
                            .dataTaskPublisher(for: request)
                            .sink(receiveCompletion: { completion in
                                if case .failure = completion {
                                    promise(.failure(.requestSmsFailed))
                                }
                            }, receiveValue: { _ in
                                let smsCode = ask(
                                    "Please enter the received verification code:",
                                    type: String.self
                                ) { settings in
                                    settings.addInvalidCase("Invalid code length") { value in
                                        requiredCodeLength != value.count
                                    }
                                }
                                self.logger.log("\n")
                                promise(.success(.verificationCode(phoneId, smsCode)))
                            })
                            .store(in: &self.disposeBag)
                    default:
                        self.logger.log("\n")
                        promise(.success(.securityCode(input)))
                    }
                })
                .store(in: &self.disposeBag)
        }
    }

//    MARK: - send security code -

    public func sendSecurityCode(
        validationType: ValidationType,
        assets: AuthenticationAssets
    ) -> Future<Int, OlympUsError> {
        Future { promise in
            self.state = .sendingSecurityCode
            var request = self.request(forURL: validationType.verificationURL, assets: assets, method: .post)
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.httpBody = validationType.body
            self.session
                .dataTaskPublisher(for: request)
                .map {
                    $0.response
                }
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.deviceTrustFailed))
                    }
                }, receiveValue: { response in
                    if let httpResponse = response as? HTTPURLResponse {
                        promise(.success(httpResponse.statusCode))
                    } else {
                        promise(.failure(.deviceTrustFailed))
                    }
                })
                .store(in: &self.disposeBag)
        }
    }

//    MARK: - requesting trust -

    private let trustURL = URL(string: "https://idmsa.apple.com/appleauth/auth/2sv/trust")!
    public func requestTrust(assets: AuthenticationAssets) -> Future<[HTTPCookie], OlympUsError> {
        Future { promise in
            self.state = .requestingTrust
            let request = self.request(forURL: self.trustURL, assets: assets, method: .get)
            self.session
                .dataTaskPublisher(for: request)
                .map { $0.response }
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.deviceTrustFailed))
                    }
                }, receiveValue: { response in
                    if let httpResponse = response as? HTTPURLResponse {
                        let responseCookies = HTTPCookie.cookies(
                            withResponseHeaderFields: httpResponse.allHeaderFields as! [String: String],
                            for: self.trustURL
                        )
                        promise(.success(responseCookies))
                    } else {
                        promise(.failure(.deviceTrustFailed))
                    }
                })
                .store(in: &self.disposeBag)
        }
    }

//    MARK: - get session from Olympus -

    private let olympusSessionURL = URL(string: "https://appstoreconnect.apple.com/olympus/v1/session")!
    public func getOlympusSession(assets: AuthenticationAssets, for account: String) -> Future<Void, OlympUsError> {
        Future { promise in
            self.state = .gettingSession
            let request = self.request(forURL: self.olympusSessionURL, assets: assets, method: .get)
            self.session
                .dataTaskPublisher(for: request)
                .map { $0.response }
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.olympusSessionFailed))
                    }
                }, receiveValue: { response in
                    if self.handle(response: response) {
                        self.storeAuthenticationAssets(assets: assets, for: account)
                        promise(.success(()))
                    } else {
                        promise(.failure(.olympusSessionFailed))
                    }
                })
                .store(in: &self.disposeBag)
        }
    }

    private func handle(response: URLResponse) -> Bool {
        guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
            return false
        }

        let allHeaderFields = response.allHeaderFields

        guard let originalCookies = allHeaderFields["Set-Cookie"] as? String else {
            return true
        }

        let regex = try! NSRegularExpression(pattern: #"(?<!Expires=\w{3}),"#, options: [])
        var cookieDict: [String: String] = [:]
        var startIndex = originalCookies.startIndex
        regex.enumerateMatches(
            in: originalCookies,
            options: [],
            range: NSRange(originalCookies.startIndex..., in: originalCookies)
        ) { result, _, _ in
            guard let nsrange = result?.range,
                  let range = Range<String.Index>(nsrange, in: originalCookies) else { return }
            let match = originalCookies[startIndex ..< range.lowerBound]
            startIndex = range.upperBound
            let keyValuePair = match.split(separator: "=")
            let key = String(keyValuePair[0]).trimmingCharacters(in: .whitespaces)
            cookieDict[key] = String(keyValuePair.dropFirst().joined(separator: "="))
        }

        let lastMatch = originalCookies[startIndex...]
        let keyValuePair = lastMatch.split(separator: "=")
        let key = String(keyValuePair[0]).trimmingCharacters(in: .whitespaces)
        cookieDict[key] = String(keyValuePair.dropFirst().joined(separator: "="))

        let appleURL = URL(string: "apple.com")!
        let cookies = cookieDict
            .flatMap {
                HTTPCookie.cookies(withResponseHeaderFields: ["Set-Cookie": "\($0.key)=\($0.value)"], for: appleURL)
            }

        cookies.forEach {
            self.session.configuration.httpCookieStorage?.setCookie($0)
        }

        storeCookies()
        return true
    }

    private let downloadAuthURL =
        URL(string: "https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action")!
    public func getDownloadAuth(assets: AuthenticationAssets) -> Future<Void, OlympUsError> {
        Future { promise in
            self.state = .gettingDownloadAuth
            let request = self.request(forURL: self.downloadAuthURL, assets: assets, method: .post)
            self.session
                .dataTaskPublisher(for: request)
                .sink(receiveCompletion: { completion in
                    if case .failure = completion {
                        promise(.failure(.downloadAuthFailed))
                    }
                }, receiveValue: { output in
                    if self.handle(response: output.response),
                       self.session.configuration.httpCookieStorage?.cookies?
                       .contains(where: { $0.name == "ADCDownloadAuth" }) == true
                    {
                        promise(.success(()))
                    } else {
                        promise(.failure(.downloadAuthFailed))
                    }
                })
                .store(in: &self.disposeBag)
        }
    }

    public func cleanup() {
        removeDownloadSessionInfo()
        removeCookies()
    }

    private func removeDownloadSessionInfo() {
        do {
            let items = try KeychainPasswordItem.passwordItems(forService: "xcinfo.session")
            if !items.isEmpty {
                for item in items {
                    try item.deleteItem()
                }
                logger.success("Deleted Apple developer portal session info from keychain.")
            } else {
                logger.log("No Apple developer portal session info was stored.")
            }
        } catch {
            logger
                .error(
                    "Error deleting Keychain entries. Please open Keychain Access.app and remove items named 'xcinfo.session'."
                )
        }
    }

//    MARK: - Helpers -

    private func request(forURL url: URL, assets: AuthenticationAssets, method: HttpMethod = .get) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        request.addValue(assets.serviceKey!, forHTTPHeaderField: "X-Apple-Widget-Key")
        request.addValue(assets.scnt!, forHTTPHeaderField: "scnt")
        request.addValue(assets.asid!, forHTTPHeaderField: "X-Apple-ID-Session-Id")
        if [HttpMethod.post, .put].contains(method) {
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
        }
        return request
    }
}

//    MARK: - Cookies -

extension OlympUs {
    private func storeCookies() {
        guard let cookies = session.configuration.httpCookieStorage?.cookies else { return }

        let userDefaults = UserDefaults.standard
        let cookiesArray = cookies.compactMap { $0.properties }
        userDefaults.set(cookiesArray, forKey: "cookies")
    }

    private func restoreCookies() {
        guard let cookieStorage = session.configuration.httpCookieStorage else { return }

        let userDefaults = UserDefaults.standard

        if let cookies = userDefaults.array(forKey: "cookies") as? [[HTTPCookiePropertyKey: Any]] {
            for cookieProperties in cookies {
                if let cookie = HTTPCookie(properties: cookieProperties) {
                    cookieStorage.setCookie(cookie)
                }
            }
        }
    }

    private func removeCookies() {
        UserDefaults.standard.removeObject(forKey: "cookies")
    }

}

extension Publisher {

    func asFuture() -> Future<Output, Failure> {
        var cancellable: AnyCancellable?
        return Future { promise in
            cancellable = self.sink(
                receiveCompletion: { completion in
                    if case let .failure(error) = completion {
                        promise(.failure(error))
                    }
                    _ = cancellable
                },
                receiveValue: { value in
                    promise(.success(value))
                }
            )
        }
    }

}
