//
//  Authentication.swift
//  StosSign
//
//  Created by Stossy11 on 18/12/2025.
//
//  PATCHED (untested): port of the AltSign change "Handle 2FA codes that Apple sends on its own".
//  Search for "// CHANGED" to see every modification.
//

import Foundation
import StosSign_API
import StosSign_Common
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public typealias AppleAPISession = StosSign_API.AppleAPISession
public typealias AppleAPIError = StosSign_API.AppleAPIError

public final class Authentication {
    public init() { }
    
    public static let dateFormatter = ISO8601DateFormatter()
    
    // CHANGED: small helpers ------------------------------------------------------------
    
    /// Same data, but with a different client info string (used for the SMS / macOS client info override).
    private static func applyingClientInfo(_ clientInfo: String?, to data: AnisetteData) -> AnisetteData {
        return AnisetteData(
            machineID: data.machineID,
            oneTimePassword: data.oneTimePassword,
            localUserID: data.localUserID,
            routingInfo: data.routingInfo,
            deviceUniqueIdentifier: data.deviceUniqueIdentifier,
            deviceSerialNumber: data.deviceSerialNumber,
            deviceDescription: clientInfo ?? data.deviceDescription,
            date: data.date,
            locale: data.locale,
            timeZone: data.timeZone
        )
    }
    
    /// Apple rejects one-time passwords that were already used, so ask for fresh anisette data when a refresh handler exists.
    private static func refreshedAnisetteData(
        _ current: AnisetteData,
        using handler: (() async throws -> AnisetteData)?
    ) async throws -> AnisetteData {
        guard let handler = handler else { return current }
        return try await handler()
    }
    
    /// Optional: drop locale keywords such as "@rg=skzzzz". Apple's 2FA endpoints can answer HTTP 500 when they are present.
    private static func normalizedLocaleIdentifier(_ identifier: String) -> String {
        return String(identifier.prefix { $0 != "@" })
    }
    
    private static func makeClientDictionary(anisetteData: AnisetteData) -> [String: Any] {
        let locale = normalizedLocaleIdentifier(Locale.current.identifier)
        return [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "loc": locale,
            "X-Apple-Locale": locale,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "PST"
        ]
    }
    
    // -----------------------------------------------------------------------------------
    
    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        smsClientInfo: String? = nil,
        verificationHandler: ((@escaping (String?) -> Void) async -> Void)? = nil,
        anisetteDataRefreshHandler: (() async throws -> AnisetteData)? = nil // CHANGED: new, optional, last so existing callers keep working
    ) async throws -> (Account, AppleAPISession) {
        let sanitizedAppleID = unsanitizedAppleID.lowercased()
        let macOSClientInfo = applyingClientInfo(smsClientInfo, to: anisetteData) // CHANGED: uses helper, same result as before
        
        // CHANGED: refresh closure that keeps the client info override
        var refreshMacOSClientInfo: (() async throws -> AnisetteData)? = nil
        if let handler = anisetteDataRefreshHandler {
            refreshMacOSClientInfo = {
                return Authentication.applyingClientInfo(smsClientInfo, to: try await handler())
            }
        }
        
        print(anisetteData.deviceDescription)
        print(macOSClientInfo.deviceDescription)
        
        let clientDictionary = makeClientDictionary(anisetteData: anisetteData) // CHANGED: moved into helper
        
        let context = GSAContext(username: sanitizedAppleID, password: password)
        guard let publicKey = context.start() else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        let initialParameters: [String: Any] = [
            "A2k": publicKey,
            "cpd": clientDictionary,
            "ps": ["s2k", "s2k_fo"],
            "o": "init",
            "u": sanitizedAppleID
        ]
        
        let responseDictionary = try await sendAuthenticationRequest(
            parameters: initialParameters,
            anisetteData: anisetteData
        )
        
        guard let c = responseDictionary["c"] as? String,
              let salt = responseDictionary["s"] as? Data,
              let iterations = responseDictionary["i"] as? Int,
              let serverPublicKey = responseDictionary["B"] as? Data
        else {
            throw URLError(.badServerResponse)
        }
        
        context.salt = salt
        context.serverPublicKey = serverPublicKey
        
        let sp = responseDictionary["sp"] as? String
        let isHexadecimal = (sp == "s2k_fo")
        
        guard let verificationMessage = context.makeVerificationMessage(
            iterations: iterations,
            isHexadecimal: isHexadecimal
        ) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        let verificationParameters: [String: Any] = [
            "c": c,
            "cpd": clientDictionary,
            "M1": verificationMessage,
            "o": "complete",
            "u": sanitizedAppleID
        ]
        
        let verificationResponse = try await sendAuthenticationRequest(
            parameters: verificationParameters,
            anisetteData: anisetteData
        )
        
        guard let serverVerificationMessage = verificationResponse["M2"] as? Data,
              let serverDictionary = verificationResponse["spd"] as? Data,
              let statusDictionary = verificationResponse["Status"] as? [String: Any]
        else {
            throw URLError(.badServerResponse)
        }
        
        guard context.verifyServerVerificationMessage(serverVerificationMessage) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let decryptedData = serverDictionary.decryptedCBC(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let decryptedDictionary = try PropertyListSerialization.propertyList(
            from: decryptedData,
            format: nil
        ) as? [String: Any],
              let dsid = decryptedDictionary["adsid"] as? String,
              let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
        else {
            throw URLError(.badServerResponse)
        }
        
        context.dsid = dsid
        
        // CHANGED: since October 2026 Apple often sends the code to trusted devices on its own.
        // It then answers with hsc 409 and no "au" value instead of "trustedDeviceSecondaryAuth".
        let authType = statusDictionary["au"] as? String
        let statusCode = statusDictionary["hsc"] as? Int
        let isCodeAlreadySent = (authType ?? "").isEmpty && statusCode == 409
        let effectiveAuthType: String? = isCodeAlreadySent ? "trustedDeviceSecondaryAuth" : authType
        
        switch effectiveAuthType {
        case "trustedDeviceSecondaryAuth":
            guard let verificationHandler = verificationHandler else {
                throw AppleAPIError.requiresTwoFactorAuthentication
            }
            
            try await requestTrustedDeviceTwoFactorCode(
                dsid: dsid,
                idmsToken: idmsToken,
                anisetteData: macOSClientInfo,
                isCodeAlreadySent: isCodeAlreadySent, // CHANGED
                anisetteDataRefresh: refreshMacOSClientInfo, // CHANGED
                verificationHandler: verificationHandler
            )
            
            // CHANGED: the first one-time password was already used, so sign in again with a fresh one
            let freshAnisetteData = try await refreshedAnisetteData(anisetteData, using: anisetteDataRefreshHandler)
            
            return try await authenticate(
                appleID: unsanitizedAppleID,
                password: password,
                anisetteData: freshAnisetteData,
                smsClientInfo: smsClientInfo,
                verificationHandler: verificationHandler,
                anisetteDataRefreshHandler: anisetteDataRefreshHandler
            )
            
        case "secondaryAuth":
            guard let verificationHandler = verificationHandler else {
                throw AppleAPIError.requiresTwoFactorAuthentication
            }
            
            try await requestSMSTwoFactorCode(
                dsid: dsid,
                idmsToken: idmsToken,
                anisetteData: macOSClientInfo,
                verificationHandler: verificationHandler
            )
            
            // CHANGED: fresh one-time password for the second sign-in
            let freshAnisetteData = try await refreshedAnisetteData(anisetteData, using: anisetteDataRefreshHandler)
            
            return try await authenticate(
                appleID: unsanitizedAppleID,
                password: password,
                anisetteData: freshAnisetteData,
                smsClientInfo: smsClientInfo,
                verificationHandler: verificationHandler,
                anisetteDataRefreshHandler: anisetteDataRefreshHandler
            )
            
        default:
            guard let sessionKey = decryptedDictionary["sk"] as? Data,
                  let c = decryptedDictionary["c"] as? Data
            else {
                throw URLError(.badServerResponse)
            }
            
            context.sessionKey = sessionKey
            
            let app = "com.apple.gs.xcode.auth"
            guard let checksum = context.makeChecksum(appName: app) else {
                throw AppleAPIError.authenticationHandshakeFailed
            }
            
            // CHANGED: fresh one-time password for the app token request (no-op without a refresh handler)
            let tokenAnisetteData = try await refreshedAnisetteData(anisetteData, using: anisetteDataRefreshHandler)
            
            let tokenParameters: [String: Any] = [
                "app": [app],
                "c": c,
                "checksum": checksum,
                "cpd": makeClientDictionary(anisetteData: tokenAnisetteData), // CHANGED
                "o": "apptokens",
                "t": idmsToken,
                "u": dsid
            ]
            
            
            let token = try await fetchAuthToken(
                app: app,
                parameters: tokenParameters,
                context: context,
                anisetteData: tokenAnisetteData // CHANGED
            )
            
            let session = AppleAPISession(
                dsid: dsid,
                authToken: token,
                anisetteData: tokenAnisetteData // CHANGED
            )
            
            let account = try await AppleAPI.shared.fetchAccount(session: session)
            return (account, session)
        }
    }
    
    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        smsClientInfo: String? = nil,
        verificationHandler: ((@escaping (String?) -> Void) -> Void)? = nil,
        anisetteDataRefreshHandler: (() async throws -> AnisetteData)? = nil, // CHANGED: new, optional
        completionHandler: @escaping (Account?, AppleAPISession?, Error?) -> Void
    ) {
        Task {
            do {
                let success = try await authenticate(
                    appleID: unsanitizedAppleID,
                    password: password,
                    anisetteData: anisetteData,
                    smsClientInfo: smsClientInfo,
                    verificationHandler: { veri in
                        verificationHandler?(veri)
                    },
                    anisetteDataRefreshHandler: anisetteDataRefreshHandler // CHANGED
                )
                
                completionHandler(success.0, success.1, nil)
            } catch {
                completionHandler(nil, nil, error)
            }
        }
    }
    

    public static func sendAuthenticationRequest(
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData
    ) async throws -> [String: Any] {
        guard let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2") else {
            throw AppleAPIError.unknown
        }
        
        let parameters: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": requestParameters
        ]
        
        var httpHeaders = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/808.1.4",
            "Connection": "close"
        ]
        
        let bodyData = try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )
        
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        let (data, _) = try await AppleAPI.shared.session.data(for: request)
        
        guard let responseDictionary = try PropertyListSerialization.propertyList(
            from: data,
            format: nil
        ) as? [String: Any],
              let dictionary = responseDictionary["Response"] as? [String: Any],
              let status = dictionary["Status"] as? [String: Any]
        else {
            throw URLError(.badServerResponse)
        }
        
        let errorCode = status["ec"] as? Int ?? 0
        guard errorCode == 0 else {
            switch errorCode {
            case -20101, -22406:
                throw AppleAPIError.incorrectCredentials
            case -22421:
                throw AppleAPIError.invalidAnisetteData
            case -20209:
                throw AppleAPIError.accountLocked
            default:
                guard let errorDescription = status["em"] as? String else {
                    throw AppleAPIError.unknown
                }
                
                let localizedDescription = "\(errorDescription) (\(errorCode))"
                throw AppleAPIError.customError(code: errorCode, message: localizedDescription)
            }
        }
        
        return dictionary
    }

    public static func makeTwoFactorCodeRequest(
        url: URL,
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData
    ) -> URLRequest {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = identityToken.data(using: .utf8)?.base64EncodedString() ?? ""
        
        let httpHeaders = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "27.0 (27A5218g)",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-Locale": normalizedLocaleIdentifier(anisetteData.locale.identifier), // CHANGED: optional locale clean-up
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST",
            "Connection": "close"
        ]
        
        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        return request
    }
    
    
    // Private funcs :3

    public static func fetchAuthToken(
        app: String,
        parameters: [String: Any],
        context: GSAContext,
        anisetteData: AnisetteData
    ) async throws -> String {
        let responseDictionary = try await sendAuthenticationRequest(
            parameters: parameters,
            anisetteData: anisetteData
        )
        
        guard let encryptedToken = responseDictionary["et"] as? Data else {
            throw URLError(.badServerResponse)
        }
        
        guard let token = encryptedToken.decryptedGCM(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }
        
        guard let tokensDictionary = try PropertyListSerialization.propertyList(
            from: token,
            format: nil
        ) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        
        guard let appTokens = tokensDictionary["t"] as? [String: Any],
              let tokens = appTokens[app] as? [String: Any],
              let authToken = tokens["token"] as? String
        else {
            throw URLError(.badServerResponse)
        }
        
        return authToken
    }

    public static func requestTrustedDeviceTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        isCodeAlreadySent: Bool = false, // CHANGED: new
        anisetteDataRefresh: (() async throws -> AnisetteData)? = nil, // CHANGED: new
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        let verifyURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
        
        // CHANGED: if Apple already pushed a code, do not ask for another one,
        // because that would invalidate the code that was just sent.
        if !isCodeAlreadySent {
            let request = makeTwoFactorCodeRequest(
                url: requestURL,
                dsid: dsid,
                idmsToken: idmsToken,
                anisetteData: anisetteData
            )
            
            let _ = try? await AppleAPI.shared.session.data(for: request)
        }
        
        
        let verificationCode = try await withCheckedThrowingContinuation { continuation in
            Task {
                await verificationHandler { code in
                    continuation.resume(returning: code)
                }
            }
        }
        
        guard let code = verificationCode else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }
        
        // CHANGED: typing the code can take longer than the one-time password stays valid, so use fresh anisette data
        var verifyAnisetteData = anisetteData
        if let refresh = anisetteDataRefresh {
            verifyAnisetteData = try await refresh()
        }
        
        var verifyRequest = makeTwoFactorCodeRequest(
            url: verifyURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: verifyAnisetteData
        )
        verifyRequest.allHTTPHeaderFields?["security-code"] = code
        
        let (data, _) = try await AppleAPI.shared.session.data(for: verifyRequest)
        
        guard let responseDictionary = try PropertyListSerialization.propertyList(
            from: data,
            format: nil
        ) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        
        let errorCode = responseDictionary["ec"] as? Int ?? 0
        guard errorCode == 0 else {
            switch errorCode {
            case -21669:
                throw AppleAPIError.incorrectVerificationCode
            default:
                guard let errorDescription = responseDictionary["em"] as? String else {
                    throw AppleAPIError.unknown
                }
                
                let localizedDescription = errorDescription + " (\(errorCode))"
                throw AppleAPIError.customError(code: errorCode, message: errorDescription)
            }
        }
    }

    public static func requestSMSTwoFactorCode(
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        verificationHandler: @escaping (@escaping (String?) -> Void) async -> Void
    ) async throws {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        let verifyURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!
        
        var request = makeTwoFactorCodeRequest(
            url: requestURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData
        )
        request.httpMethod = "POST"
        
        let bodyXML = [
            "serverInfo": [
                "phoneNumber.id": "1"
            ]
        ] as [String: Any]
        
        let bodyData = try PropertyListSerialization.data(
            fromPropertyList: bodyXML,
            format: .xml,
            options: 0
        )
        request.httpBody = bodyData
        
        let _ = try? await AppleAPI.shared.session.data(for: request)
        
        let verificationCode = try await withCheckedThrowingContinuation { continuation in
            Task {
                await verificationHandler { code in
                    continuation.resume(returning: code)
                }
            }
        }
        
        guard let code = verificationCode else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }
        
        var verifyRequest = makeTwoFactorCodeRequest(
            url: verifyURL,
            dsid: dsid,
            idmsToken: idmsToken,
            anisetteData: anisetteData
        )
        verifyRequest.httpMethod = "POST"
        
        let verifyBodyXML = [
            "securityCode.code": code,
            "serverInfo": [
                "mode": "sms",
                "phoneNumber.id": "1"
            ]
        ] as [String: Any]
        
        let verifyBodyData = try PropertyListSerialization.data(
            fromPropertyList: verifyBodyXML,
            format: .xml,
            options: 0
        )
        verifyRequest.httpBody = verifyBodyData
        
        let (_, response) = try await AppleAPI.shared.session.data(for: verifyRequest)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200,
              httpResponse.allHeaderFields.keys.contains("X-Apple-PE-Token")
        else {
            throw AppleAPIError.incorrectVerificationCode
        }
    }
}
