//
//  ViewController.swift
//  TouchID Result Codes
//
//  Created by David Wagner on 04/07/2017.
//  Copyright © 2017 David Wagner. All rights reserved.
//

import UIKit
import Security

class ViewController: UIViewController {
    
    @IBOutlet weak var secItemCopyMatchingResult: UILabel!
    @IBOutlet weak var secKeyRawSignResult: UILabel!
    @IBOutlet weak var cryptoResult: UILabel!
    @IBOutlet weak var certResult: UILabel!
    @IBOutlet weak var machineLabel: UILabel!
    
    var certData: Data!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        storeInKeychain()
        createSigningKey()
        loadCertData()
    }
    
    func setupUI() {
        secItemCopyMatchingResult.text = ""
        secKeyRawSignResult.text = ""
        cryptoResult.text = ""
        certResult.text = ""

        machineLabel.text = "iOS \(UIDevice.current.systemVersion) - \(UIDevice.trc_machineName())"
    }
    
    func loadCertData() {
        guard let path = Bundle.main.url(forResource: "apple.com", withExtension: "der") else {
            fatalError("Could not find cert")
        }
        certData = try! Data(contentsOf: path)
    }
    
    @IBAction func handleSecItemCopyMatchingTapped(_ sender: UIButton) {
        perfomSecItemCopyMatching()
    }
    
    @IBAction func handleSecKeyRawSignTapped(_ sender: UIButton) {
        #if targetEnvironment(simulator)
        print("Not available on simulator")
        #else
        performSecKeyRawSign()
        #endif
    }
    
    @IBAction func handleCryptoTapped(_ sender: UIButton) {
        #if targetEnvironment(simulator)
        print("Not available on simulator")
        #else
        performCrypto()
        #endif
    }
    
    @IBAction func handleCertTapped(_ sender: UIButton) {
        performCert()
    }
}

// MARK: - TouchID keychain access
extension ViewController {
    private static var service: String { return "mytestservice" }
    private static var account: String { return "my test account name" }
    
    func perfomSecItemCopyMatching() {
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : ViewController.service,
                                       kSecAttrAccount: ViewController.account,
                                       kSecReturnData: true]
        var result :AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        secItemCopyMatchingResult.text = "Result: \(status)"
        
        if let data = result as? Data, let secret = String(data: data, encoding: .utf8) {
            print("Fetched secret: \(secret)")
        } else {
            print("Could not retrieve secret from keychain: \(status)")
        }
    }
    
    func deleteExistingItemInKeychain() {
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : ViewController.service,
                                       kSecAttrAccount: ViewController.account]
        SecItemDelete(query as CFDictionary)
    }
    
    func storeInKeychain() {
        var error :Unmanaged<CFError>?
        let maybeSacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .touchIDCurrentSet, &error);
        
        guard let sacObject = maybeSacObject else {
            fatalError("storeInKeychain error: \(String(describing: error))")
        }
        
        guard let data = "42".data(using: .utf8) else {
            fatalError("storeInKeychain could not create secret data")
        }
        
        deleteExistingItemInKeychain()
        
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : ViewController.service,
                                       kSecAttrAccount: ViewController.account,
                                       kSecAttrAccessControl: sacObject,
                                       kSecValueData : data]
        let status = SecItemAdd(query as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            print("Added secret to keychain")
        default:
            fatalError("storeInKeychain SecItemAdd failed: \(status)")
        }
    }
    
}

extension ViewController {
    func performCert() {
        guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
            print("SecCertificateCreateWithData failed")
            return
        }
        
        let policy = SecPolicyCreateBasicX509()
        
        var trust: SecTrust?
        let result = SecTrustCreateWithCertificates(cert, policy, &trust)
        guard result == errSecSuccess else {
            print("SecTrustCreateWithCertificates failed: \(result)")
            certResult.text = "Failed"
            return
        }
        
        guard let _ = SecTrustCopyPublicKey(trust!) else {
            print("SecTrustCopyPublicKey failed")
            certResult.text = "Failed"
            return
        }
            
        print("Got cert public key OK")
        certResult.text = "OK"
    }
}


// MARK: - TouchID signing
extension ViewController {
    private static var signPrivateLabel: String { return "myprivatekey" }
    
    func performSecKeyRawSign() {
        guard let privateKey = getPrivateKey() else {
            fatalError("handleSecKeyRawSignTapped private key unavailable")
        }
        
        let maybePlainText = "There was a little fishy".data(using: .utf8)
        guard let plainText = maybePlainText else {
            fatalError("handleSecKeyRawSignTapped could not create plainText")
        }
        let digestToSign = self.sha1DigestForData(data: plainText)
        
        let signature = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        var signatureLength = 128
        let status = SecKeyRawSign(privateKey,
                                   .PKCS1,
                                   [UInt8](digestToSign),
                                   Int(CC_SHA1_DIGEST_LENGTH),
                                   signature,
                                   &signatureLength)
        secKeyRawSignResult.text = "Result: \(status)"
        
        print("Signature status: \(status)")
        
        if status == errSecSuccess {
            let sigData = Data(bytes: signature, count: Int(signatureLength))
            let hexBytes = sigData.map { String(format: "%02hhx", $0) }
            print("Signature: \(hexBytes.joined())")
            
            // Validate the signature
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                fatalError("Could not copy public key")
            }
            
            let verifyResult = SecKeyRawVerify(publicKey,
                                               .PKCS1,
                                                [UInt8](digestToSign),
                                               Int(CC_SHA1_DIGEST_LENGTH),
                                               signature,
                                               signatureLength)
            print("Verify result: \(verifyResult == 0 ? "Valid" : String(verifyResult))")
        }
    }
    
    func performCrypto() {
        guard let privateKey = getPrivateKey() else {
            fatalError("handleSecKeyRawSignTapped private key unavailable")
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            fatalError("Could not copy public key")
        }
        
        let plainText = Data("This is totally secret. Shhh! 🦄".utf8)

        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, plainText as CFData, &error) else {
            print("Encryption failed: \(error!.takeRetainedValue() as Error)")
            cryptoResult.text = "Fail"
            return
        }
        
        let hexBytes = (cipherText as Data).map { String(format: "%02hhx", $0) }
        print("Cipher text: \(hexBytes.joined())")
        
        guard let decryptedText = SecKeyCreateDecryptedData(privateKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, cipherText, &error) else {
            print("Decryption failed failed: \(error!.takeRetainedValue() as Error)")
            cryptoResult.text = "Fail"
            return
        }

        let hexBytes2 = (decryptedText as Data).map { String(format: "%02hhx", $0) }
        print("Decrypted text: \(hexBytes2.joined())")

        print("Crypto success! The secret text is: \(String(data: decryptedText as Data, encoding: .utf8)!)")
        
        cryptoResult.text = "OK"
    }
    
    func createSigningKey() {
        #if targetEnvironment(simulator)
        print("Not available on simulator")
        #else
        // private key parameters
        let maybeAccess = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.touchIDCurrentSet, .privateKeyUsage],
            nil)
        guard let access = maybeAccess else {
            fatalError("createSigningKey SecAccessControlCreateWithFlags failed.")
        }
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrLabel as String : ViewController.signPrivateLabel as AnyObject,
            kSecAttrAccessControl as String: access
        ]
        
        // global parameters
        let parameters: [String: AnyObject] = [
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256 as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParams as AnyObject
        ]
        
        var privateKey :SecKey?
        var publicKey :SecKey?
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        if status == errSecSuccess {
            print("Created signing key pair")
        } else {
            fatalError("createSigningKey SecKeyGeneratePair failed: \(status)")
        }
        #endif
    }
    
    func getPrivateKey() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String : ViewController.signPrivateLabel as AnyObject,
            kSecReturnRef as String: true,
            kSecUseOperationPrompt as String: "Psst",
            ] as [String : Any]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
        if status == errSecSuccess {
            return (ref as! SecKey)
        } else {
            return nil
        }
    }
    
    func sha1DigestForData(data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }
}
