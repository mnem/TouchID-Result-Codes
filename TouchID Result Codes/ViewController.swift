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
    
    private let service = "mytestservice"
    private let account = "my test account name"
    
    private let signApplicationTag = "touchid-result-codes-test"
    private let signPrivateLabel = "private"
    private let signPublicLabel = "public"
    
    @IBOutlet weak var secItemCopyMatchingResult: UILabel!
    @IBOutlet weak var secKeyRawSignResult: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        secItemCopyMatchingResult.text = ""
        secKeyRawSignResult.text = ""
        
        storeInKeychain()
        createSigningKey()
    }
    
    func getPrivateKey() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
//            kSecAttrApplicationTag as String: signApplicationTag as AnyObject,
            kSecAttrLabel as String : signPrivateLabel as AnyObject,
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
    
    func createSigningKey() {
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
            kSecAttrLabel as String : signPrivateLabel as AnyObject,
//            kSecAttrApplicationTag as String: signApplicationTag as AnyObject,
            kSecAttrAccessControl as String: access
        ]
        
        // public key parameters
//        let publicKeyParams: [String: AnyObject] = [
//            kSecAttrIsPermanent as String: false as AnyObject,
//            kSecAttrLabel as String : signPublicLabel as AnyObject,
//            kSecAttrApplicationTag as String: signApplicationTag as AnyObject
//        ]
        
        // global parameters
        let parameters: [String: AnyObject] = [
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256 as AnyObject,
//            kSecPublicKeyAttrs as String: publicKeyParams as AnyObject,
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
    }
    
    func deleteExistingItemInKeychain() {
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : service,
                                       kSecAttrAccount: account]
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
                     kSecAttrService : service,
                     kSecAttrAccount: account,
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
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func handleSecItemCopyMatchingTapped(_ sender: UIButton) {
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : service,
                                       kSecAttrAccount: account,
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
    
    @IBAction func handleSecKeyRawSignTapped(_ sender: UIButton) {
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
        }
    }
    
    func sha1DigestForData(data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0, CC_LONG(data.count), &digest)
        }
        return Data(bytes: digest)
    }
}

