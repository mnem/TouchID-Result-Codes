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
    
    @IBOutlet weak var secItemCopyMatchingResult: UILabel!
    @IBOutlet weak var secKeyRawSignResult: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        secItemCopyMatchingResult.text = ""
        secKeyRawSignResult.text = ""
        
        storeInKeychain()
    }
    
    func deleteExistingItemInKeychain() {
        let query :[CFString : Any] = [kSecClass : kSecClassGenericPassword,
                                       kSecAttrService : service,
                                       kSecAttrAccount: account]
        let status = SecItemDelete(query as CFDictionary)
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
    
    @IBAction func handleSecKeyRawSignTapped(_ sender: Any) {
    }
    
}

