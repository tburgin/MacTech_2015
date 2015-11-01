/*
    MachinePIN.swift
    VerifyAuthPlugin

    Copyright 2015 Thomas Burgin.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

import Foundation
import Security

class MachinePIN: NSObject {
    
    // Define a pointer to the MechanismRecord. This will be used to get and set
    // all the inter-mechanism data. It is also used to allow or deny the login.
    private var mechanism:UnsafePointer<MechanismRecord>
    
    // This NSString will be used as the domain for the inter-mechanism context data
    private let contextPINDomain : NSString = "com.burginsystems.pin"
    
    //
    // init the class with a MechanismRecord
    init(mechanism:UnsafePointer<MechanismRecord>) {
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] initWithMechanismRecord");
        self.mechanism = mechanism
    }
    
    //
    // This is the only public function. It will be called from the
    // ObjC AuthorizationPlugin class
    func run() {
        
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:run:[+]");
        
        // Get the PIN and set the hint
        let ret : Bool = setHintValue(getPIN())
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:run:[+] setHintValue %@",
            ret ? "Success" : "Fail");
        
        // Allow to login. End of mechanism
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:run:[+] allowLogin");
        allowLogin()
        
    }
    
    //
    // This is how we set the inter-mechanism context data
    private func setHintValue(pin : NSString?) -> Bool {
        
        // Try and unwrap the optional NSString
        guard let pin = pin
            else {
                NSLog("VerifyAuth:MechanismInvoke:MachinePIN:setHintValue [+] Failed to unwrap inPin");
                return false
            }
        
        // Try and unwrap the optional NSData returned from archivedDataWithRootObject
        // This can be decoded on the other side with unarchiveObjectWithData
        guard let data : NSData = NSKeyedArchiver.archivedDataWithRootObject(pin)
            else {
                NSLog("VerifyAuth:MechanismInvoke:MachinePIN:setHintValue [+] Failed to unwrap archivedDataWithRootObject");
                return false
            }
        
        // Fill the AuthorizationValue struct with our data
        var value = AuthorizationValue(length: data.length,
            data: UnsafeMutablePointer<Void>(data.bytes))
        
        // Use the MechanismRecord SetHintValue callback to set the
        // inter-mechanism context data
        let err : OSStatus = self.mechanism.memory.fPlugin.memory.fCallbacks.memory.SetHintValue(
            mechanism.memory.fEngine, contextPINDomain.UTF8String, &value)
        
        return (err == errSecSuccess) ? true : false
        
    }
    
    //
    // Get the PIN from the System.keychain
    private func getPIN() -> NSString? {
        
        var err : OSStatus
        
        let serviceName = "com.burginsystems.pin"
        let accountName = "machine"
        
        var passLen : UInt32 = 0
        var buffer : UnsafeMutablePointer<Void> = nil
        var pin : NSString?
        
        var keycahin : SecKeychain?
        let path = ("/Library/Keychains/System.keychain" as NSString).UTF8String
        
        err = SecKeychainOpen(path, &keycahin)
        if (err != errSecSuccess) {
            return pin
        }
        
        err = SecKeychainFindGenericPassword(keycahin,
            UInt32(serviceName.characters.count),
            (serviceName as NSString).UTF8String,
            UInt32(accountName.characters.count),
            (accountName as NSString).UTF8String,
            &passLen, &buffer, nil)
        
        if (err != errSecSuccess) {
            return pin
        }
        
        pin = NSString.init(bytes: buffer, length: Int(passLen), encoding: NSUTF8StringEncoding)!
        return pin
        
    }
    
    //
    // Allow the login. End of the mechanism
    private func allowLogin() -> OSStatus {
        
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] Done. Thanks and have a lovely day.");
        var err: OSStatus = noErr
        err = self.mechanism
            .memory.fPlugin
            .memory.fCallbacks
            .memory.SetResult(mechanism.memory.fEngine, AuthorizationResult.Allow)
        NSLog("VerifyAuth:MechanismInvoke:MachinePIN:[+] [%d]", Int(err));
        return err
        
    }
    
    
}
