/*
    Verify.m
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

#import "Verify.h"
#import "PromptWindowController.h"

@implementation Verify

- (id)initWithMechanism:(MechanismRecord *)inMechanism {
    
    if ([super init]) {
        _mechanism = (MechanismRecord *)inMechanism;
    }
    return self;
}

- (void)run {
    
    NSLog(@"VerifyAuth:MechanismInvoke:Verify:run [+] ");
    
    // Make sure the login user is a real user. Apple has a number of helper users
    // that will "login" through the system.login.console mechs.
    uid_t uid = [self getUID];
    if (uid < 501) {
        return;
    }
    
    // Get the pin that was set by the MachinePIN mechanism
    NSString *pin = [self getPIN];
    
    // Create an instance of the PromptWindowController
    PromptWindowController *promptWindowController = [[PromptWindowController alloc] init];
    [promptWindowController setMechanism:_mechanism];
    
    // If the PIN we received from the inter-mechanism context data is not nil, set the
    // @property pin of the promptWindowController instance.
    if (pin) {
        NSLog(@"VerifyAuth:MechanismInvoke:PromptWindowController [+] setPin");
        [promptWindowController setPin:pin];
    }
    
    // Display the PIN Prompt Window. Running as Modal will block the main thread. This will allow
    // the user to input a PIN before we decide to allow or deny the login. The login will either be
    // denied within the promptWindowController instance or we will return from the run method of
    // the verify class. The default "allow login" will be handled back in the
    // AuthorizationPlugin class . If the pin is nil, we still want to display to window. Hitting
    // enter will allow the login.
    [NSApp runModalForWindow:[promptWindowController window]];
    
#pragma mark Display PromptWindowController
    
}

- (NSString *)getPIN {
    
    // Setup method variables
    NSString *pin;
    const AuthorizationValue *value;
    
    // This NSString will be used as the domain for the inter-mechanism context data
    NSString *contextPINDomain = @"com.burginsystems.pin";
    
    // Use the MechanismRecord GetHintValue callback to get the
    // inter-mechanism context data
    NSLog(@"VerifyAuth:MechanismInvoke:Verify [+] Attempting to read %@", contextPINDomain);
    if (_mechanism->fPlugin->fCallbacks->GetHintValue(_mechanism->fEngine,
                                                      [contextPINDomain UTF8String],
                                                      &value) == errAuthorizationSuccess) {
        
        NSData *pinData = [[NSData alloc] initWithBytes:value->data length:value->length];
        id ret = [NSKeyedUnarchiver unarchiveObjectWithData:pinData];
        pin = (NSString *)ret;
        
    } else {
        NSLog(@"VerifyAuth:MechanismInvoke:Verify [!] Failed to read %@", contextPINDomain);
    }
    
    return pin;
}

- (uid_t)getUID {
    
    // Setup method variables
    const AuthorizationValue *value;
    AuthorizationContextFlags flags;
    uid_t uid = (uid_t) -2;
    
    // Use the MechanismRecord GetHintValue callback to get the
    // inter-mechanism context data
    if (_mechanism->fPlugin->fCallbacks->GetContextValue(_mechanism->fEngine,
                                                         "uid",
                                                         &flags,
                                                         &value) == errAuthorizationSuccess) {
        if (value->length == sizeof(uid_t)) {
            uid = *(const uid_t *) value->data;
        }
    }
    
    return uid;
    
}

@end
