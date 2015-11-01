/*
    PromptWindowController.h
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

#import <Cocoa/Cocoa.h>
#include <Security/AuthorizationPlugin.h>
#import "AuthorizationPlugin.h"

@interface PromptWindowController : NSWindowController <NSWindowDelegate>

@property MechanismRecord *mechanism;
@property (nonatomic, strong) NSString *pin;
@property (nonatomic, strong) NSSound *tts;
@property NSRect screenRect;

@property (weak) IBOutlet NSWindow *backdropWindow;
@property (weak) IBOutlet NSView *mainView;
@property (weak) IBOutlet NSView *stopLoginView;
@property (weak) IBOutlet NSView *promptView;
@property (weak) IBOutlet NSSecureTextField *promptPINTextField;

- (IBAction)okayButton:(id)sender;
- (IBAction)loginButton:(id)sender;

@end
