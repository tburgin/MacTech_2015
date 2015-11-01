/*
    Verify.h
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

#import <Foundation/Foundation.h>
#import "AuthorizationPlugin.h"

@interface Verify : NSObject

// Define a pointer to the MechanismRecord. This will be used to get and set
// all the inter-mechanism data. It is also used to allow or deny the login.
@property MechanismRecord *mechanism;

- (id)initWithMechanism:(MechanismRecord *)inMechanism;
- (void)run;

@end
