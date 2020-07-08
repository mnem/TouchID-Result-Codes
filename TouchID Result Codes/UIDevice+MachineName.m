//
//  UIDevice+MachineName.m
//  TouchID Result Codes
//
//  Created by David Wagner on 06/07/2017.
//  Copyright © 2017 David Wagner. All rights reserved.
//

#import "UIDevice+MachineName.h"
#import <sys/utsname.h>
#import <memory.h>

@implementation UIDevice (MachineName)

+ (NSString *)trc_machineName
{
    struct utsname systemInfo;
    uname(&systemInfo);
    
    return [NSString stringWithCString:systemInfo.machine
                              encoding:NSUTF8StringEncoding];
}

@end
