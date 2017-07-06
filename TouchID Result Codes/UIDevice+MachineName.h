//
//  UIDevice+MachineName.h
//  TouchID Result Codes
//
//  Created by David Wagner on 06/07/2017.
//  Copyright © 2017 David Wagner. All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface UIDevice (MachineName)

+ (NSString *)trc_machineName;

@end

NS_ASSUME_NONNULL_END
