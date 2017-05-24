/*******************************************************************************
 * The MIT License (MIT)
 * 
 * Copyright (c) 2017 Jean-David Gadina - www.xs-labs.com
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

/*!
 * @header      KeychainCracker.h
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#ifdef __cplusplus
#import <Foundation/Foundation.h>
#else
@import Foundation;
#endif

NS_ASSUME_NONNULL_BEGIN

@protocol KeychainCracker< NSObject >

@property( atomic, readonly, nullable ) NSString * message;
@property( atomic, readonly           ) double     progress;
@property( atomic, readonly           ) BOOL       progressIsIndeterminate;
@property( atomic, readonly           ) NSUInteger secondsRemaining;
@property( atomic, readwrite, assign  ) NSUInteger maxThreads;
@property( atomic, readwrite, assign  ) NSUInteger maxCharsForCaseVariants;
@property( atomic, readwrite, assign  ) NSUInteger maxCharsForCommonSubstitutions;

- ( nullable instancetype )initWithKeychain: ( NSString * )keychain passwords: ( NSArray< NSString * > * )passwords;
- ( void )crack: ( void ( ^ )( BOOL passwordFound, NSString * _Nullable password ) )completion;
- ( void )stop;

@end

NS_ASSUME_NONNULL_END
