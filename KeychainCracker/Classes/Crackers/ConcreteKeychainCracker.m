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
 * @file        ConcreteKeychainCracker.m
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#import "ConcreteKeychainCracker.h"
#import "NSString+KeychainCracker.h"
#import <stdatomic.h>

NS_ASSUME_NONNULL_BEGIN

@interface ConcreteKeychainCracker()
{
    atomic_ulong   _processed;
    atomic_bool    _unlocked;
    atomic_bool    _stopping;
    SecKeychainRef _keychain;
}

@property( atomic, readwrite, strong           ) NSString                     * keychainName;
@property( atomic, readwrite, strong           ) NSArray< NSString * >        * passwords;
@property( atomic, readwrite, assign           ) NSUInteger                     numberOfPasswordsToTest;
@property( atomic, readwrite, strong           ) NSMutableArray< NSString * > * foundPasswords;
@property( atomic, readwrite, assign           ) NSUInteger                     threadsRunning;
@property( atomic, readwrite, strong, nullable ) NSString                     * message;
@property( atomic, readwrite, assign           ) BOOL                           initialized;
@property( atomic, readwrite, assign           ) double                         progress;
@property( atomic, readwrite, assign           ) BOOL                           progressIsIndeterminate;
@property( atomic, readwrite, assign           ) NSUInteger                     lastProcessed;
@property( atomic, readwrite, assign           ) NSUInteger                     secondsRemaining;
@property( atomic, readwrite, strong, nullable ) NSTimer                      * timer;
@property( atomic, readwrite, strong, nullable ) void ( ^ completion )( BOOL passwordFound, NSString * _Nullable password );

- ( void )crack;
- ( void )generateVariants: ( NSMutableArray< NSString * > * )passwords withSelector: ( SEL )selector maxChars: ( NSUInteger )maxChars message: ( NSString * )message;
- ( void )crackPasswords: ( NSArray< NSString * > * )passwords;
- ( void )checkProgress;

@end

NS_ASSUME_NONNULL_END

@implementation ConcreteKeychainCracker

@synthesize maxThreads;
@synthesize maxCharsForCaseVariants;
@synthesize maxCharsForCommonSubstitutions;

- ( nullable instancetype )initWithKeychain: ( NSString * )keychain passwords: ( NSArray< NSString * > * )passwords
{
    if( ( self = [ self init ] ) )
    {
        self.keychainName   = keychain;
        self.passwords      = passwords;
        self.foundPasswords = [ NSMutableArray new ];
        
        if( [ [ NSFileManager defaultManager ] fileExistsAtPath: self.keychainName ] == NO )
        {
            return nil;
        }
        
        if( self.passwords.count == 0 )
        {
            return nil;
        }
        
        if( SecKeychainOpen( self.keychainName.UTF8String, &_keychain ) != noErr || _keychain == NULL )
        {
            return nil;
        }
        
        SecKeychainLock( _keychain );
    }
    
    return self;
}

- ( void )dealloc
{
    if( _keychain != NULL )
    {
        CFRelease( _keychain );
    }
}

- ( void )crack: ( void ( ^ )( BOOL passwordFound, NSString * _Nullable password ) )completion
{
    @synchronized( self )
    {
        if( self.timer )
        {
            @throw [ NSException exceptionWithName: @"com.xs-labs.KeychainCracker" reason: @"KeychainCracker is already running" userInfo: nil ];
        }
        
        self.timer                   = [ NSTimer scheduledTimerWithTimeInterval: 1 target: self selector: @selector( checkProgress ) userInfo: nil repeats: YES ];
        self.completion              = completion;
        self.initialized             = NO;
        self.progressIsIndeterminate = YES;
    }
    
    [ NSThread detachNewThreadSelector: @selector( crack ) toTarget: self withObject: nil ];
}

- ( void )stop
{
    @synchronized( self )
    {
        if( self.timer == nil )
        {
            return;
        }
        
        atomic_store( &_stopping, true );
        
        self.progressIsIndeterminate = YES;
    }
}

- ( void )crack
{
    NSMutableArray< NSString * >                     * passwords;
    NSMutableArray< NSString * >                     * sub;
    NSMutableArray< NSMutableArray< NSString * > * > * groups;
    NSUInteger                                         n;
    NSUInteger                                         i;
    
    passwords             = self.passwords.mutableCopy;
    groups                = [ NSMutableArray new ];
    self.secondsRemaining = 0;
    
    if( self.maxCharsForCaseVariants > 0 )
    {
        [ self generateVariants: passwords withSelector: @selector( caseVariants ) maxChars: self.maxCharsForCaseVariants message: @"Generating case variants" ];
    }
    
    if( atomic_load( &_stopping ) == true )
    {
        self.initialized = YES;
        
        return;
    }
    
    if( self.maxCharsForCommonSubstitutions > 0 )
    {
        [ self generateVariants: passwords withSelector: @selector( commonSubstitutions ) maxChars: self.maxCharsForCommonSubstitutions message: @"Generating common substitutions" ];
    }
    
    if( atomic_load( &_stopping ) == true )
    {
        self.initialized = YES;
        
        return;
    }
    
    self.message                 = @"Preparing worker threads...";
    self.numberOfPasswordsToTest = passwords.count;
    _processed                   = 0;
    self.progress                = 0;
    n                            = ( passwords.count / self.maxThreads );
    
    for( i = 0; i < self.maxThreads; i++ )
    {
        if( passwords.count < n )
        {
            break;
        }
        
        sub = [ passwords subarrayWithRange: NSMakeRange( 0, n ) ].mutableCopy;
        
        [ passwords removeObjectsInRange: NSMakeRange( 0, n ) ];
        [ groups addObject: sub ];
    }
    
    if( atomic_load( &_stopping ) == true )
    {
        self.initialized = YES;
        
        return;
    }
    
    for( sub in groups )
    {
        if( passwords.count == 0 )
        {
            break;
        }
        
        [ sub addObject: passwords.firstObject ];
        [ passwords removeObject: passwords.firstObject ];
    }
    
    if( atomic_load( &_stopping ) == true )
    {
        self.initialized = YES;
        
        return;
    }
    
    for( sub in groups )
    {
        if( sub.count == 0 )
        {
            continue;
        }
        
        [ NSThread detachNewThreadSelector: @selector( crackPasswords: ) toTarget: self withObject: sub ];
    }
    
    self.initialized             = YES;
    self.progressIsIndeterminate = NO;
}

- ( void )generateVariants: ( NSMutableArray< NSString * > * )passwords withSelector: ( SEL )selector maxChars: ( NSUInteger )maxChars message: ( NSString * )message
{
    NSUInteger     n;
    NSUInteger     i;
    NSDate       * start;
    NSString     * password;
    NSTimeInterval diff;
    
    n                            = passwords.count;
    self.progress                = 0;
    self.progressIsIndeterminate = NO;
    start                        = [ NSDate date ];
    
    for( i = 0; i < n; i++ )
    {
        password      = passwords[ 0 ];
        self.progress = ( double )i / ( double )n;
        self.message  = [ NSString stringWithFormat: @"%@ - %.0f%%", message, self.progress * 100.0 ];
        
        [ passwords removeObjectAtIndex: 0 ];
        
        if( password.length > maxChars )
        {
            [ passwords addObject: password ];
        }
        else
        {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [ passwords addObjectsFromArray: [ password performSelector: selector ] ];
            #pragma clang diagnostic pop
        }
        
        diff                  = -[ start timeIntervalSinceNow ];
        self.secondsRemaining = ( NSUInteger )( ( n - i ) / ( i / diff ) );
        
        if( atomic_load( &_stopping ) == true )
        {
            self.progressIsIndeterminate = YES;
            
            return;
        }
    }
    
    self.progressIsIndeterminate = YES;
}

- ( void )crackPasswords: ( NSArray< NSString * > * )passwords
{
    NSString * p;
    
    @autoreleasepool
    {
        [ NSThread setThreadPriority: 1.0 ];
        
        @synchronized( self )
        {
            self.threadsRunning = self.threadsRunning + 1;
        }
        
        for( p in passwords )
        {
            if( atomic_load( &( self->_unlocked ) ) )
            {
                break;
            }
            
            if( atomic_load( &self->_stopping ) == true )
            {
                break;
            }
            
            atomic_fetch_add( &( self->_processed ), 1 );
            
            if( SecKeychainUnlock( self->_keychain, ( UInt32 )( p.length ), p.UTF8String, TRUE ) == noErr )
            {
                @synchronized( self )
                {
                    [ self.foundPasswords addObject: p ];
                    
                    atomic_store( &( self->_unlocked ), true );
                    
                    break;
                }
            }
        }
    }
    
    @synchronized( self )
    {
        self.threadsRunning = self.threadsRunning - 1;
    }
}

- ( void )checkProgress
{
    NSString *           password;
    NSString * _Nullable validPassord;
    BOOL                 found;
    
    validPassord = nil;
    found        = NO;
    
    if( atomic_load( &_stopping ) == true )
    {
        self.message = @"Stopping...";
    }
    
    if( self.initialized == NO )
    {
        return;
    }
    
    if( atomic_load( &_stopping ) == true && self.threadsRunning > 0 )
    {
        return;
    }
    
    atomic_store( &_stopping, false );
    
    if( atomic_load( &( self->_unlocked ) ) )
    {
        self.message = @"Password found - Verifying...";
        
        @synchronized( self )
        {
            for( password in self.foundPasswords )
            {
                SecKeychainLock( _keychain );
                
                if( SecKeychainUnlock( _keychain, ( UInt32 )( password.length ), password.UTF8String, TRUE ) == noErr )
                {
                    found        = YES;
                    validPassord = password;
                    
                    goto stop;
                }
            }
        }
    }
    
    if( self.threadsRunning == 0 )
    {
        goto stop;
    }
    
    {
        atomic_ulong done;
        NSUInteger   last;
        NSUInteger    total;
        NSString    * s;
        
        done          = atomic_load( &( self->_processed ) );
        last          = ( self.progress == 0 ) ? done : done - self.lastProcessed;
        total         = self.numberOfPasswordsToTest;
        self.progress = ( double )done / ( double )total;
        
        s                     = [ NSNumberFormatter localizedStringFromNumber: [ NSNumber numberWithUnsignedInteger: total ] numberStyle: NSNumberFormatterDecimalStyle ];
        self.message          = [ NSString stringWithFormat: @"Trying %@ passwords - %.0f%% (~%lu / sec)", s, self.progress * 100, last ];
        self.lastProcessed    = done;
        self.secondsRemaining = ( last ) ? ( total - done ) / last : 0;
    }
    
    return;
    
    stop:
    
        [ self.timer invalidate ];
        
        self.timer       = nil;
        self.message     = nil;
        self.initialized = NO;
        
        if( self.completion )
        {
            self.completion( found, validPassord );
        }
        
        self.completion = NULL;
}

@end
