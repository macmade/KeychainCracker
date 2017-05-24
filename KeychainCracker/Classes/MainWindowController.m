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
 * @file        MainWindowController.m
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#import "MainWindowController.h"
#import "KeychainCracker.h"
#import "GenericKeychainCracker.h"

NS_ASSUME_NONNULL_BEGIN

@interface MainWindowController()

@property( atomic, readwrite, assign           ) BOOL                  running;
@property( atomic, readwrite, assign           ) BOOL                  caseVariants;
@property( atomic, readwrite, assign           ) NSInteger             caseVariantsMax;
@property( atomic, readwrite, assign           ) BOOL                  commonSubstitutions;
@property( atomic, readwrite, assign           ) NSInteger             commonSubstitutionsMax;
@property( atomic, readwrite, strong, nullable ) NSString            * keychain;
@property( atomic, readwrite, strong, nullable ) NSString            * wordList;
@property( atomic, readwrite, strong, nullable ) NSImage             * keychainIcon;
@property( atomic, readwrite, strong, nullable ) NSImage             * wordListIcon;
@property( atomic, readwrite, strong, nullable ) NSString            * runningLabel;
@property( atomic, readwrite, strong, nullable ) id< KeychainCracker > cracker;
@property( atomic, readwrite, strong, nullable ) NSTimer             * timer;
@property( atomic, readwrite, assign           ) NSInteger             numberOfThreads;
@property( atomic, readwrite, assign           ) double                progress;
@property( atomic, readwrite, assign           ) BOOL                  indeterminate;
@property( atomic, readwrite, assign           ) BOOL                  hasStopped;
@property( atomic, readwrite, assign           ) BOOL                  hasTimeRemaining;
@property( atomic, readwrite, strong, nullable ) NSString            * timeRemainingLabel;
@property( atomic, readwrite, assign           ) BOOL                  useCPPImplementation;

- ( void )windowWillClose: ( NSNotification * )notification;
- ( IBAction )crack: ( nullable id )sender;
- ( IBAction )stop: ( nullable id )sender;
- ( IBAction )chooseKeychain: ( nullable id )sender;
- ( IBAction )chooseWordList: ( nullable id )sender;
- ( IBAction )chooseImplementation: ( nullable id )sender;
- ( void )displayAlertWithTitle: ( NSString * )title message: ( NSString * )message;
- ( void )updateUI;
- ( NSString * )timeRemainingWithSeconds: ( NSUInteger )seconds;

@end

NS_ASSUME_NONNULL_END

@implementation MainWindowController

- ( instancetype )init
{
    return [ self initWithWindowNibName: NSStringFromClass( self.class ) ];
}

- ( void )dealloc
{
    [ [ NSNotificationCenter defaultCenter ] removeObserver: self ];
    [ self.timer invalidate ];
}

- ( void )windowWillClose: ( NSNotification * )notification
{
    ( void )notification;
    
    [ [ NSUserDefaults standardUserDefaults ] setBool:    self.caseVariants           forKey: @"CaseVariants" ];
    [ [ NSUserDefaults standardUserDefaults ] setInteger: self.caseVariantsMax        forKey: @"CaseVariantsMax" ];
    [ [ NSUserDefaults standardUserDefaults ] setBool:    self.commonSubstitutions    forKey: @"CommonSubstitutions" ];
    [ [ NSUserDefaults standardUserDefaults ] setInteger: self.commonSubstitutionsMax forKey: @"CommonSubstitutionsMax" ];
    [ [ NSUserDefaults standardUserDefaults ] setInteger: self.numberOfThreads        forKey: @"NumberOfThreads" ];
    [ [ NSUserDefaults standardUserDefaults ] setBool:    self.useCPPImplementation   forKey: @"UseCPPImplementation" ];
    [ [ NSUserDefaults standardUserDefaults ] synchronize ];
}

- ( void )windowDidLoad
{
    NSString * keychain;
    NSString * wordList;
    
    [ super windowDidLoad ];
    
    [ [ NSNotificationCenter defaultCenter ] addObserver: self selector: @selector( windowWillClose: ) name: NSWindowWillCloseNotification object: self.window ];
    
    self.window.titlebarAppearsTransparent = YES;
    self.window.titleVisibility            = NSWindowTitleHidden;
    self.window.title                      = [ [ NSBundle mainBundle ] objectForInfoDictionaryKey: @"CFBundleName" ];
    
    keychain = [ [ NSUserDefaults standardUserDefaults ] objectForKey: @"Keychain" ];
    wordList = [ [ NSUserDefaults standardUserDefaults ] objectForKey: @"WordList" ];
    
    self.caseVariants           = [ [ NSUserDefaults standardUserDefaults ] boolForKey:    @"CaseVariants" ];
    self.caseVariantsMax        = [ [ NSUserDefaults standardUserDefaults ] integerForKey: @"CaseVariantsMax" ];
    self.commonSubstitutions    = [ [ NSUserDefaults standardUserDefaults ] boolForKey:    @"CommonSubstitutions" ];
    self.commonSubstitutionsMax = [ [ NSUserDefaults standardUserDefaults ] integerForKey: @"CommonSubstitutionsMax" ];
    self.numberOfThreads        = [ [ NSUserDefaults standardUserDefaults ] integerForKey: @"NumberOfThreads" ];
    self.useCPPImplementation   = [ [ NSUserDefaults standardUserDefaults ] boolForKey:    @"UseCPPImplementation" ];
    
    if( self.numberOfThreads <= 0 || self.numberOfThreads > 200 )
    {
        self.numberOfThreads = 20;
    }
    
    if( self.caseVariantsMax < 2 || self.caseVariantsMax > 20 )
    {
        self.caseVariantsMax = 20;
    }
    
    if( self.commonSubstitutionsMax < 2 || self.commonSubstitutionsMax > 20 )
    {
        self.commonSubstitutionsMax = 5;
    }
    
    if( wordList.length && [ [ NSFileManager defaultManager ] fileExistsAtPath: wordList ] )
    {
        self.wordList     = wordList;
        self.wordListIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.wordList ];
    }
    else if
    (
           [ [ NSBundle mainBundle ] pathForResource: @"words" ofType: @"txt" ].length
        && [ [ NSFileManager defaultManager ] fileExistsAtPath: [ [ NSBundle mainBundle ] pathForResource: @"words" ofType: @"txt" ] ]
    )
    {
        self.wordList     = [ [ NSBundle mainBundle ] pathForResource: @"words" ofType: @"txt" ];
        self.wordListIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.wordList ];
    }
    
    if( keychain.length && [ [ NSFileManager defaultManager ] fileExistsAtPath: keychain ] )
    {
        self.keychain     = keychain;
        self.keychainIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.keychain ];
    }
    else if
    (
           [ [ NSBundle mainBundle ] pathForResource: @"test" ofType: @"keychain-db" ].length
        && [ [ NSFileManager defaultManager ] fileExistsAtPath: [ [ NSBundle mainBundle ] pathForResource: @"test" ofType: @"keychain-db" ] ]
    )
    {
        self.keychain     = [ [ NSBundle mainBundle ] pathForResource: @"test" ofType: @"keychain-db" ];
        self.keychainIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.keychain ];
    }
    else
    {
        {
            NSTask   * task;
            NSData   * data;
            NSPipe   * output;
            NSPipe   * error;
            
            output              = [ NSPipe pipe ];
            error               = [ NSPipe pipe ];
            task                = [ NSTask new ];
            task.standardOutput = output;
            task.standardError  = error;
            task.launchPath     = @"/usr/bin/security";
            task.arguments      = @[ @"default-keychain" ];
            
            [ task launch ];
            [ task waitUntilExit ];
            
            data     = [ output.fileHandleForReading readDataToEndOfFile ];
            keychain = [ [ NSString alloc ] initWithData: data encoding: NSUTF8StringEncoding ];
            keychain = [ keychain stringByTrimmingCharactersInSet: [ NSCharacterSet whitespaceAndNewlineCharacterSet ] ];
            keychain = [ keychain stringByTrimmingCharactersInSet: [ NSCharacterSet characterSetWithCharactersInString: @"\"" ] ];
            
            if( [ [ NSFileManager defaultManager ] fileExistsAtPath: keychain ] )
            {
                self.keychain     = keychain;
                self.keychainIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.keychain ];
            }
        }
    }
    
    self.timer = [ NSTimer scheduledTimerWithTimeInterval: 0.1 target: self selector: @selector( updateUI ) userInfo: nil repeats: YES ];
}

- ( IBAction )crack: ( nullable id )sender
{
    GenericKeychainCrackerImplementation imp;
    NSArray< NSString * >              * passwords;
    NSData                             * data;
    
    ( void )sender;
    
    if( self.cracker != nil )
    {
        return;
    }
    
    data      = [ [ NSFileManager defaultManager ] contentsAtPath: self.wordList ];
    passwords = [ [ [ NSString alloc ] initWithData: data encoding: NSUTF8StringEncoding ] componentsSeparatedByString: @"\n" ];
    
    if( passwords.count == 0 || ( passwords.count == 1 && passwords.firstObject.length == 0 ) )
    {
        [ self displayAlertWithTitle: @"Error" message: @"Error reading from the word list file." ];
        
        return;
    }
    
    imp                     = ( self.useCPPImplementation ) ? GenericKeychainCrackerImplementationCXX : GenericKeychainCrackerImplementationObjectiveC;
    self.cracker            = [ [ GenericKeychainCracker alloc ] initWithKeychain: self.keychain passwords: passwords implementation: imp ];
    self.cracker.maxThreads = ( self.numberOfThreads ) ? ( NSUInteger )( self.numberOfThreads ) : 1;
    
    if( self.caseVariants && self.caseVariantsMax > 0 )
    {
        self.cracker.maxCharsForCaseVariants = ( NSUInteger )( self.caseVariantsMax );
    }
    
    if( self.commonSubstitutions && self.commonSubstitutionsMax > 0 )
    {
        self.cracker.maxCharsForCommonSubstitutions = ( NSUInteger )( self.commonSubstitutionsMax );
    }
    
    if( self.cracker == nil )
    {
        [ self displayAlertWithTitle: @"Error" message: @"Error initializing the keychain cracker." ];
        
        return;
    }
    
    self.running = YES;
    
    [ self.cracker crack: ^( BOOL found, NSString * _Nullable password )
        {
            dispatch_async
            (
                dispatch_get_main_queue(),
                ^( void )
                {
                    if( self.hasStopped == NO )
                    {
                        if( found )
                        {
                            [ self displayAlertWithTitle: @"Password found" message: [ NSString stringWithFormat: @"The keychain password is: %@", password ] ];
                        }
                        else
                        {
                            [ self displayAlertWithTitle: @"Password not found" message: @"A correct keychain password wasn't found in the supplied word list." ];
                        }
                    }
                    
                    self.hasStopped = NO;
                    self.running    = NO;
                    self.cracker    = nil;
                }
            );
        }
    ];
}

- ( IBAction )stop: ( nullable id )sender
{
    ( void )sender;
    
    self.hasStopped = YES;
    
    [ self.cracker stop ];
}

- ( IBAction )chooseKeychain: ( nullable id )sender
{
    NSOpenPanel * panel;
    
    ( void )sender;
    
    panel                         = [ NSOpenPanel openPanel ];
    panel.canCreateDirectories    = NO;
    panel.canChooseDirectories    = NO;
    panel.canChooseFiles          = YES;
    panel.allowsMultipleSelection = NO;
    
    [ panel beginSheetModalForWindow: self.window completionHandler: ^( NSInteger result )
        {
            if( result != NSFileHandlingPanelOKButton )
            {
                return;
            }
            
            if( [ [ NSFileManager defaultManager ] fileExistsAtPath: panel.URLs.firstObject.path ] == NO )
            {
                return;
            }
            
            self.keychain     = panel.URLs.firstObject.path;
            self.keychainIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.keychain ];
            
            [ [ NSUserDefaults standardUserDefaults ] setObject: self.keychain forKey: @"Keychain" ];
            [ [ NSUserDefaults standardUserDefaults ] synchronize ];
        }
    ];
}

- ( IBAction )chooseWordList: ( nullable id )sender
{
    NSOpenPanel * panel;
    
    ( void )sender;
    
    panel                         = [ NSOpenPanel openPanel ];
    panel.canCreateDirectories    = NO;
    panel.canChooseDirectories    = NO;
    panel.canChooseFiles          = YES;
    panel.allowsMultipleSelection = NO;
    panel.allowedFileTypes        = @[ @"txt" ];
    
    [ panel beginSheetModalForWindow: self.window completionHandler: ^( NSInteger result )
        {
            if( result != NSFileHandlingPanelOKButton )
            {
                return;
            }
            
            if( [ [ NSFileManager defaultManager ] fileExistsAtPath: panel.URLs.firstObject.path ] == NO )
            {
                return;
            }
            
            self.wordList     = panel.URLs.firstObject.path;
            self.wordListIcon = [ [ NSWorkspace sharedWorkspace ] iconForFile: self.wordList ];
            
            [ [ NSUserDefaults standardUserDefaults ] setObject: self.wordList forKey: @"WordList" ];
            [ [ NSUserDefaults standardUserDefaults ] synchronize ];
        }
    ];
}

- ( IBAction )chooseImplementation: ( nullable id )sender
{
    ( void )sender;
}

- ( void )displayAlertWithTitle: ( NSString * )title message: ( NSString * )message
{
    dispatch_async
    (
        dispatch_get_main_queue(),
        ^( void )
        {
            NSAlert * alert;
            
            alert                 = [ NSAlert new ];
            alert.messageText     = title;
            alert.informativeText = message;
            
            [ alert addButtonWithTitle: NSLocalizedString( @"OK", @"" ) ];
            [ alert beginSheetModalForWindow: self.window completionHandler: NULL ];
        }
    );
}

- ( void )updateUI
{
    if( self.running == NO )
    {
        self.runningLabel       = @"";
        self.progress           = 0.0;
        self.indeterminate      = YES;
        self.hasTimeRemaining   = NO;
        self.timeRemainingLabel = @"";
    }
    else
    {
        self.runningLabel       = self.cracker.message;
        self.progress           = self.cracker.progress;
        self.indeterminate      = self.cracker.progressIsIndeterminate;
        self.hasTimeRemaining   = ( self.cracker.secondsRemaining > 0 );
        self.timeRemainingLabel = [ self timeRemainingWithSeconds: self.cracker.secondsRemaining ];
    }
}

- ( NSString * )timeRemainingWithSeconds: ( NSUInteger )seconds
{
    NSString * unit;
    double     value;
    
    if( seconds == 0 )
    {
        return @"";
    }
    
    if( seconds < 60 )
    {
        value = seconds;
        unit  = ( value > 1 ) ? @"seconds" : @"second";
    }
    else if( seconds < 3600 )
    {
        value = seconds / 60;
        unit  = ( value > 1 ) ? @"minutes" : @"minute";
    }
    else
    {
        value = seconds / 3600;
        unit  = ( value > 1 ) ? @"hours" : @"hour";
    }
    
    return [ NSString stringWithFormat: @"Estimated time remaining: about %.02f %@", value, unit ];
}

@end
