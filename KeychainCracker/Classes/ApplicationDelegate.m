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
 * @file        ApplicationDelegate.m
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#import "ApplicationDelegate.h"
#import "AboutWindowController.h"
#import "MainWindowController.h"

NS_ASSUME_NONNULL_BEGIN

@interface ApplicationDelegate()

@property( atomic, readwrite, strong, nullable ) AboutWindowController * aboutWindowController;
@property( atomic, readwrite, strong, nullable ) MainWindowController  * mainWindowController;

@end

NS_ASSUME_NONNULL_END

@implementation ApplicationDelegate

- ( void )applicationDidFinishLaunching: ( NSNotification * )notification
{
    ( void )notification;
    
    self.mainWindowController = [ MainWindowController new ];
    
    [ self.mainWindowController.window center ];
    [ self.mainWindowController.window makeKeyAndOrderFront: nil ];
}

- ( BOOL )applicationShouldTerminateAfterLastWindowClosed: ( NSApplication * )sender
{
    ( void )sender;
    
    return YES;
}

- ( IBAction )showAboutWindow: ( nullable id )sender
{
    @synchronized( self )
    {
        if( self.aboutWindowController == nil )
        {
            self.aboutWindowController = [ AboutWindowController new ];
            
            [ self.aboutWindowController.window center ];
        }
        
        [ self.aboutWindowController.window makeKeyAndOrderFront: sender ];
    }
}

@end
