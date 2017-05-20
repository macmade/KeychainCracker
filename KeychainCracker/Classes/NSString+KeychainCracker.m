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
 * @file        NSString+KeychainCracker.m
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#import "NSString+KeychainCracker.h"

@implementation NSString( KeychainCracker )

- ( NSArray< NSString * > * )caseVariants
{
    char                         * permutation;
    const char                   * cp;
    NSUInteger                     length;
    NSUInteger                     i;
    NSUInteger                     j;
    NSUInteger                     n;
    NSMutableArray< NSString * > * variants;
    
    if( self.length == 0 )
    {
        return @[];
    }
    
    cp     = self.UTF8String;
    length = self.length;
    
    if( length > 20 )
    {
        return @[ self ];
    }
    
    permutation = calloc( length + 1, 1 );
    
    if( permutation == NULL )
    {
        return @[ self ];
    }
    
    variants = [ NSMutableArray new ];
    
    for( i = 0, n = ( NSUInteger )pow( 2, length ); i < n; i++ )
    {
        for( j = 0; j < length; j++ )
        {
            permutation[ j ] = ( ( i >> j & 1 ) != 0 ) ? ( char )toupper( cp[ j ] ) : cp[ j ];
        }
        
        [ variants addObject: [ NSString stringWithUTF8String: permutation ] ];
    }
    
    free( permutation );
    
    return variants;
}

- ( NSArray< NSString * > * )commonSubstitutions
{
    return @[ self ];
}

@end
