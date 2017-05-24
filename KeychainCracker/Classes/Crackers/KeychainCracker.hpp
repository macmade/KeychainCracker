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
 * @header      KeychainCracker.hpp
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#ifndef XS_KEYCHAIN_CRACKER_HPP
#define XS_KEYCHAIN_CRACKER_HPP

#include <string>
#include <list>
#include <functional>

namespace XS
{
    class KeychainCracker
    {
        public:
            
            KeychainCracker( const std::string & keychain, const std::list< std::string > & passwords );
            ~KeychainCracker( void );
            
            KeychainCracker( const KeychainCracker & o )      = delete;
            KeychainCracker( KeychainCracker && o )           = delete;
            KeychainCracker & operator =( KeychainCracker o ) = delete;
            
            friend void swap( KeychainCracker & o1, KeychainCracker & o2 );
            
            std::string   message( void )                 const;
            double        progress( void )                const;
            bool          progressIsIndeterminate( void ) const;
            unsigned long secondsRemaining( void )        const;
            
            void crack( const std::function< void( bool, const std::string & ) > & completion );
            void stop( void );
            
            size_t maxThreads( void )                     const;
            size_t maxCharsForCaseVariants( void )        const;
            size_t maxCharsForCommonSubstitutions( void ) const;
            
            void maxThreads( size_t value );
            void maxCharsForCaseVariants( size_t value );
            void maxCharsForCommonSubstitutions( size_t value );
            
        private:
            
            class  IMPL;
            IMPL * impl;
    };
}

#endif /* XS_KEYCHAIN_CRACKER_HPP */
