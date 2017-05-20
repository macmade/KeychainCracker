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
 * @file        KeychainCracker.cpp
 * @copyright   (c) 2017, Jean-David Gadina - www.xs-labs.com
 */

#include "KeychainCracker.hpp"
#include <exception>
#include <algorithm>
#include <mutex>
#include <atomic>
#include <thread>
#include <Security/Security.h>

namespace XS
{
    class KeychainCracker::IMPL
    {
        public:
            
            IMPL( const std::string & keychain, const std::vector< std::string > & passwords, unsigned int options, size_t threads );
            ~IMPL( void );
            
            unsigned int                 _options;
            std::string                  _keychainName;
            std::vector< std::string >   _passwords;
            std::vector< std::string >   _foundPasswords;
            size_t                       _threadCount;
            SecKeychainRef               _keychain;
            std::atomic< unsigned long > _processed;
            std::atomic< bool          > _unlocked;
            std::atomic< bool          > _initialized;
            std::atomic< bool          > _stopping;
            std::atomic< size_t        > _threadsRunning;
            size_t                       _numberOfPasswordsToTest;
            std::string                  _message;
            double                       _progress;
            bool                         _progressIsIndeterminate;
            bool                         _running;
            size_t                       _lastProcessed;
            size_t                       _secondsRemaining;
            std::recursive_mutex         _rmtx;
            
            std::function< void( bool, const std::string & ) > _completion;
            
            void crack( void );
            
            std::vector< std::string > caseVariants( const std::string & str );
            std::vector< std::string > commonSubstitutions( const std::string & str );
    };
    
    KeychainCracker::KeychainCracker( const std::string & keychain, const std::vector< std::string > & passwords, unsigned int options, size_t threads ):
        impl( new IMPL( keychain, passwords, options, threads ) )
    {}
    
    KeychainCracker::~KeychainCracker( void )
    {
        delete this->impl;
    }
    
    void swap( KeychainCracker & o1, KeychainCracker & o2 )
    {
        using std::swap;
        
        swap( o1.impl, o2.impl );
    }
    
    std::string KeychainCracker::message( void ) const
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        return this->impl->_message;
    }
    
    double KeychainCracker::progress( void ) const
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        return this->impl->_progress;
    }
    
    bool KeychainCracker::progressIsIndeterminate( void ) const
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        return this->impl->_progressIsIndeterminate;
    }
    
    unsigned long KeychainCracker::secondsRemaining( void ) const
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        return this->impl->_secondsRemaining;
    }
    
    void KeychainCracker::crack( const std::function< void( bool, const std::string & ) > & completion )
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        if( this->impl->_running )
        {
            throw std::runtime_error( "KeychainCracker is already running" );
        }
        
        this->impl->_running                 = true;
        this->impl->_completion              = completion;
        this->impl->_initialized             = false;
        this->impl->_progressIsIndeterminate = true;
        
        std::thread
        (
            [ this ]
            {
                this->impl->crack();
            }
        )
        .detach();
    }
    
    void KeychainCracker::stop( void )
    {
        std::lock_guard< std::recursive_mutex > l( this->impl->_rmtx );
        
        if( this->impl->_running == false )
        {
            return;
        }
        
        this->impl->_stopping                = true;
        this->impl->_progressIsIndeterminate = true;
    }
    
    KeychainCracker::IMPL::IMPL( const std::string & keychain, const std::vector< std::string > & passwords, unsigned int options, size_t threads ):
        _options(                 options ),
        _keychainName(            keychain ),
        _passwords(               passwords ),
        _threadCount(             threads ),
        _keychain(                nullptr ),
        _processed(               0 ),
        _unlocked(                false ),
        _initialized(             false ),
        _stopping(                false ),
        _threadsRunning(          0 ),
        _numberOfPasswordsToTest( 0 ),
        _progress(                0.0 ),
        _progressIsIndeterminate( false ),
        _running(                 false ),
        _lastProcessed(           0 ),
        _secondsRemaining(        0 )
    {
        if( SecKeychainOpen( this->_keychainName.c_str(), &( this->_keychain ) ) != noErr || this->_keychain == NULL )
        {
            throw std::runtime_error( std::string( "Cannot open keychain" ) + this->_keychainName );
        }
        
        SecKeychainLock( this->_keychain );
    }
    
    KeychainCracker::IMPL::~IMPL( void )
    {
        if( this->_keychain != nullptr )
        {
            CFRelease( this->_keychain );
        }
    }
    
    void KeychainCracker::IMPL::crack( void )
    {}
    
    std::vector< std::string > KeychainCracker::IMPL::caseVariants( const std::string & str )
    {
        char                     * permutation;
        const char               * cp;
        size_t                     length;
        size_t                     i;
        size_t                     j;
        size_t                     n;
        std::vector< std::string > variants;
        
        cp     = str.c_str();
        length = str.length();
        
        if( length == 0 )
        {
            return {};
        }
        
        if( length > 20 )
        {
            return { str };
        }
        
        permutation = new char[ length + 1 ];
        
        if( permutation == NULL )
        {
            return { str };
        }
        
        for( i = 0, n = ( size_t )pow( 2, length ); i < n; i++ )
        {
            for( j = 0; j < length; j++ )
            {
                permutation[ j ] = ( ( i >> j & 1 ) != 0 ) ? ( char )toupper( cp[ j ] ) : cp[ j ];
            }
            
            variants.push_back( permutation );
        }
        
        delete[] permutation;
        
        return variants;
    }
    
    std::vector< std::string > KeychainCracker::IMPL::commonSubstitutions( const std::string & str )
    {
        return { str };
    }
}
