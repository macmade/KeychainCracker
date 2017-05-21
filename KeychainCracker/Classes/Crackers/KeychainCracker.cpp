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
#include <chrono>
#include <Security/Security.h>

namespace XS
{
    class KeychainCracker::IMPL
    {
        public:
            
            IMPL( const std::string & keychain, const std::vector< std::string > & passwords, unsigned int options, size_t threads );
            ~IMPL( void );
            
            std::string                  _keychainName;
            std::vector< std::string >   _passwords;
            std::vector< std::string >   _foundPasswords;
            std::atomic< size_t >        _threadCount;
            SecKeychainRef               _keychain;
            std::atomic< unsigned int  > _options;
            std::atomic< unsigned long > _processed;
            std::atomic< bool >          _unlocked;
            std::atomic< bool >          _initialized;
            std::atomic< bool >          _stopping;
            std::atomic< bool >          _running;
            std::atomic< size_t >        _threadsRunning;
            std::atomic< size_t >        _secondsRemaining;
            std::atomic< size_t >        _numberOfPasswordsToTest;
            std::string                  _message;
            std::atomic< double >        _progress;
            std::atomic< bool >          _progressIsIndeterminate;
            std::atomic< size_t >        _lastProcessed;
            std::recursive_mutex         _rmtx;
            
            std::function< void( bool, const std::string & ) > _completion;
            
            void crack( void );
            void generateVariants( std::vector< std::string > & passwords, std::vector< std::string > ( IMPL::* func )( const std::string & ), const std::string & message );
            void crackPasswords( const std::vector< std::string > & passwords );
            void checkProgress( void );
            
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
        
        std::thread
        (
            [ this ]
            {
                this->impl->checkProgress();
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
        _keychainName(            keychain ),
        _passwords(               passwords ),
        _threadCount(             threads ),
        _options(                 options ),
        _keychain(                nullptr ),
        _processed(               0 ),
        _unlocked(                false ),
        _initialized(             false ),
        _stopping(                false ),
        _running(                 false ),
        _threadsRunning(          0 ),
        _secondsRemaining(        0 ),
        _numberOfPasswordsToTest( 0 ),
        _progress(                0.0 ),
        _progressIsIndeterminate( false ),
        _lastProcessed(           0 )
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
    {
        std::vector< std::string >                passwords;
        std::vector< std::vector< std::string > > groups;
        unsigned long                             n;
        unsigned long                             i;
        std::vector< std::thread >                threads;
        
        passwords               = this->_passwords;
        this->_secondsRemaining = 0;
        
        if( this->_options.load() & static_cast< unsigned int >( Options::CaseVariants ) )
        {
            this->generateVariants( passwords, &IMPL::caseVariants, "Generating case variants" );
        }
        
        if( this->_stopping )
        {
            this->_initialized = true;
            
            return;
        }
        
        if( this->_options.load() & static_cast< unsigned int >( Options::CommonSubstitutions ) )
        {
            this->generateVariants( passwords, &IMPL::commonSubstitutions, "Generating common substitutions" );
        }
        
        if( this->_stopping )
        {
            this->_initialized = true;
            
            return;
        }
        
        {
            std::lock_guard< std::recursive_mutex > l( this->_rmtx );
            
            this->_message = "Preparing worker threads";
        }
        
        this->_numberOfPasswordsToTest = passwords.size();
        this->_processed               = 0;
        this->_progress                = 0;
        n                              = ( passwords.size() / this->_threadCount );
        
        for( i = 0; i < this->_threadCount; i++ )
        {
            {
                std::vector< std::string > sub;
                
                if( passwords.size() < n )
                {
                    break;
                }
                
                sub = std::vector< std::string >( passwords.begin(), passwords.begin() + static_cast< long >( n ) );
                
                passwords.erase( passwords.begin(), passwords.begin() + static_cast< long >( n ) );
                groups.push_back( sub );
            }
        }
        
        if( this->_stopping )
        {
            this->_initialized = true;
            
            return;
        }
        
        for( auto & sub: groups )
        {
            if( passwords.size() == 0 )
            {
                break;
            }
            
            sub.push_back( passwords[ 0 ] );
            passwords.erase( passwords.begin() );
        }
        
        if( this->_stopping )
        {
            this->_initialized = true;
            
            return;
        }
        
        for( const auto & sub: groups )
        {
            if( sub.size() == 0 )
            {
                continue;
            }
            
            threads.push_back
            (
                std::thread
                (
                    [ this, sub ]
                    {
                        this->crackPasswords( sub );
                    }
                )
            );
        }
        
        this->_initialized             = true;
        this->_progressIsIndeterminate = false;
        
        for( auto & t: threads )
        {
            t.join();
        }
    }
    
    void KeychainCracker::IMPL::generateVariants( std::vector< std::string > & passwords, std::vector< std::string > ( IMPL::* func )( const std::string & ), const std::string & message )
    {
        size_t                     i;
        size_t                     n;
        std::vector< std::string > variants;
        time_t                     start;
        double                     diff;
        char                       percent[ 4 ] = { 0, 0, 0, 0 };
        
        n                              = passwords.size();
        this->_progress                = 0;
        this->_progressIsIndeterminate = false;
        start                          = time( nullptr );
        
        for( i = 0; i < n; i++ )
        {
            variants        = ( this->*( func ) )( passwords[ 0 ] );
            this->_progress = static_cast< double >( i ) / static_cast< double >( n );
            
            sprintf( percent, "%.0f", this->_progress * 100 );
            
            this->_message  = message + " - " + percent + "%";
            
            passwords.erase( passwords.begin() );
            passwords.insert( passwords.end(), variants.begin(), variants.end() );
            
            diff                    = static_cast< double >( time( nullptr ) - start );
            this->_secondsRemaining = static_cast< unsigned long >( ( n - i ) / ( i / diff ) );
            
            if( this->_stopping )
            {
                this->_progressIsIndeterminate = true;
                
                return;
            }
        }
        
        this->_progressIsIndeterminate = true;
    }
    
    void KeychainCracker::IMPL::crackPasswords( const std::vector< std::string > & passwords )
    {
        this->_threadsRunning++;
        
        for( const auto & p: passwords )
        {
            if( this->_unlocked )
            {
                break;
            }
            
            if( this->_stopping )
            {
                break;
            }
            
            this->_processed++;
            
            if( SecKeychainUnlock( this->_keychain, static_cast< UInt32 >( p.length() ), p.c_str(), TRUE ) == noErr )
            {
                {
                    std::lock_guard< std::recursive_mutex > l( this->_rmtx );
                    
                    this->_foundPasswords.push_back( p );
                    
                    this->_unlocked = true;
                    
                    break;
                }
            }
        }
        
        this->_threadsRunning--;
    }
    
    void KeychainCracker::IMPL::checkProgress( void )
    {
        std::string validPassord;
        bool        found;
        
        while( 1 )
        {
            std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
            
            found = false;
            
            if( this->_stopping )
            {
                {
                    std::lock_guard< std::recursive_mutex > l( this->_rmtx );
                    
                    this->_message = "Stopping...";
                }
            }
            
            if( this->_initialized == false )
            {
                continue;
            }
            
            if( this->_stopping && this->_threadsRunning > 0 )
            {
                continue;
            }
            
            this->_stopping = false;
            
            if( this->_unlocked )
            {
                {
                    std::lock_guard< std::recursive_mutex > l( this->_rmtx );
                    
                    this->_message = "Password found - Verifying...";
                    
                    for( const auto & password: this->_foundPasswords )
                    {
                        SecKeychainLock( this->_keychain );
                        
                        if( SecKeychainUnlock( this->_keychain, static_cast< UInt32 >( password.length() ), password.c_str(), TRUE ) == noErr )
                        {
                            found        = true;
                            validPassord = password;
                            
                            break;
                        }
                    }
                }
            }
            
            if( this->_threadsRunning == 0 )
            {
                break;
            }
            
            {
                unsigned long done;
                unsigned long last;
                unsigned long total;
                char          percent[ 4 ] = { 0, 0, 0, 0 };
                
                done            = this->_processed;
                last            = ( this->_progress == 0 ) ? done : done - this->_lastProcessed;
                total           = this->_numberOfPasswordsToTest;
                this->_progress = static_cast< double >( done ) / static_cast< double >( total );
                
                sprintf( percent, "%.0f", this->_progress * 100 );
                
                this->_message          = std::string( "Trying " )
                                        + std::to_string( total )
                                        + " passwords - "
                                        + percent
                                        + "% (~"
                                        + std::to_string( last )
                                        + " / sec)";
                this->_lastProcessed    = done;
                this->_secondsRemaining = ( total - done ) / last;
            }
        }
        
        {
            std::lock_guard< std::recursive_mutex > l( this->_rmtx );
            
            this->_running     = false;
            this->_message     = "";
            this->_initialized = false;
            
            if( this->_completion != nullptr )
            {
                this->_completion( found, validPassord );
            }
            
            this->_completion = nullptr;
        }
    }
    
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
        
        for( i = 0, n = static_cast< size_t >( pow( 2, length ) ); i < n; i++ )
        {
            for( j = 0; j < length; j++ )
            {
                permutation[ j ] = ( ( i >> j & 1 ) != 0 ) ? static_cast< char >( toupper( cp[ j ] ) ) : cp[ j ];
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
