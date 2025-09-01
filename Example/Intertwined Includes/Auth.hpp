#pragma once

#include <string>
#include <sstream>
#include <iomanip>

#include <optional>

#pragma comment(lib, "wldap32.lib" )
#pragma comment(lib, "crypt32.lib" )
#pragma comment(lib, "Ws2_32.lib")

#define CURL_STATICLIB 

#include <curl\curl.h>
#include <nlohmann\json.hpp>

#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>
#include <cryptopp/rng.h>

class IntertwinedAuth {
private:

	std::string _AppID, _SessionID, _Hash, _Version, _EncKey, _IV, _LastError;
	inline static std::string _LastRetHash;
	long _LastResponseCode;
	bool _EncryptedAPI, _ForceHash;
	nlohmann::json JsonParser;

	static size_t WriteCallback( void* contents, size_t size, size_t nmemb, void* userp ) {
		( ( std::string* ) userp )->append( ( char* ) contents, size * nmemb );
		return size * nmemb;
	}

	// iterates through every single header callback
	static size_t HeaderCallback( char* buffer, size_t size, size_t nitems, void* userdata )
	{
		std::string BufStr = std::string( buffer );

		/*
		For some reason the 'returnhash' header sometimes gets transmitted as 'Returnhash' occasionally?
		Effect of encoding/encryption? makes no sense.
		*/

		if ( BufStr.substr( 0, 10 ) == "returnhash" ) {
			_LastRetHash = std::string( BufStr.erase( BufStr.find( "returnhash: " ), 12 ) ).substr( 0, 64 );
		}

		if ( BufStr.substr( 0, 10 ) == "Returnhash" ) {
			_LastRetHash = std::string( BufStr.erase( BufStr.find( "Returnhash: " ), 12 ) ).substr( 0, 64 );
		}

		// Debugging
		//std::cout << "Header: " << std::string( buffer, size * nitems ) << std::endl;

		return nitems * size;
	}


	std::string Request( std::string data )
	{
		CURL* curl = curl_easy_init( );

		if ( !curl ) {
			ExitProcess( rand( ) % RAND_MAX );
			return { };
		}

		std::string to_return;

		curl_easy_setopt( curl, CURLOPT_URL, ( _EncryptedAPI ? "https://api.intertwined.solutions/encrypted.php" : "https://api.intertwined.solutions/" ) );

		curl_easy_setopt( curl, CURLOPT_SSL_VERIFYPEER, 0 );
		curl_easy_setopt( curl, CURLOPT_SSL_VERIFYHOST, 0 );

		curl_easy_setopt( curl, CURLOPT_HEADERFUNCTION, HeaderCallback );

		curl_easy_setopt( curl, CURLOPT_POSTFIELDS, data.c_str( ) );

		curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteCallback );
		curl_easy_setopt( curl, CURLOPT_WRITEDATA, &to_return );

		auto code = curl_easy_perform( curl );

		curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &_LastResponseCode );

		if ( _LastResponseCode == 429 ) {
			system( "start cmd.exe /c \"Echo TOO MANY REQUESTS. TRY AGAIN LATER. && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		if ( code != CURLE_OK )
			MessageBoxA( 0, curl_easy_strerror( code ), 0, MB_ICONERROR );

		curl_easy_cleanup( curl );

		return to_return;
	}

	static bool CompareHashes( const std::string s1, const std::string s2, const size_t len ) {

		if ( ( s1.size( ) != s2.size( ) ) || s1.size( ) != len || s2.size( ) != len )
			return false;

		for ( size_t i = 0u; i < len; ++i ) {
			if ( s1.at( i ) != s2.at( i ) )
				return false;
		}

		return true;
	}

	// Thanks to https://www.cryptopp.com/docs/ref/
	class EncryptionClass {
	private:

		// Returns "NONCE_HEX:TAG_HEX:CT_HEX"
		// IV is passed as AAD
		static std::string Encrypt_AEAD_AES256( const std::string& plaintext, const std::string& enckey, const std::string& aad = std::string( ) ) {

			CryptoPP::SecByteBlock key = Key32( enckey );

			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::SecByteBlock nonce( 12 );
			rng.GenerateBlock( nonce, nonce.size( ) );

			CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
			enc.SetKeyWithIV( key, key.size( ), nonce, nonce.size( ) );

			const size_t TAG_LEN = 16; // 128-bit auth tag
			std::string ct_and_tag;

			CryptoPP::AuthenticatedEncryptionFilter aef(
				enc,
				new CryptoPP::StringSink( ct_and_tag ),
				false,      // putAAD = false
				TAG_LEN
			);

			if ( !aad.empty( ) ) {
				aef.ChannelPut( CryptoPP::AAD_CHANNEL, reinterpret_cast< const byte* >( aad.data( ) ), aad.size( ) );
				aef.ChannelMessageEnd( CryptoPP::AAD_CHANNEL );
			}

			aef.ChannelPut( CryptoPP::DEFAULT_CHANNEL, reinterpret_cast< const byte* >( plaintext.data( ) ), plaintext.size( ) );
			aef.ChannelMessageEnd( CryptoPP::DEFAULT_CHANNEL );

			const size_t ct_len = ct_and_tag.size( ) - TAG_LEN;
			const std::string ct = ct_and_tag.substr( 0, ct_len );
			const std::string tag = ct_and_tag.substr( ct_len, TAG_LEN );

			return Bin2Hex( std::string( ( const char* ) nonce.data( ), nonce.size( ) ) )
				+ ":" + Bin2Hex( tag )
				+ ":" + Bin2Hex( ct );
		}

		// Accepts "NONCE_HEX:TAG_HEX:CT_HEX"
		static std::string Decrypt_AEAD_AES256( const std::string& blob_hex, const std::string& enckey, const std::string& aad = std::string( ) ) {

			auto c1 = blob_hex.find( ':' );
			auto c2 = ( c1 == std::string::npos ) ? std::string::npos : blob_hex.find( ':', c1 + 1 );
			if ( c1 == std::string::npos || c2 == std::string::npos )
				throw std::runtime_error( "Bad blob format; expected NONCE:TAG:CT" );

			const std::string nonce = Hex2Bin( blob_hex.substr( 0, c1 ) );
			const std::string tag = Hex2Bin( blob_hex.substr( c1 + 1, c2 - ( c1 + 1 ) ) );
			const std::string ct = Hex2Bin( blob_hex.substr( c2 + 1 ) );

			CryptoPP::SecByteBlock key = Key32( enckey );

			CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
			dec.SetKeyWithIV( key, key.size( ),
				reinterpret_cast< const byte* >( nonce.data( ) ), nonce.size( ) );

			std::string recovered;
			CryptoPP::AuthenticatedDecryptionFilter adf(
				dec,
				new CryptoPP::StringSink( recovered ),
				CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
				static_cast< int >( tag.size( ) )
			);

			if ( !aad.empty( ) ) {
				adf.ChannelPut( CryptoPP::AAD_CHANNEL, reinterpret_cast< const byte* >( aad.data( ) ), aad.size( ) );
				adf.ChannelMessageEnd( CryptoPP::AAD_CHANNEL );
			}

			adf.ChannelPut( CryptoPP::DEFAULT_CHANNEL, reinterpret_cast< const byte* >( ct.data( ) ), ct.size( ) );
			adf.ChannelPut( CryptoPP::DEFAULT_CHANNEL, reinterpret_cast< const byte* >( tag.data( ) ), tag.size( ) );
			adf.ChannelMessageEnd( CryptoPP::DEFAULT_CHANNEL );

			return recovered; // throws if tag check fails
		}

	public:

		std::string SHA256_HMAC( const std::string str, std::string key )
		{
			std::string Ret;

			CryptoPP::SecByteBlock KeyBlock( ( const CryptoPP::byte* ) key.data( ), key.size( ) );
			CryptoPP::HMAC<CryptoPP::SHA256> Hash( KeyBlock, KeyBlock.size( ) );

			try {
				CryptoPP::StringSource hashing( str, true,
					new CryptoPP::HashFilter( Hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink( Ret ),
							false
						)
					)
				);
			}
			catch ( CryptoPP::Exception& ex ) {
				throw std::runtime_error( std::string( "Error hashing" ) );
				exit( -1 );
			}

			return Ret;
		}

		std::string SHA256( const std::string str )
		{
			std::string Ret;

			CryptoPP::SHA256 Hash;

			try {
				CryptoPP::StringSource hashing( str, true,
					new CryptoPP::HashFilter( Hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink( Ret ),
							false
						)
					)
				);
			}
			catch ( CryptoPP::Exception& ex ) {
				throw std::runtime_error( std::string( "Error hashing" ) );
				exit( -1 );
			}

			return Ret;
		}

		std::string GenerateRandIV( ) {

			CryptoPP::byte Buf[ 16 ];

			// Generate random block
			CryptoPP::AutoSeededRandomPool ASRP;
			ASRP.GenerateBlock( Buf, 16 );


			std::string Ret;
			CryptoPP::ArraySource arr( Buf, 16, true,
				new CryptoPP::HexEncoder(
					new CryptoPP::StringSink( Ret )
				)
			);

			return Ret;

		}

		static std::string B64DecodeStrict( const std::string& b64 ) {
			std::string out;
			CryptoPP::StringSource( b64, true,
				new CryptoPP::Base64Decoder( new CryptoPP::StringSink( out ) ) );
			return out;
		}

		static CryptoPP::SecByteBlock Key32( const std::string& enckey ) {
			std::string b = B64DecodeStrict( enckey );
			if ( b.size( ) == 32 )
				return CryptoPP::SecByteBlock( ( const byte* ) b.data( ), b.size( ) );

			throw std::runtime_error( "Invalid EncKey; expected base64(32B)" );
			exit( -1 );
		}

		std::string Encrypt( const std::string& PlainText, const std::string& Key, const std::string& aad = "" ) {
			return Encrypt_AEAD_AES256( PlainText, Key, aad );
		}

		std::string Decrypt( const std::string& BlobHex, const std::string& Key, const std::string& aad = "" ) {
			return Decrypt_AEAD_AES256( BlobHex, Key, aad );
		}

		static std::string Bin2Hex( const std::string& in ) {
			std::string Hex;

			try {
				CryptoPP::StringSource encoding( in, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink( Hex ),
						false
					)
				);
			}
			catch ( CryptoPP::Exception& ex ) {
				throw std::runtime_error( std::string( "Error converting " + in + " to hexadecimal" ) );
				exit( -1 );
			}

			return Hex;
		}

		static std::string Hex2Bin( const std::string& in ) {
			std::string Binary;

			try {
				CryptoPP::StringSource decoding( in, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StringSink( Binary )
					)
				);
			}
			catch ( CryptoPP::Exception& ex ) {
				throw std::runtime_error( std::string( "Error converting " + in + " to binary" ) );
				exit( -1 );
			}

			return Binary;
		}
	}Encryption;

public:
	// Constructor
	IntertwinedAuth( std::string AppID, std::string EncKey, std::string Ver, bool ForceHash = false, std::string Hash = "", bool Encrypted = true ) {
		this->_AppID = AppID;
		this->_EncKey = EncKey;
		this->_Version = Ver;
		this->_ForceHash = ForceHash;
		this->_Hash = Hash;
		this->_EncryptedAPI = Encrypted;
	}

	struct UserData {

		UserData( std::string user, int time, int level, std::string ip ) {
			Username = user; this->Expiry = time; this->Level = level; IpAddress = ip;
		}

		// Also used to hold the license when using loginlicense
		std::string Username;
		time_t Expiry;
		int Level;
		std::string IpAddress;
	};

	bool Init( ) {

		this->_IV = Encryption.GenerateRandIV( );

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData {  };

		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "init" ) +
				"&appid=" + Encryption.Bin2Hex( this->_AppID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&hash=" + Encryption.Encrypt( this->_Hash, this->_EncKey, this->_IV ) +
				"&ver=" + Encryption.Encrypt( this->_Version, this->_EncKey, this->_IV );
		}
		else
			ReqData = "type=init&appid=" + this->_AppID + "&hash=" + this->_Hash;

		std::string RawResponse = Request( ReqData );

		if ( !_LastRetHash.length( ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. NO RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;
		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return false;
		}

		this->_SessionID = Parsed[ "sessionid" ];

		return true;
	}

	std::optional<UserData> Login( std::string user, std::string pass, std::string hwid = "" ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to login.";
			throw std::runtime_error( "Please initiate a session before attempting to login." );
			return { };
		}

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "login" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&user=" + Encryption.Encrypt( user, this->_EncKey, this->_IV ) +
				"&pass=" + Encryption.Encrypt( pass, this->_EncKey, this->_IV ) +
				"&hwid=" + Encryption.Encrypt( hwid, this->_EncKey, this->_IV ) +
				"&hash=" + Encryption.Encrypt( this->_Hash, this->_EncKey, this->_IV );
		}
		else
			ReqData = "type=login&sid=" + this->_SessionID + "&user=" + user + "&pass=" + pass + "&hwid=" + hwid + "&hash=" + this->_Hash;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;
		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return { };
		}

		// This will only work if it was successfull.
		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		return UserData( Parsed[ "data" ][ "user" ], Parsed[ "data" ][ "expiry" ], Parsed[ "data" ][ "level" ], Parsed[ "data" ][ "ip" ] );
	}

	std::optional<UserData> LoginLicense( std::string license, std::string hwid = "" ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to login.";
			throw std::runtime_error( "Please initiate a session before attempting to login." );
			return { };
		}

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "loginlicense" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&license=" + Encryption.Encrypt( license, this->_EncKey, this->_IV ) +
				"&hwid=" + Encryption.Encrypt( hwid, this->_EncKey, this->_IV ) +
				"&hash=" + Encryption.Encrypt( this->_Hash, this->_EncKey, this->_IV );
		}
		else
			ReqData = "type=loginlicense&sid=" + this->_SessionID + "&license=" + license + "&hwid=" + hwid + "&hash=" + this->_Hash;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;
		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return { };
		}

		return UserData( Parsed[ "data" ][ "license" ], Parsed[ "data" ][ "expiry" ], Parsed[ "data" ][ "level" ], Parsed[ "data" ][ "ip" ] );
	}


	std::optional<UserData> Register( std::string user, std::string pass, std::string license ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to register.";
			throw std::runtime_error( "Please initiate a session before attempting to register." );
			return { };
		}

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "register" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&license=" + Encryption.Encrypt( license, this->_EncKey, this->_IV ) +
				"&user=" + Encryption.Encrypt( user, this->_EncKey, this->_IV ) +
				"&pass=" + Encryption.Encrypt( pass, this->_EncKey, this->_IV ) +
				"&hash=" + Encryption.Encrypt( this->_Hash, this->_EncKey, this->_IV );
		}
		else
			ReqData = ReqData = "type=register&sid=" + this->_SessionID + "&user=" + user + "&pass=" + pass + "&license=" + license + "&hash=" + this->_Hash;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;

		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return { };
		}

		return UserData( Parsed[ "data" ][ "user" ], Parsed[ "data" ][ "expiry" ], Parsed[ "data" ][ "level" ], Parsed[ "data" ][ "ip" ] );
	}

	std::optional<std::string> WebHook( std::string WebhookID ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to access a webhook.";
			throw std::runtime_error( "Please initiate a session before attempting to access a webhook." );
			return { };
		}

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "webhook" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&whid=" + Encryption.Encrypt( WebhookID, this->_EncKey, this->_IV );
		}
		else
			ReqData = "type=webhook&sid=" + this->_SessionID + "&whid=" + WebhookID;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;

		return Encryption.Hex2Bin( Response );

	}

	std::optional<std::string> GetVariable( std::string VarID ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to access a webhook.";
			throw std::runtime_error( "Please initiate a session before attempting to access a webhook." );
			return { };
		}

		if ( this->_Hash.empty( ) && this->_ForceHash ) {
			this->_LastError = "Please provide a proper hash when using ForceHash.";
			throw std::runtime_error( "Please provide a proper hash when using ForceHash." );
			return { };
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "get_var" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV ) +
				"&var_id=" + Encryption.Encrypt( VarID, this->_EncKey, this->_IV );
		}
		else
			ReqData = "type=get_var&sid=" + this->_SessionID + "&var_id=" + VarID;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;

		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return { };
		}

		return Parsed[ "var" ];
	}

	bool Close( ) {

		if ( this->_SessionID.empty( ) ) {
			this->_LastError = "Please initiate a session before attempting to upgrade.";
			throw std::runtime_error( "Please initiate a session before attempting to upgrade." );
			return false;
		}

		std::string ReqData { };
		if ( this->_EncryptedAPI ) {
			ReqData = "type=" + Encryption.Bin2Hex( "close" ) +
				"&sid=" + Encryption.Bin2Hex( this->_SessionID ) +
				"&iv=" + Encryption.Bin2Hex( this->_IV );
		}
		else
			ReqData = "type=close&sid=" + this->_SessionID;

		std::string RawResponse = Request( ReqData );

		if ( !CompareHashes( _LastRetHash, Encryption.SHA256_HMAC( this->_IV + "." + RawResponse, this->_EncKey ), 64 ) ) {
			system( "start cmd.exe /c \"Echo ERROR WHILE LOADING INTERTWINED. INVALID RETURN HASH. PLEASE TRY AGAIN && timeout 5\"" );
			exit( rand( ) % RAND_MAX );
		}

		std::string Response = this->_EncryptedAPI ? Encryption.Decrypt( RawResponse, this->_EncKey, this->_IV ) : RawResponse;

		auto Parsed = JsonParser.parse( Response );

		if ( !Parsed[ "success" ] ) {
			this->_LastError = Parsed[ "error" ];
			return false;
		}

		return true;
	}

	bool IsInitiated( ) {
		return !this->_SessionID.empty( );
	}

	std::string GetLastError( ) {
		return this->_LastError;
	}

};