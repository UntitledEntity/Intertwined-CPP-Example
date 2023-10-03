#include <iostream>

#include "Intertwined Includes\Auth.hpp"

std::string GetHWID( ) {
    std::string hwid;
    char volumeName[ MAX_PATH ];
    DWORD serialNumber;
    DWORD maxComponentLen;
    DWORD fileSystemFlags;

    if ( GetVolumeInformationA( "C:\\", volumeName, sizeof( volumeName ), &serialNumber, &maxComponentLen, &fileSystemFlags, NULL, 0 ) ) {
        hwid = std::to_string( serialNumber );
    }
    return hwid;
}

int main( )
{
    IntertwinedAuth Auth = IntertwinedAuth( "Appid", "Enckey", "Version" );

    if ( !Auth.Init( ) ) {
        std::cout << "Error Initiating: " << Auth.GetLastError( ) << "\n";
        return 0;
    }

    int loginchoice = 0;

    std::cout << "Choose login type, License (0), User & Pass (1): ";
    std::cin >> loginchoice;

    if ( loginchoice != 0 && loginchoice != 1 ) {
        std::cout << "Please choose 0 or 1";
        return 0;
    }

    if ( loginchoice == 1 ) {

        std::string User, Pass;

        std::cout << "Username: ";
        std::cin >> User;

        std::cout << "Pass: ";
        std::cin >> Pass;

        std::optional<IntertwinedAuth::UserData> LoginResp = Auth.Login( User, Pass, GetHWID( ) );

        if ( !LoginResp ) {
            std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
            return 0;
        }

        std::cout << "Correct user and password." << "\n";

        IntertwinedAuth::UserData Userdata = LoginResp.value( );

        std::cout << "Welcome " << Userdata.Username << ", your user expires on " << ctime( &( Userdata.Expiry ) ) << "\n";

        std::cout << "You are connecting from " << Userdata.IpAddress << " and you are level " << Userdata.Level << "\n";
    }
    else if ( loginchoice == 0 ) {
        std::string License;

        std::cout << "License: ";
        std::cin >> License;

        std::optional<IntertwinedAuth::UserData> LoginResp = Auth.LoginLicense( License, GetHWID( ) );

        if ( !LoginResp ) {
            std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
            return 0;
        }

        IntertwinedAuth::UserData Userdata = LoginResp.value( );

        std::cout << "Welcome " << Userdata.Username << ", your license expires on " << ctime( &( Userdata.Expiry ) );

        std::cout << "You are connecting from " << Userdata.IpAddress << " and you are level " << Userdata.Level << "\n";
    }
    else
        return 0;

    /*std::optional<std::string> WebhookRet = Auth.WebHook( "AfgVb7hy" );
    if ( !WebhookRet ) {
        std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
        return 0;
    }

    std::cout << "Webhook return: " + WebhookRet.value( ) + "\n";*/

    // This closes out the session. The sessions which are more than 24 hours long will terminate automatically, but you should still terminate them after you're done.
    Auth.Close( );

    Sleep( -1 );

}
