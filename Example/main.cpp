#include <iostream>
#include <fstream>

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

bool DownloadFileToDisk( IntertwinedAuth* Auth, std::string WHID, std::string OutDir ) {

    if ( !Auth->IsInitiated( ) )
        return false;

    std::string FileContents = Auth->WebHook( WHID ).value_or( "" );
    if ( FileContents.empty( ) )
        return false;

    std::ofstream Out( OutDir, std::ios::binary );
    if ( !Out.is_open( ) )
        return false;

    Out.write( FileContents.data( ), FileContents.size( ) );

    std::cout << "test" << std::endl;
    return true;
}


int main( )
{
    IntertwinedAuth Auth = IntertwinedAuth( "Appid", "Enckey", "Version" );

    if ( !Auth.Init( ) ) {
        std::cout << "Error Initiating: " << Auth.GetLastError( ) << "\n";
        return 0;
    }

    int choice = 0;

    std::cout << "Choose action: License (0), User & Pass (1), Register (2): ";
    std::cin >> choice;

    if ( choice != 0 && choice != 1 && choice != 2) {
        std::cout << "Please choose 0 or 1";
        return 0;
    }

    if ( choice == 2 ) {
        std::string License, User, Pass;

        std::cout << "License: ";
        std::cin >> License;

        std::cout << "Username: ";
        std::cin >> User;

        std::cout << "Pass: ";
        std::cin >> Pass;

        std::optional<IntertwinedAuth::UserData> RegisterResp = Auth.Register( User, Pass, License );

        if ( !RegisterResp ) {
            std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
            return 0;
        }

        IntertwinedAuth::UserData Userdata = RegisterResp.value( );

        std::cout << "User " << Userdata.Username << " registered with license " << License << "\n";

    }
    else if ( choice == 1 ) {

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
    else if ( choice == 0 ) {
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

    /*
    // Get webhook data and store it in a string
    std::optional<std::string> WebhookRet = Auth.WebHook( "WebhookID" );
    if ( !WebhookRet ) {
        std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
        return 0;
    }

    std::cout << "Webhook return: " + WebhookRet.value( ) + "\n";

    // Access a variable and store it in a string
    std::optional<std::string> VarRet = Auth.GetVariable( "VarID" );
    if ( !VarRet ) {
        std::cout << "An unexepected error has occured: " << Auth.GetLastError( );
        return 0;
    }

    std::cout << "Variable return: " + VarRet.value( ) + "\n";*/
    
    // This closes out the session. The sessions which are more than 24 hours long will terminate automatically, but you should still terminate them after you're done.
    Auth.Close( );

    Sleep( -1 );

}
