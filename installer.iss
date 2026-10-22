; Inno Setup Script for ServerMon
#define MyAppName "ServerMon"
#define MyAppVersion "1.1"
#define MyAppPublisher "ARTHAZARD"
#define MyAppExeName "ServerMon.exe"

[Setup]
AppId={{5E97D4B6-613A-4E97-897F-C8DF64A31F7B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
OutputDir=dist-installer
OutputBaseFilename=ServerMon-Setup
PrivilegesRequired=lowest
DisableProgramGroupPage=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\ServerMon\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "gui.ui"; DestDir: "{app}"; Flags: ignoreversion
Source: "config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{app}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{userprograms}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\config\*.json"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\_internal\__pycache__"

Type: dirifempty; Name: "{app}\config"
Type: dirifempty; Name: "{app}"