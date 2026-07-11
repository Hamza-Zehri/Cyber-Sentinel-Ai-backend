; Cyber Sentinel AI - Inno Setup Installer Script
; Build with: iscc installer.iss
; Requires: Inno Setup 6+ (https://jrsoftware.org/isdl.php)

#define MyAppName "Cyber Sentinel AI"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Cyber Sentinel"
#define MyAppURL "https://github.com/Hamza-Zehri/Cyber-Sentinel-Ai-backend"
#define MyAppExeName "CyberSentinel.exe"

[Setup]
AppId={{F8A2B1C3-4D5E-6F78-9ABC-DEF012345678}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\CyberSentinelAI
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=dist\installer
OutputBaseFilename=CyberSentinelAI-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Dirs]
Name: "{app}\backups"
Name: "{app}\reports"
Name: "{app}\ai_models"
Name: "{app}\data"

[Files]
Source: "dist\CyberSentinel.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Cyber Sentinel AI"; Flags: postinstall nowait skipifsilent shellexec runascurrentuser

[UninstallRun]
Filename: "taskkill"; Parameters: "/F /IM CyberSentinel.exe"; Flags: runhidden
