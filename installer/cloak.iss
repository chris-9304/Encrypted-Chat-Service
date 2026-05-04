; Cloak v0.4.0 — Inno Setup installer script
; Produces:  dist\installer.exe
; Run with:  ISCC.exe installer\cloak.iss  (from the project root)

#define AppName      "Cloak"
#define AppVersion   "0.4.0"
#define AppPublisher "Cloak Project"
#define AppURL       "https://github.com/chris-9304/cloak"
#define AppExeName   "cloak.exe"
#define AppRelayExe  "cloak-relay.exe"
#define DistDir      "..\dist\cloak"
#define OutputDir    "..\dist"

[Setup]
; Fixed GUID — do not change; it identifies this app for upgrades/uninstall
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}

; Install location
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableDirPage=no
DisableProgramGroupPage=no

; Output — named "installer.exe" so users know exactly what to run
OutputDir={#OutputDir}
OutputBaseFilename=installer
SetupIconFile=

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Windows 10 v1809 minimum
MinVersion=10.0.17763

; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Appearance
WizardStyle=modern

; Offer admin OR per-user install (user chooses in the wizard)
PrivilegesRequiredOverridesAllowed=dialog commandline
PrivilegesRequired=lowest

; Misc
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExeName}
ShowLanguageDialog=no
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut";                      GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "addtopath";   Description: "Add cloak.exe to &PATH (use from any terminal)";  GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Files]
; Main application
Source: "{#DistDir}\cloak.exe";       DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\cloak-relay.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

; Runtime DLLs — must ship alongside cloak.exe
Source: "{#DistDir}\libsodium.dll";                               DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\boost_program_options-vc143-mt-x64-1_90.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\sqlite3.dll";                                  DestDir: "{app}"; Flags: ignoreversion

; Visual C++ 2022 Runtime — extracted to temp, installed silently if missing
Source: "{#DistDir}\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Start Menu — launches cloak.exe in a cmd window so it stays open for user input
Name: "{group}\Cloak";              Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName}"""; WorkingDir: "{app}"; Comment: "End-to-End Encrypted P2P Messenger"
Name: "{group}\Cloak Relay Server"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppRelayExe}"" --port 8765";           WorkingDir: "{app}"; Comment: "Cloak relay server"; Check: FileExists(ExpandConstant('{app}\{#AppRelayExe}'))
Name: "{group}\Uninstall Cloak";    Filename: "{uninstallexe}"

; Desktop shortcut (optional task) — same cmd wrapper
Name: "{commondesktop}\Cloak"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName}"""; WorkingDir: "{app}"; Comment: "End-to-End Encrypted P2P Messenger"; Tasks: desktopicon

[Run]
; 1. Install VC++ 2022 Runtime silently if not present
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; Check: VCRedistNeedsInstall; StatusMsg: "Installing Visual C++ 2022 Runtime..."; Flags: waituntilterminated runhidden

; 2. After install: offer to launch Cloak immediately
Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName}"""; WorkingDir: "{app}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent runascurrentuser

[Registry]
; Add install directory to user PATH (skipped if already present)
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsPathEntry('{app}'); Tasks: addtopath

[Code]

{ Check whether the MSVC 2022 x64 runtime is already installed }
function VCRedistNeedsInstall: Boolean;
var
  Installed: Cardinal;
begin
  Result := True;
  if RegQueryDWordValue(HKLM,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64',
      'Installed', Installed) then
    if Installed = 1 then
      Result := False;
end;

{ Avoid duplicating PATH entries }
function NeedsPathEntry(const Candidate: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    Exit;
  end;
  Result := Pos(';' + Uppercase(Candidate) + ';',
                ';' + Uppercase(OrigPath) + ';') = 0;
end;

{ Custom welcome page text }
procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption :=
    'This will install ' + '{#AppName}' + ' {#AppVersion}' + ' on your computer.' + #13#10 + #13#10 +
    'Cloak is an end-to-end encrypted, peer-to-peer terminal messenger.' + #13#10 +
    'No accounts. No servers that can read your messages.' + #13#10 + #13#10 +
    'After installation:' + #13#10 +
    '  - Search "Cloak" in Start Menu and click it' + #13#10 +
    '  - Enter your display name when prompted' + #13#10 +
    '  - Start chatting!' + #13#10 + #13#10 +
    'Click Next to continue.';
end;
