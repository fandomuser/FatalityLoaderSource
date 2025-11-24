# Fatality Loader

A modern, sleek DLL loader for Counter-Strike 2 with a clean WPF interface inspired by the original Fatality cheat loader.

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![C#](https://img.shields.io/badge/C%23-Programming-239120?style=for-the-badge&logo=csharp&logoColor=white)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Target](https://img.shields.io/badge/Target-CS2-orange?style=for-the-badge&logo=counter-strike&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

## ✨ Features

- **Modern UI Design**: Clean, dark-themed interface with glitch effects and smooth animations
- **Manual Map Injection**: Robust injection method that works without `-insecure` launch option
- **Local DLL Loading**: Loads `TestDLL_x64.dll` directly from the application directory
- **Real-time Status**: Visual feedback for injection progress
- **Self-Contained Build**: Single executable with embedded .NET runtime (no dependencies required)
- **Silent Operation**: No intrusive message boxes or prompts

## 🔧 Technical Details

- **Framework**: WPF (.NET 8.0)
- **Language**: C#
- **Injection Method**: Manual Map (with TLS support, SEH disabled for compatibility)
- **Target Process**: `cs2.exe`
- **Build Type**: Self-contained single-file executable

## 📦 Building

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022 (with C++ workload for Test DLL)

### Build Instructions

**1. Build the Loader (C#)**
```powershell
dotnet publish FatalityLoader.csproj -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:IncludeNativeLibrariesForSelfExtract=true /p:IncludeAllContentForSelfExtract=true
```

**2. Build the Test DLL (C++)**
Open `TestDLL_CPP/TestDLL_CPP.vcxproj` in Visual Studio and build for **Release x64**.

## 🛡️ Disclaimer

This software is provided for **educational purposes only**. Using cheats or unauthorized modifications in online games may violate the game's Terms of Service and result in account bans. The developers are not responsible for any consequences resulting from the use of this software.

Use at your own risk.

## 📝 License

This project is open-source and available under the MIT License.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📧 Support

For questions or support, please open an issue on this repository.

---

**Note**: This is a fan-made replica of the Fatality loader interface. It is not affiliated with or endorsed by the original Fatality project.
