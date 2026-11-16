# Building Windows drivers without a system-wide WDK

This directory documents how to build kernel drivers for winrbd (and the
pinned WNBD reference driver) on a Windows machine **without installing the
Windows Driver Kit (WDK) system-wide**. The toolchain is:

- Visual Studio 2022 Build Tools (MSVC v143), with the Spectre-mitigated
  libraries component added;
- the Windows SDK and WDK taken from Microsoft's NuGet packages, restored into
  a private directory;
- a small set of MSBuild property sheets (in `msbuild/`) that replace the
  "WindowsKernelModeDriver10.0" platform toolset which the WDK Visual Studio
  extension would normally install.

Everything lives in one build directory of your choice (below: `D:\wb`).
Nothing is written under `Program Files` except the optional Spectre
component in the Build Tools install.

Binaries produced this way are **unsigned**. See "Signing" at the end.

## What was verified

| Item | Value |
|---|---|
| Visual Studio Build Tools | 2022, 17.13 (MSVC 14.43) |
| Windows SDK / WDK packages | `10.0.26100.6584` (targets `10.0.26100.0`) |
| WNBD reference tree | `third_party/wnbd`, commit `20e029d04df111a1a4ef12e98130a73491dee6d4` (0.7.0) |
| Result | `driver.vcxproj`, Release x64 builds cleanly to `wnbd.sys` (about 76 KiB) |

`wnbd.sys` from the verification build: PE32+ x64, subsystem Native,
entry point `GsDriverEntry`, imports `storport.sys`, no Authenticode signature.
The file is not bit-for-bit reproducible between builds (the PE timestamp
differs), so compare structure, not hashes.

## 1. Prerequisites

1. **Visual Studio 2022 Build Tools** with the "Desktop development with C++"
   workload (MSVC v143 x64/x86 build tools, a Windows 10/11 SDK).
2. **Spectre-mitigated libraries**, as an extra component of the same install.
   From an elevated prompt:

   ```
   "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify ^
     --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" ^
     --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre ^
     --quiet --norestart
   ```

   Component id: `Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre`
   (the "latest MSVC" Spectre libraries). Afterwards
   `...\VC\Tools\MSVC\<version>\lib\spectre\x64` must exist.

   Note: the WNBD kernel driver itself is compiled with `/kernel` and links no
   C runtime, so it builds without these libraries. They are needed for the
   user-mode parts (`libwnbd`, `wnbd-client`) and for any user-mode tool of
   ours that enables Spectre mitigation, so install them up front.
3. `git` and the pinned WNBD sources (`git submodule update --init
   --recursive`, then copy or clone `third_party/wnbd` into the build directory;
   do not build inside the submodule).
4. `nuget.exe` (command line), from <https://dist.nuget.org/>. It is
   Authenticode-signed by Microsoft; check with
   `Get-AuthenticodeSignature .\nuget.exe` (Status `Valid`, signer
   `Microsoft Corporation`).

## 2. WDK from NuGet

Packages (all from nuget.org, all published by Microsoft):

| Package id | Version |
|---|---|
| `Microsoft.Windows.WDK.x64` | `10.0.26100.6584` |
| `Microsoft.Windows.SDK.CPP` | `10.0.26100.6584` (dependency) |
| `Microsoft.Windows.SDK.CPP.x64` | `10.0.26100.6584` (dependency) |

`Microsoft.Windows.WDK.x64` depends on `Microsoft.Windows.SDK.CPP.x64`
`[10.0.26100, 10.0.26101)`, which in turn pulls `Microsoft.Windows.SDK.CPP`.
The SDK packages are large (about 160 MB, 52 MB) and the WDK package about
110 MB. The WDK package requires license acceptance (`LICENSE.txt` inside the
package); by restoring it you accept the WDK license terms.

SHA-256 of the `.nupkg` files used:

```
5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0  microsoft.windows.sdk.cpp.10.0.26100.6584.nupkg
c29ce7a4641cb37ee32ebb8078cc65cfbabc7025076bcfba869039204b1e960d  microsoft.windows.sdk.cpp.x64.10.0.26100.6584.nupkg
c393d03dfb640b5c92f546b32f6770ef68cd3aaf691956e7d66d8e2c28a1b55e  microsoft.windows.wdk.x64.10.0.26100.6584.nupkg
```

### Verifying the signatures

Every package from nuget.org carries a repository countersignature, and
Microsoft's packages also carry an author signature (`.signature.p7s` inside
the `.nupkg`). Verify them before use:

```
nuget.exe verify -Signatures <dir>\*.nupkg
```

Expected: "Successfully verified package" for each file. Without Windows, the
signer chain can be inspected with OpenSSL (the author certificate subject is
`CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington,
C=US`; the countersignature is `NuGet.org Repository by Microsoft`):

```
unzip -p pkg.nupkg .signature.p7s > sig.p7s
openssl cms -verify -noverify -inform DER -in sig.p7s -binary -out /dev/null -certsout certs.pem
openssl crl2pkcs7 -nocrl -certfile certs.pem | openssl pkcs7 -print_certs -noout
```

If the build machine has a slow internet connection, download the three files
elsewhere, copy them into a local feed directory, and restore from there:

```
mkdir D:\wb\nuget-local        (put the three .nupkg files here)
nuget.exe install Microsoft.Windows.WDK.x64 -Version 10.0.26100.6584 ^
  -Source D:\wb\nuget-local -OutputDirectory D:\wb\packages ^
  -NoHttpCache -NonInteractive -DirectDownload
```

This produces `D:\wb\packages\Microsoft.Windows.WDK.x64.10.0.26100.6584`
plus the two SDK package directories.

## 3. The toolset shim

The WDK normally ships a Visual Studio extension that registers the platform
toolset `WindowsKernelModeDriver10.0`. The NuGet WDK contains the property
sheets and build targets but not that registration, so a stock driver project
fails to load on a machine without the extension. The three files in
[`msbuild/`](msbuild/) provide the missing glue on top of the stock `v143`
toolset:

| File | Imported | What it does |
|---|---|---|
| `winrbd-wdk-1-nuget.props` | before `Microsoft.Cpp.Default.props` | Imports the three NuGet packages' props and appends the trailing backslash their `WDKContentRoot` / `WindowsSdkDir` lack. |
| `winrbd-wdk-2-toolset.props` | after `Microsoft.Cpp.props` | Marks the build as kernel mode, imports `WDK.props` (include / lib path properties) and the WDK driver property sheets. Sets `SignMode=Off`. |
| `winrbd-wdk-3-toolset.targets` | after `Microsoft.Cpp.targets` | Imports the WDK driver build targets (WPP, message compiler, INF stamping, catalog). |

Inputs, overridable on the msbuild command line: `WinrbdWdkDir` (where these
three files are), `WinrbdPackages` (the restored packages directory, with
trailing backslash), `WinrbdWdkVersion` (default `10.0.26100.6584`).

`SignMode=Off` matters. Without it, the WDK targets create a self-signed
"WDKTestCert" in the current user's certificate store and test-sign the output
with it. The shim prevents that so a build never touches any certificate.

## 4. Retargeting the reference WNBD driver

WNBD's `vstudio/driver.vcxproj` targets VS2019 and the WDK installed with the
platform toolset `WindowsKernelModeDriver10.0`. [`wnbd-retarget.patch`](wnbd-retarget.patch)
changes it, in the **build copy only**, to:

- `PlatformToolset` `v143` (three configurations);
- `WindowsTargetPlatformVersion` fixed at `10.0.26100.0`;
- the three imports of the shim above plus one property, `WinrbdWdkDir`.

That is 6 added and 4 changed lines in one file; no source file changes.
The patch itself has LF line endings (git normalizes the project file's CRLF
in the index), and a plain `git apply` works on the Windows working copy
whether `core.autocrlf` is `true` or `false` (the project file is marked
`eol=crlf`). Apply it from the root of the WNBD copy:

```
git apply <path>\wnbd-retarget.patch
```

### Version header

`driver.h`, `userspace.c` and `wnbd.rc` include `include/version.h`, which WNBD's solution
generates with `vstudio/generate_version_h.ps1` (a build_deps step we skip when
building only the driver project). The script needs `git describe` to work
(tags present, and a branch checked out, not a detached HEAD) and `stampinf.exe`
on `PATH`:

```
git checkout -B build <pinned-commit>
$env:Path += ';D:\wb\packages\Microsoft.Windows.WDK.x64.10.0.26100.6584\c\bin\10.0.26100.0\x64'
powershell -ExecutionPolicy Bypass -File vstudio\generate_version_h.ps1
```

Both generated files (`include/version.h`, `vstudio/wnbd.inf`) are ignored by
git.

## 5. Build

From a normal command prompt (the batch file sets up the MSVC environment):

```
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
cd /d D:\wb\wnbd\vstudio
msbuild driver.vcxproj /m:16 /nologo ^
  /p:Configuration=Release /p:Platform=x64 ^
  /p:SolutionDir=D:\wb\wnbd\vstudio\ ^
  /p:WinrbdPackages=D:\wb\packages\ ^
  /p:WinrbdWdkDir=D:\wb\winrbd-wdk\ ^
  /v:minimal
```

`D:\wb\winrbd-wdk\` holds a copy of the three files from `msbuild/`.
`/m:16` caps msbuild's parallelism; raise or lower it to taste.

Outputs, under `vstudio\x64\Release\`: `wnbd.sys`, `wnbd.inf`,
`driver\wnbd.cat` (an unsigned catalog), and `pdb\driver\wnbd.pdb`.

### Checking the result

Run these from the same Developer Command Prompt (`dumpbin` is only on `PATH`
after `VsDevCmd.bat`):

```
dumpbin /headers vstudio\x64\Release\wnbd.sys
dumpbin /imports vstudio\x64\Release\wnbd.sys
```

Expect: `8664 machine (x64)`, `20B magic # (PE32+)`, `1 subsystem (Native)`,
entry point `GsDriverEntry`, and `storport.sys` in the imports. `powershell
Get-AuthenticodeSignature` reports `NotSigned`.

## 6. For winrbd's own driver

Use the same three imports in the new driver project (and the same
`ConfigurationType=Driver`, `DriverType=WDM`, `TargetVersion=Windows10`
properties WNBD uses). Pin `WinrbdWdkVersion` explicitly in the project so a
future package update is a deliberate change, and check the new project for
the notes below.

Known quirks of the shim:

- Only `x64` is wired up (`WDK.x64.*` sheets, `Microsoft.Windows.WDK.x64`).
  ARM64 would need the ARM64 WDK package and the matching sheets.
- The `Analyze` configuration (static driver verifier) is untouched and not
  verified here.
- If msbuild reports `MSB4011` about a sheet imported twice, remove the
  duplicate import from the shim rather than editing the WDK package.

## Signing

The binaries from this procedure are **unsigned**: no test certificate, no
production certificate. Setting up test signing (enabling test-signing mode on
a test machine, creating or choosing a test certificate, signing, installing)
is out of scope here; the project's signing policy is in the top-level
[README.md](../../README.md#signing-policy): development uses test-signing
with Secure Boot off, and the project ships no production-signed binaries.
Never use a certificate you would not hand to the public for test signing.

## Licensing

The property sheets in `msbuild/` are new files under LGPL-2.1-or-later, like other new files in `windows/`. `wnbd-retarget.patch` modifies a WNBD project file and is therefore treated as LGPL-2.1-only, like other WNBD-derived files (see the top-level `LICENSE`).
