#include <list>
#include <vector>
#include <string.h>
#include <pthread.h>
#include <cstring>
#include <jni.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <dlfcn.h>
#include <sys/stat.h>

#include "Includes/Logger.h"
#include "Includes/obfuscate.h"
#include "Includes/Utils.h"
#include "Includes/PatternScanner.h"
#include <SOCKET/server.h>
#include "KittyMemory/MemoryPatch.h"

//Target lib — DIISI SAAT RUNTIME via ConfigMode dari client
//(pengaturan "Target lib" di halaman Settings aplikasi).
//Default "libil2cpp.so" bila client tidak mengirim config.
static char g_targetLib[128] = "libil2cpp.so";
static bool g_targetLibSet = false;
#define targetLibName g_targetLib

#include "Includes/Macros.h"


enum Mode {
    InitMode = 1,
    HackMode = 2,
    StopMode = 3,
    ConfigMode = 4, // client mengirim nama lib target
    EspMode = 99,
};


struct Request {
    int Mode;
    bool boolean;
    int value;
    int screenWidth;
    int screenHeight;
};

// Pesan konfigurasi dari client (lihat SOCKET/IncludeClient.h).
// Wajib identik dengan definisi di sisi client!
struct ConfigRequest {
    int Mode;          // = Mode::ConfigMode (4)
    char libName[128]; // nama lib target dari Settings
};

#define maxplayerCount 54

struct PlayerData {
    char PlayerName[64];
    // string *Test;
    float Health;
    float Distance2;
    bool get_IsDieing;
    bool isBot;
    Vector3 CloseEnemyHeadLocation;
    Vector3 HeadLocation;
    Vector3 ToeLocation;
    Vector2 RShoulder;
    Vector3 LShoulder;
    Vector3 Toe;
    Vector3 Hip;
    Vector3 Head;
    int x;
    int y;
    int z;
    int id;
    int h;
    char debug[60];
};

struct Response {
    bool Success;
    int PlayerCount;
    PlayerData Players[maxplayerCount];
};

SocketServer server;

int InitServer() {
    if (!server.Create()) {
        return -1;
    }
    if (!server.Bind()) {
        return -1;
    }
    if (!server.Listen()) {
        return -1;
    }
    return 0;
}
enum f {
    f1 = 4,
    f2 = 5,
    f3 = 6,
    f4 = 7,
    f5 = 8,
    f6 = 9,
    f7 = 10,
    f8 = 11,
    f9 = 12,
    f10 = 13,
    f11 = 504, // Dump Game Files (tombol 500 di menu)
};
// fancy struct for patches for kittyMemory
struct My_Patches {
    // let's assume we have patches for these functions for whatever game
    // like show in miniMap boolean function
    MemoryPatch GodMode,
    GodMode2,
    SliderExample;
    // etc...
} hexPatches;

// ============================================================
// AUTO-UPDATE PATCH SYSTEM (signature-based, tahan game update)
// ------------------------------------------------------------
// Offset hardcoded (0x123456) MATI setiap game update. Sistem ini
// menggantinya dengan SIGNATURE (pola bytes gaya IDA: "AA BB ?? CC").
// Saat lib di-inject, Thread() otomatis scan memory libil2cpp.so dan
// mengubah signature jadi offset -> patch. Selama pola bytes di sekitar
// fungsi target tidak berubah drastis, patch tetap ketemu walau game update.
//
// CARA TAMBAH FITUR BARU:
//   1. Tekan tombol "Dump Game Files" di menu (f::f11).
//      Hasil: /sdcard/Android/data/com.kiloo.subwaysurf/files/SubwayDump/
//             berisi libil2cpp.so + base.apk
//   2. Di PC: unzip base.apk -> assets/bin/Data/Managed/Metadata/
//      global-metadata.dat. Jalankan Il2CppDumper(libil2cpp.so +
//      global-metadata.dat) -> dump.cs
//   3. Cari method target di dump.cs, buka alamatnya di IDA/Ghidra,
//      copy ~16-32 bytes pertama. Ganti bytes yang berubah-ubah
//      (alamat/offset/register) dengan "??".
//   4. Tambah satu baris di g_dynPatches:
//      { "NamaFitur", "AA BB ?? CC ...", "bytes pengganti hex" },
//   5. Di CreateServer(), tambah handler:
//      } else if (request.Mode == f::fXX) {
//          setDynamicPatch("NamaFitur", request.boolean);
//          response.Success = true;
//      }
//   6. Di Main.cpp: tambah "NNN_Toggle_Nama Fitur" di features[],
//      tambah fXX = NNN+4 di enum f, dan case NNN di Changes().
// ============================================================
struct DynamicPatch {
    const char *name;       // nama fitur, dipakai setDynamicPatch()
    const char *signature;  // pola IDA, mis. "00 00 80 D2 ?? ?? ?? ?? C0 03 5F D6"
    const char *patchHex;   // bytes pengganti (hex, spasi opsional)
    MemoryPatch patch;      // terisi otomatis setelah resolveDynamicPatches()
};

// DAFTAR PATCH AKTIF. "GodMode" di bawah memakai SIGNATURE PLACEHOLDER -
// GANTI dengan signature asli dari hasil dump sebelum dipakai!
static DynamicPatch g_dynPatches[] = {
    // Contoh ARM64: fungsi yang me-return false (00 00 80 D2) lalu RET (C0 03 5F D6).
    // "??" menutupi bytes yang bisa berubah antar update.
    { "GodMode", "AA BB CC DD EE FF 11 22 33 44 55 66 77 88 99 00",
      "00 00 80 D2 C0 03 5F D6" },
};
static const int g_dynPatchCount = sizeof(g_dynPatches) / sizeof(g_dynPatches[0]);

// Scan semua signature -> bikin MemoryPatch. Dipanggil sekali dari Thread()
// setelah libil2cpp.so ke-load. Return jumlah patch yang berhasil.
static int resolveDynamicPatches() {
    int ok = 0;
    for (int i = 0; i < g_dynPatchCount; i++) {
        DynamicPatch &dp = g_dynPatches[i];
        uintptr_t off = PatternScanner::findOffset(targetLibName, dp.signature);
        if (off != 0) {
            dp.patch = MemoryPatch::createWithHex(targetLibName, off, dp.patchHex);
            if (dp.patch.isValid()) {
                LOGI(OBFUSCATE("[DynPatch] %s -> offset 0x%lx OK"), dp.name, (unsigned long)off);
                ok++;
            } else {
                LOGE(OBFUSCATE("[DynPatch] %s: offset ketemu tapi patch gagal dibuat"), dp.name);
            }
        } else {
            LOGE(OBFUSCATE("[DynPatch] %s: SIGNATURE TIDAK KETEMU - isi signature asli di g_dynPatches"), dp.name);
        }
    }
    LOGI(OBFUSCATE("[DynPatch] %d/%d patch berhasil di-resolve"), ok, g_dynPatchCount);
    return ok;
}

// Nyalakan/matikan patch dinamis by name. Return false bila nama tidak ada
// atau patch-nya tidak valid (signature belum diisi / tidak ketemu).
static bool setDynamicPatch(const char *name, bool enable) {
    for (int i = 0; i < g_dynPatchCount; i++) {
        if (strcmp(name, g_dynPatches[i].name) == 0) {
            MemoryPatch &p = g_dynPatches[i].patch;
            if (!p.isValid()) {
                LOGE(OBFUSCATE("[DynPatch] %s: patch tidak valid (cek log resolve)"), name);
                return false;
            }
            return enable ? p.Modify() : p.Restore();
        }
    }
    LOGE(OBFUSCATE("[DynPatch] %s: nama tidak ada di g_dynPatches"), name);
    return false;
}

// ============================================================
// AUTO DUMP: salin libil2cpp.so + base.apk milik game ke folder
// yang bisa diakses user (/sdcard/...), untuk dianalisis di PC
// dengan Il2CppDumper. Berjalan DI DALAM proses game sehingga bisa
// membaca file APK & lib miliknya sendiri TANPA root.
// Trigger: tombol "Dump Game Files" di menu (f::f11).
// ============================================================
#define DUMP_PKG_NAME "com.kiloo.subwaysurf"

static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static bool copyFile(const char *src, const char *dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in.is_open()) return false;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << in.rdbuf();
    out.flush();
    return in.good() && out.good();
}

// Ambil path file milik proses ini dari /proc/self/maps.
// needle: "libil2cpp.so" atau "base.apk"
static bool findOwnFilePath(const char *needle, char *out, size_t outSize) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, needle)) continue;
        char *path = strrchr(line, ' ');
        if (!path) continue;
        path++; // lewati spasi
        size_t n = strlen(path);
        while (n > 0 && (path[n - 1] == '\n' || path[n - 1] == '\r')) path[--n] = '\0';
        if (n == 0) continue;
        snprintf(out, outSize, "%s", path);
        found = true;
        break;
    }
    fclose(fp);
    return found;
}

static bool dumpGameFiles() {
    char outDir[256];
    snprintf(outDir, sizeof(outDir), "/sdcard/Android/data/%s/files/SubwayDump", DUMP_PKG_NAME);
    mkdir_p(outDir);

    char libPath[512] = {0}, apkPath[512] = {0};
    bool gotLib = findOwnFilePath(g_targetLib, libPath, sizeof(libPath));
    bool gotApk = findOwnFilePath("base.apk", apkPath, sizeof(apkPath));
    bool ok = true;

    if (gotLib) {
        char dst[512];
        snprintf(dst, sizeof(dst), "%s/%s", outDir, g_targetLib);
        if (copyFile(libPath, dst)) {
            LOGI(OBFUSCATE("[Dump] %s tersalin"), g_targetLib);
        } else {
            LOGE(OBFUSCATE("[Dump] gagal menyalin %s"), g_targetLib);
            ok = false;
        }
    } else {
        LOGE(OBFUSCATE("[Dump] %s tidak ketemu di /proc/self/maps"), g_targetLib);
        ok = false;
    }

    if (gotApk) {
        char dst[512];
        snprintf(dst, sizeof(dst), "%s/base.apk", outDir);
        if (copyFile(apkPath, dst)) {
            LOGI(OBFUSCATE("[Dump] base.apk tersalin"));
        } else {
            LOGE(OBFUSCATE("[Dump] gagal menyalin base.apk"));
            ok = false;
        }
    } else {
        LOGE(OBFUSCATE("[Dump] base.apk tidak ketemu di /proc/self/maps"));
        ok = false;
    }

    LOGI(OBFUSCATE("[Dump] selesai -> %s"), outDir);
    return ok;
}

bool feature1, feature2, featureHookToggle, Health;
int sliderValue = 1, level = 0;
void *instanceBtn;

// Hooking examples. Assuming you know how to write hook
void (*AddMoneyExample)(void *instance, int amount);

bool (*old_get_BoolExample)(void *instance);
bool get_BoolExample(void *instance) {
    if (instance != NULL && featureHookToggle) {
        return true;
    }
    return old_get_BoolExample(instance);
}

float (*old_get_FloatExample)(void *instance);
float get_FloatExample(void *instance) {
    if (instance != NULL && sliderValue > 1) {
        return (float) sliderValue;
    }
    return old_get_FloatExample(instance);
}

int (*old_Level)(void *instance);
int Level(void *instance) {
    if (instance != NULL && level) {
        return (int) level;
    }
    return old_Level(instance);
}

void (*old_FunctionExample)(void *instance);
void FunctionExample(void *instance) {
    instanceBtn = instance;
    if (instance != NULL) {
        if (Health) {
            *(int *) ((uint64_t) instance + 0x48) = 999;
        }
    }
    return old_FunctionExample(instance);
}



void createDataList(Response& response) {}


void *CreateServer(void *) {
    if (InitServer() == 0) {
        if (server.Accept()) {
            // Buffer 512 byte: cukup untuk Request maupun ConfigRequest.
            // (Protokol length-prefixed, jadi ukuran pesan bervariasi.)
            char msgBuf[512];
            while (server.receive((void*)msgBuf) > 0) {
                Response response {};
                int mode = *(int *)msgBuf;
                if (mode == Mode::ConfigMode) {
                    // Client mengirim nama lib target dari halaman Settings.
                    ConfigRequest *cfg = (ConfigRequest *)msgBuf;
                    cfg->libName[sizeof(cfg->libName) - 1] = '\0';
                    if (cfg->libName[0] != '\0') {
                        snprintf(g_targetLib, sizeof(g_targetLib), "%s", cfg->libName);
                        g_targetLibSet = true;
                        LOGI(OBFUSCATE("[Config] target lib: %s"), g_targetLib);
                    }
                    response.Success = true;
                } else {
                    Request *request = (Request *)msgBuf;
                if (request->Mode == Mode::InitMode) {
                    response.Success = true;
                } else if (request->Mode == Mode::HackMode) {

                    response.Success = true;
                } else if (request->Mode == Mode::EspMode) {

                    createDataList(response);
                    response.Success = true;
                } else if (request->Mode == f::f1) {

                    feature2 = request->boolean;

                    // GodMode via AUTO-UPDATE signature (entry "GodMode" di g_dynPatches).
                    // Pastikan signature sudah diisi dari hasil dump, kalau tidak
                    // setDynamicPatch() return false dan ada pesan di logcat.
                    if (setDynamicPatch("GodMode", feature2)) {
                        LOGI(OBFUSCATE("GodMode %s"), feature2 ? "ON" : "OFF");
                    } else {
                        LOGE(OBFUSCATE("GodMode gagal: isi signature asli di g_dynPatches dulu"));
                    }
                    response.Success = true;
                } else if (request->Mode == f::f2) {
                    sliderValue = request->value;
                    response.Success = true;
                } else if (request->Mode == f::f3) {
                    int value = request->value;
                    switch (value) {
                        //For noobies
                        case 0:
                            hexPatches.SliderExample = MemoryPatch::createWithHex(
                                targetLibName, string2Offset(
                                    OBFUSCATE("0x100000")),
                                OBFUSCATE(
                                    "00 00 A0 E3 1E FF 2F E1"));
                            hexPatches.SliderExample.Modify();
                            break;
                        case 1:
                            hexPatches.SliderExample = MemoryPatch::createWithHex(
                                targetLibName, string2Offset(
                                    OBFUSCATE("0x100000")),
                                OBFUSCATE("01 00 A0 E3 1E FF 2F E1"));
                            hexPatches.SliderExample.Modify();
                            break;
                        case 2:
                            hexPatches.SliderExample = MemoryPatch::createWithHex(
                                targetLibName,
                                string2Offset(
                                    OBFUSCATE("0x100000")),
                                OBFUSCATE(
                                    "02 00 A0 E3 1E FF 2F E1"));
                            hexPatches.SliderExample.Modify();
                            break;
                    }
                    response.Success = true;
                } else if (request->Mode == f::f4) {
                    int value = request->value;
                    switch (value) {
                        case 0:
                            LOGD(OBFUSCATE("Selected item 1"));
                            break;
                        case 1:
                            LOGD(OBFUSCATE("Selected item 2"));
                            break;
                        case 2:
                            LOGD(OBFUSCATE("Selected item 3"));
                            break;
                    }
                    response.Success = true;
                } else if (request->Mode == f::f5) {
                    int value = request->value;

                    response.Success = true;
                } else if (request->Mode == f::f6) {
                    featureHookToggle = request->boolean;
                    response.Success = true;
                } else if (request->Mode == f::f7) {
                    level = request->value;
                    response.Success = true;
                } else if (request->Mode == f::f11) {
                    // Tombol "Dump Game Files": salin libil2cpp.so + base.apk
                    // ke /sdcard/Android/data/<pkg>/files/SubwayDump/
                    response.Success = dumpGameFiles();
                }
                } // end else (mode != ConfigMode)
                server.sendX((void*)& response, sizeof(response));
            }
        }
    }
    return nullptr;
}


void* Thread (void *) {
    // Tunggu config (nama lib target) dari client max ~15 detik.
    // Kalau tidak ada (client lama), pakai default g_targetLib.
    for (int i = 0; i < 15 && !g_targetLibSet; i++) {
        sleep(1);
    }
    LOGI(OBFUSCATE("[Thread] target lib: %s"), g_targetLib);

    ProcMap il2cppMap;
    do {
        il2cppMap = KittyMemory::getLibraryMap(g_targetLib);
        sleep(1);
    } while (!il2cppMap.isValid());

    // AUTO-UPDATE: resolve semua signature di g_dynPatches jadi offset.
    // Dipanggil sekali di sini; patch di-toggle dari CreateServer().
    resolveDynamicPatches();

    #if defined(__aarch64__) //To compile this code for arm64 lib only. Do not worry about greyed out highlighting code, it still works
    // GodMode sekarang AUTO-UPDATE via signature (entry "GodMode" di g_dynPatches).
    // Tidak ada lagi offset hardcoded di sini.
    // ARM64 assembly example
    // MOV X0, #0x0 = 00 00 80 D2
    // RET = C0 03 5F D6
    //You can also specify target lib like this
    hexPatches.GodMode2 = MemoryPatch::createWithHex("libtargetLibHere.so",
        string2Offset(OBFUSCATE("0x222222")),
        OBFUSCATE("20 00 80 D2 C0 03 5F D6"));

    // Hook example. Comment out if you don't use hook
    // Strings in macros are automatically obfuscated. No need to obfuscate!
    HOOK("str", FunctionExample, old_FunctionExample);
    HOOK_LIB("libFileB.so", "0x123456", FunctionExample, old_FunctionExample);
    HOOK_NO_ORIG("0x123456", FunctionExample);
    HOOK_LIB_NO_ORIG("libFileC.so", "0x123456", FunctionExample);
    HOOKSYM("__SymbolNameExample", FunctionExample, old_FunctionExample);
    HOOKSYM_LIB("libFileB.so", "__SymbolNameExample", FunctionExample, old_FunctionExample);
    HOOKSYM_NO_ORIG("__SymbolNameExample", FunctionExample);
    HOOKSYM_LIB_NO_ORIG("libFileB.so", "__SymbolNameExample", FunctionExample);

    // Patching offsets directly. Strings are automatically obfuscated too!
    PATCHOFFSET("0x20D3A8", "00 00 A0 E3 1E FF 2F E1");
    PATCHOFFSET_LIB("libFileB.so", "0x20D3A8", "00 00 A0 E3 1E FF 2F E1");

    AddMoneyExample = (void(*)(void *, int))getAbsoluteAddress(targetLibName, 0x123456);

    #else //To compile this code for armv7 lib only.
    // GodMode sekarang AUTO-UPDATE via signature (entry "GodMode" di g_dynPatches).
    // Tidak ada lagi offset hardcoded di sini.
        // New way to patch hex via KittyMemory without need to specify len. Spaces or without spaces are fine
    // ARMv7 assembly example
    // MOV R0, #0x0 = 00 00 A0 E3
    // BX LR = 1E FF 2F E1
    //You can also specify target lib like this
    hexPatches.GodMode2 = MemoryPatch::createWithHex("libtargetLibHere.so",
        string2Offset(OBFUSCATE("0x222222")),
        OBFUSCATE("01 00 A0 E3 1E FF 2F E1"));

    // Hook example. Comment out if you don't use hook
    // Strings in macros are automatically obfuscated. No need to obfuscate!
    HOOK("str", FunctionExample, old_FunctionExample);
    HOOK_LIB("libFileB.so", "0x123456", FunctionExample, old_FunctionExample);
    HOOK_NO_ORIG("0x123456", FunctionExample);
    HOOK_LIB_NO_ORIG("libFileC.so", "0x123456", FunctionExample);
    HOOKSYM("__SymbolNameExample", FunctionExample, old_FunctionExample);
    HOOKSYM_LIB("libFileB.so", "__SymbolNameExample", FunctionExample, old_FunctionExample);
    HOOKSYM_NO_ORIG("__SymbolNameExample", FunctionExample);
    HOOKSYM_LIB_NO_ORIG("libFileB.so", "__SymbolNameExample", FunctionExample);

    // Patching offsets directly. Strings are automatically obfuscated too!
    PATCHOFFSET("0x20D3A8", "00 00 A0 E3 1E FF 2F E1");
    PATCHOFFSET_LIB("libFileB.so", "0x20D3A8", "00 00 A0 E3 1E FF 2F E1");

    AddMoneyExample = (void (*)(void *, int)) getAbsoluteAddress(targetLibName, 0x123456);

    LOGI(OBFUSCATE("Done"));
    #endif

    return NULL;

}


__attribute__((constructor))
void lib_main() {
    pthread_t PidThread;
    pthread_create(&PidThread, NULL, Thread, NULL);
    pthread_t ptid;
    pthread_create(&ptid, nullptr, CreateServer, nullptr);

}
