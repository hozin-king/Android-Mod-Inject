#pragma once
// PatternScanner.h — runtime AoB (Array-of-Bytes) signature scanner.
//
// Kenapa file ini ada: offset hardcoded (mis. 0x123456) MATI setiap game update.
// Solusinya: definisikan patch sebagai SIGNATURE gaya IDA ("AA BB ?? CC"),
// lalu cari alamatnya di memory saat lib di-inject. Selama pola bytes di
// sekitar fungsi target tidak berubah drastis, patch tetap ketemu otomatis
// walau game sudah update -> "auto update".
//
// Cara dapat signature:
//   1. Dump libil2cpp.so + base.apk pakai tombol "Dump Game Files" di menu.
//   2. Di PC: unzip base.apk -> assets/bin/Data/Managed/Metadata/global-metadata.dat
//   3. Il2CppDumper(libil2cpp.so + global-metadata.dat) -> dump.cs
//   4. Cari method target di dump.cs, buka alamatnya di IDA/Ghidra,
//      copy ~16-32 bytes pertama, ganti bytes yang berubah-ubah (alamat/
//      register) dengan "??". Contoh: "00 00 80 D2 ?? ?? ?? ?? C0 03 5F D6"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace PatternScanner {

// Satu entry hasil parse: bytes + mask (true = wildcard/??)
struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask; // true = "??", cocok dengan byte apa pun
    bool valid = false;
};

// Parse pola gaya IDA: "AA BB ?? CC" (spasi opsional, case-insensitive)
inline Pattern parse(const char *pat) {
    Pattern p;
    if (!pat) return p;
    const char *s = pat;
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (*s == '?') {
            p.bytes.push_back(0);
            p.mask.push_back(true);
            while (*s == '?') s++;
        } else {
            unsigned int b = 0;
            if (sscanf(s, "%2x", &b) != 1) return Pattern{};
            p.bytes.push_back((uint8_t)b);
            p.mask.push_back(false);
            s += 2;
        }
    }
    p.valid = !p.bytes.empty();
    return p;
}

// Cari satu pola di rentang memory [start, end). Return alamat ketemu / 0.
inline uintptr_t scanRange(uintptr_t start, uintptr_t end, const Pattern &p) {
    if (!p.valid || end <= start || p.bytes.size() > (end - start)) return 0;
    const uint8_t *base = (const uint8_t *)start;
    size_t n = p.bytes.size();
    size_t len = end - start;
    for (size_t i = 0; i + n <= len; i++) {
        bool ok = true;
        for (size_t j = 0; j < n; j++) {
            if (!p.mask[j] && base[i + j] != p.bytes[j]) { ok = false; break; }
        }
        if (ok) return start + i;
    }
    return 0;
}

// Cari pola di SEMUA segmen executable milik libName di proses ini.
// (Server lib jalan DI DALAM proses game, jadi /proc/self/maps = maps game.)
// Return OFFSET dari base lib (bukan alamat absolut) supaya cocok dengan
// MemoryPatch::createWithHex(lib, offset, ...). Return 0 bila tidak ketemu.
inline uintptr_t findOffset(const char *libName, const char *idaPattern) {
    Pattern p = parse(idaPattern);
    if (!p.valid || !libName) return 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    uintptr_t found = 0;
    while (fgets(line, sizeof(line), fp)) {
        // Format: start-end perms offset dev inode pathname
        // Contoh: 7370b6c000-7370d9a000 r-xp 00000000 ... /.../libil2cpp.so
        if (!strstr(line, libName)) continue;
        if (!strstr(line, "r-xp")) continue; // hanya segmen kode executable
        uintptr_t segStart = 0, segEnd = 0, fileOff = 0;
        if (sscanf(line, "%lx-%lx %*4c %lx", &segStart, &segEnd, &fileOff) != 3)
            continue;
        uintptr_t addr = scanRange(segStart, segEnd, p);
        if (addr) {
            // Offset relatif terhadap awal file lib = addr - segStart + fileOff
            found = (addr - segStart) + fileOff;
            break;
        }
    }
    fclose(fp);
    return found;
}

} // namespace PatternScanner
