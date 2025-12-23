#pragma once
#include <windows.h>
#include <cstdint>
#include <tlhelp32.h>
#include <string>
#include <psapi.h>

#include "globals.h"

extern "C"
uint64_t ntreadvirtualmemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

namespace memory {
    inline DWORD roblox_process_id = 0;
    inline HANDLE roblox_handle = nullptr;
    inline uintptr_t roblox_base_address = 0;
    inline uintptr_t roblox_base_size = 0;

    inline DWORD get_process_id(std::string& name) {
        DWORD pid = 0;
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (!snapshot || snapshot == INVALID_HANDLE_VALUE) return pid;
        if (!Process32First(snapshot, &pe32)) return pid;
        do {
            if (_strcmpi(pe32.szExeFile, name.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
        CloseHandle(snapshot);
        roblox_process_id = pid;
        return pid;
    }

    inline HANDLE get_process_handle() {
        auto handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE,
            roblox_process_id
        );
        roblox_handle = handle;
        return handle;
    }

    inline uintptr_t get_base_address() {
        uintptr_t base_adress = 0;
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, roblox_process_id);
        if (!snapshot || snapshot == INVALID_HANDLE_VALUE) return base_adress;
        if (Module32First(snapshot, &me32)) {
            base_adress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
        }
        CloseHandle(snapshot);
        roblox_base_address = base_adress;
        return base_adress;
    }

    inline uintptr_t get_base_size() {
        uintptr_t base_size = 0;
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, roblox_process_id);
        if (!snapshot || snapshot == INVALID_HANDLE_VALUE) return base_size;
        if (Module32First(snapshot, &me32)) {
            base_size = (uintptr_t)(me32.modBaseSize);
        }
        CloseHandle(snapshot);
        roblox_base_size = base_size;
        return base_size;
    }

    inline std::string get_roblox_version() {
        std::string version = "version-xxxxxxxxxxxxxxxx";
		char filename[MAX_PATH];
		if (!K32GetModuleFileNameExA(roblox_handle, 0, filename, MAX_PATH)) return version;
		auto path = fs::path(filename);
		version = path.parent_path().filename().string();
        return version;
    }
}

template <typename T>
inline T read(uintptr_t addr) {
    T buffer{};
    SIZE_T bytes_read;
    auto result = ntreadvirtualmemory(memory::roblox_handle, (void*)(addr), (void*)(&buffer), sizeof(T), &bytes_read);
    if (result != 0 || bytes_read != sizeof(T)) return T();
    return buffer;
}

inline std::string read_string(uintptr_t addr) {
    auto length = read<uint64_t>(addr + 0x10);
    if (length > 15) addr = read<uint64_t>(addr);
    std::string result;
    result.reserve((size_t)(length));
    for (size_t i = 0; i < (size_t)(length); ++i) {
        auto character = read<char>(addr + i);
        if (character == '\0') break;
        result.push_back(character);
    }
    return result;
}

template <typename T>
inline bool read_buffer(uintptr_t addr, size_t size, T buffer) {
    SIZE_T bytes_read;
    auto result = ntreadvirtualmemory(memory::roblox_handle, (void*)(addr), (void*)(buffer), size, &bytes_read);
    return result == 0 && bytes_read == size;
}

template <typename T>
inline bool read_buffer(uintptr_t addr, size_t size, T buffer, SIZE_T* bytes_read) {
    auto result = ntreadvirtualmemory(memory::roblox_handle, (void*)(addr), (void*)(buffer), size, bytes_read);
    return result == 0 && *bytes_read == size;
}

std::vector<std::string> extract_rtti(uintptr_t col_address) {
    std::vector<std::string> results;
    auto base_offset = read<uint32_t>(col_address + 0x14);
    if (base_offset == 0) return results;

    auto base_address = col_address - base_offset;
    auto class_hierarchy_descriptor_offset = read<uint32_t>(col_address + 0x10);
    if (class_hierarchy_descriptor_offset == 0) return results;

    auto class_hierarchy_descriptor_ptr = base_address + class_hierarchy_descriptor_offset;
    auto base_class_count = read<uint32_t>(class_hierarchy_descriptor_ptr + 0x08);
    if (base_class_count <= 0 || base_class_count >= 25) return results;

    auto base_class_array_offset = read<uint32_t>(class_hierarchy_descriptor_ptr + 0x0C);
    if (base_class_array_offset == 0) return results;

    auto base_class_array_ptr = base_address + base_class_array_offset;

    for (auto i = 0; i < base_class_count; ++i) {
        auto base_class_descriptor_offset = read<uint32_t>(base_class_array_ptr + (4 * i));
        if (!base_class_descriptor_offset) break;

        auto base_class_descriptor_ptr = base_address + base_class_descriptor_offset;
        auto type_descriptor_offset = read<uint32_t>(base_class_descriptor_ptr);
        if (!type_descriptor_offset) break;

        auto type_descriptor_ptr = memory::roblox_base_address + type_descriptor_offset;

        char name_buffer[61] = "";
        if (!read_buffer(type_descriptor_ptr + 0x14, 60, name_buffer)) break;

        std::string name(name_buffer);
        if (name.empty()) break;

        results.push_back(name);
    }

    return results;
}

inline std::string get_rtti_name(uintptr_t vtable) {
    auto col = read<uintptr_t>(vtable - sizeof(uintptr_t));
    if (!col) return "";
    auto rtti_strings = extract_rtti(col);
    if (rtti_strings.empty()) return "";
    return rtti_strings[0];
}

std::pair<uintptr_t, size_t> get_section_info(uintptr_t base, std::string section_name) {
    auto dos = read<IMAGE_DOS_HEADER>(base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] invalid dos header magic\n");
        return std::pair<uintptr_t, size_t>();
    }
    auto nt = read<IMAGE_NT_HEADERS>((uintptr_t)(base + dos.e_lfanew));
    IMAGE_SECTION_HEADER section;
    auto found = false;
    auto table = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS);
    for (auto i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        section = read<IMAGE_SECTION_HEADER>((uintptr_t)(table + i * sizeof(IMAGE_SECTION_HEADER)));
        char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        memcpy(name, section.Name, IMAGE_SIZEOF_SHORT_NAME);
        if (_strcmpi(name, section_name.c_str()) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        printf("[-] failed to find specified section\n");
        return std::pair<uintptr_t, size_t>();
    }
    uintptr_t section_address = (uintptr_t)(base + section.VirtualAddress);
    size_t section_size = section.Misc.VirtualSize;
    return std::pair<uintptr_t, size_t>(section_address, section_size);
}

inline std::vector<MEMORY_BASIC_INFORMATION> get_scannable_regions(uintptr_t base, uintptr_t size) {
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    auto current = base;
    auto end = base + size;
    while (current < end) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(
            memory::roblox_handle,
            (LPCVOID)(current),
            &mbi,
            sizeof(MEMORY_BASIC_INFORMATION)
        );
        if (result == 0) break;
        uintptr_t region_start = (uintptr_t)mbi.BaseAddress;
        uintptr_t region_end = region_start + mbi.RegionSize;
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS) &&
            mbi.BaseAddress >= (LPCVOID)base && (uintptr_t)mbi.BaseAddress < end)
            regions.push_back(mbi);
        current += mbi.RegionSize;
    }
	return regions;
}

inline std::vector<uintptr_t> scan_region_for_strings(uintptr_t region_start, uintptr_t region_size, std::string string) {
    std::vector<uintptr_t> found;

    std::vector<BYTE> buffer(region_size);
    auto region_end = region_start + region_size;

	SIZE_T bytes_read;
    if (!read_buffer(region_start, region_size, buffer.data(), &bytes_read)) return found;

	for (auto i = 0; i < bytes_read - string.size(); ++i) 
        if (memcmp(buffer.data() + i, string.data(), string.size()) == 0)
            found.push_back(region_start + i);

    return found;
}

inline std::vector<uintptr_t> scan_region_for_xrefs(uintptr_t region_start, uintptr_t region_size, uintptr_t target_address) {
    std::vector<uintptr_t> xrefs;
    
    std::vector<BYTE> buffer(region_size);
    auto region_end = region_start + region_size;

    SIZE_T bytes_read;
    if (!read_buffer(region_start, region_size, buffer.data(), &bytes_read)) return xrefs;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    for (auto i = 0; i < bytes_read; i += instruction.length) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + i, bytes_read - i, &instruction, operands))) continue;
        auto runtime_address = region_start + i;
        for (int i = 0; i < instruction.operand_count; i++) {
            auto& operand = operands[i];
            if (!(operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP)) continue;
            ZyanU64 result_address = 0;
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, runtime_address, &result_address))) continue;
            if (result_address == target_address) xrefs.push_back(runtime_address);
        }
    }

    return xrefs;
}