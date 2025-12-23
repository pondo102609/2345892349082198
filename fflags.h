#pragma once
#include "memory/memory.h"

uintptr_t get_fflag_bank_offset() {
    auto lookup = "BootstrapperCycleDetectionMaxInterval"; // any fflag name works
    std::vector<uintptr_t> strings_found;
    auto regions = get_scannable_regions(memory::roblox_base_address, memory::roblox_base_size);
    for (auto& region : regions) {
        auto base = region.BaseAddress;
        auto size = region.RegionSize;
        auto strings = scan_region_for_strings((uintptr_t)(base), size, lookup);
        for (auto str : strings) {
            //printf("[+] string %s found @ 0x%llx\n", lookup, str);
            //printf("[+] offset of 0x%llx is 0x%llx\n", str, str - memory::roblox_base_address);
            strings_found.push_back(str);
        }
    }

    std::vector<uintptr_t> xrefs_found;
    auto text_section_info = get_section_info(memory::roblox_base_address, ".text");
    auto text_regions = get_scannable_regions(text_section_info.first, text_section_info.second);
    for (auto& region : text_regions) {
        auto base = region.BaseAddress;
        auto size = region.RegionSize;
        for (auto addr : strings_found) {
            auto xrefs = scan_region_for_xrefs((uintptr_t)(base), size, addr);
            for (auto xref : xrefs) {
                //printf("[+] xref found @ 0x%llx\n", xref);
                //printf("[+] offset of xref 0x%llx is 0x%llx\n", xref, xref - memory::roblox_base_address);
                xrefs_found.push_back(xref);
            }
        }
    }

    for (auto xref : xrefs_found) {
        std::vector<BYTE> buffer(0x20);
        uintptr_t start = xref - 0x20;

        size_t bytes_read;
        if (!read_buffer(start, 0x20, buffer.data(), &bytes_read)) return 0;

        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        auto offset = bytes_read;
        for (auto offset = bytes_read; offset > 0; --offset) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + offset, bytes_read - offset, &instruction, operands))) continue;
            uintptr_t runtime_address = start + offset;
            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                instruction.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RCX &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                ZyanU64 result_address = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[1], runtime_address, &result_address))) {
                    //printf("[+] found fflag_bank ( 0x%llx ) @ 0x%llx\n", result_address, runtime_address);
					auto offset = result_address - memory::roblox_base_address;
                    //printf("[+] fflag_bank offset - 0x%llx\n", offset);
                    return offset;
                }
            }
        }
	}

    return 0;
}

std::map<std::string, uintptr_t> get_fflags() {
    std::map<std::string, uintptr_t> fflags = {};

    auto fflag_bank = read<uintptr_t>(memory::roblox_base_address + get_fflag_bank_offset());

    auto buckets_ptr = read<uintptr_t>(fflag_bank + 0x18);
    auto bucket_mask = read<uintptr_t>(fflag_bank + 0x30);
    auto bucket_count = bucket_mask + 1;

    std::unordered_set<uintptr_t> visited_nodes;
    uintptr_t rva_offset = 0;

    for (auto bucket_idx = 0; bucket_idx <= bucket_count; ++bucket_idx) {
        auto bucket_offset = buckets_ptr + (bucket_idx * 0x10);
        auto first_node = read<uintptr_t>(bucket_offset);
        auto last_node = read<uintptr_t>(bucket_offset + 0x8);

        if (!first_node || first_node == last_node) continue;

        auto current_node = first_node;
        while (current_node != last_node && current_node) {
            if (visited_nodes.find(current_node) != visited_nodes.end()) break;
			visited_nodes.insert(current_node);

            auto len = read<uintptr_t>(current_node + 0x20);

            if (!len || len > 1000) {
                auto next_node = read<uintptr_t>(current_node + 0x8);
                if (!next_node || next_node == first_node) break;
                current_node = next_node;
                continue;
            }

            auto fflag_name = read_string(current_node + 0x10);
            if (fflag_name.empty()) {
                auto next_node = read<uintptr_t>(current_node + 0x8);
                if (!next_node || next_node == first_node) break;
                current_node = next_node;
                continue;
			}

            auto getset = read<uintptr_t>(current_node + 0x30);
            if (getset) {
                auto vtable = read<uintptr_t>(getset);
				auto rtti_name = get_rtti_name(vtable);
                if (rtti_name == "UnregisteredValueGetSet@FLog@@") {
                    uintptr_t next_node = read<uintptr_t>(current_node + 0x8);
                    if (!next_node || next_node == first_node) break;
                    current_node = next_node;
                    continue;
                }

                if (!rva_offset) {
                    for (auto offset = 0x8; offset < 0x1000; offset += 0x8) {
                        auto absolute = read<uintptr_t>(getset + offset);
                        auto rva = absolute - memory::roblox_base_address;

                        if (rva < memory::roblox_base_address) {
                            rva_offset = offset;
                            break;
                        }
                    }
                }

                auto absolute = read<uintptr_t>(getset + rva_offset);
                auto fflag_pointer = absolute - memory::roblox_base_address;

                fflags[fflag_name] = fflag_pointer;
            }

            auto next_node = read<uintptr_t>(current_node + 0x8);
            if (!next_node || next_node == first_node) break;
            current_node = next_node;
        }
    }

    return fflags;
}