#include <windows.h>

#include "fflags/fflags.h"

int main() {
	SetConsoleTitle("external offsets dumper - @kitodoescode");
	std::string roblox_name = "RobloxPlayerBeta.exe";

	if (!memory::get_process_id(roblox_name)) {
		printf("[-] failed to get roblox process id.\n");
		system("pause");
		return 1;
	}

	if (!memory::get_process_handle()) {
		printf("[-] failed to get roblox handle.\n");
		system("pause");
		return 1;
	}

	if (!memory::get_base_address()) {
		printf("[-] failed to get roblox base address.\n");
		system("pause");
		return 1;
	}

	if (!memory::get_base_size()) {
		printf("[-] failed to get roblox base size.\n");
		system("pause");
		return 1;
	}

	printf("[+] found robloxplayerbeta.exe @ 0x%llx\n", memory::roblox_base_address);
	printf("[+] roblox process id - %lu\n", memory::roblox_process_id);

	printf("[*] starting dump...\n");

	auto fflags = get_fflags();

	fs::path output = fs::current_path() / "dump.h";
	if (fs::exists(output)) fs::remove(output);
	std::ofstream file(output);

	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::tm tm;
	localtime_s(&tm, &time_t);

	file << "// roblox version - " << memory::get_roblox_version() << "\n";
	file << "// dumped at      - " << std::put_time(&tm, "%H:%M %d/%m/%y") << "\n";
	file << "// total offsets  - " << fflags.size() << "\n";
	file << "// join my server - https://discord.gg/skidding\n";
	file << "\n";
	file << "namespace offsets {\n";
	file << "    namespace fflags {\n";

	for (auto& [name, pointer] : fflags) {
		file << "        inline uintptr_t " << name << " = 0x" << std::hex << pointer << ";\n";
	}

	file << "    }\n";
	file << "}";

	printf("[+] dumped to %s\n", output.filename().string().c_str());
	system("pause");
	return 0;
}