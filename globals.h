#pragma once
#include <windows.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <filesystem>
#include <unordered_set>
#include <map>

#include <Zydis.h>

namespace fs = std::filesystem;
#define sleep_ms(ms) std::this_thread::sleep_for(std::chrono::milliseconds(ms));