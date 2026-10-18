#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace WinArk::Engine {

struct YaraMatchDetail {
    std::string ruleName;
    std::string namespaceName;
    std::string description;
    uint32_t matchOffset;
    uint32_t matchLength;
};

class LocalYaraEngine {
public:
    LocalYaraEngine() = default;
    ~LocalYaraEngine() = default;

    // Load compiled rules or rule directory (*.yar) from local disk
    bool LoadRuleDirectory(const std::wstring& ruleDirPath);

    // Deep inspect process memory range (VAD / RWX memory pages)
    bool ScanProcessMemory(uint32_t processId, uint64_t baseAddress, size_t size, std::vector<YaraMatchDetail>& outMatches);

    // Deep inspect file bytes
    bool ScanFile(const std::wstring& filePath, std::vector<YaraMatchDetail>& outMatches);

    void Close();

private:
    void* m_yaraCompiler = nullptr;
    void* m_yaraRules = nullptr;
};

} // namespace WinArk::Engine
