#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace WinArk::Engine {

enum class HashMatchResult {
    SafeWhitelist,      // Known legitimate OS / software binary
    MaliciousBlacklist, // Known malware / rootkit / trojan hash
    Unknown             // Not present in local database (send to deep YARA scan)
};

struct FileHashRecord {
    std::string sha256;
    std::string md5;
    std::string fileName;
    std::string description;
    bool isMalicious;
};

class LocalHashEngine {
public:
    LocalHashEngine() = default;
    ~LocalHashEngine() = default;

    // Initialize local SQLite database
    bool Initialize(const std::wstring& dbFilePath);

    // Fast microsecond lookup
    HashMatchResult QueryHash(const std::string& sha256, const std::string& md5 = "");

    // Add record to local offline database
    bool AddRecord(const FileHashRecord& record);

    void Close();

private:
    void* m_dbHandle = nullptr; // SQLite3 db instance
};

} // namespace WinArk::Engine
