// Compile the implementation once in this test executable to exercise private
// history helpers without exporting test-only APIs from the production plugin.
#include "../src/claude_risk.cpp"

#include <iostream>

namespace {

int failures = 0;
void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        std::cerr << "Claude runtime check failed at line " << line << ": " << expression << '\n';
        ++failures;
    }
}

struct TemporaryDirectory {
    std::wstring path;

    TemporaryDirectory() {
        wchar_t parent[MAX_PATH] = {};
        const DWORD length = GetTempPathW(MAX_PATH, parent);
        if (length == 0 || length >= MAX_PATH) return;
        wchar_t name[MAX_PATH] = {};
        if (!GetTempFileNameW(parent, L"tmi", 0, name)) return;
        if (!DeleteFileW(name)) return;
        if (CreateDirectoryW(name, nullptr)) path = name;
    }

    ~TemporaryDirectory() {
        if (path.empty()) return;
        const std::wstring history = path + L"\\tm_ip_plugin_iphistory.log";
        DeleteFileW(history.c_str());
        DeleteFileW((history + L".tmp").c_str());
        RemoveDirectoryW(path.c_str());
    }
};

} // namespace

#define CHECK(expression) Check(static_cast<bool>(expression), #expression, __LINE__)

int main() {
    using namespace claude_risk;

    const std::string trace =
        "fl=1164f6\nh=claude.ai\nip=69.63.196.167\nts=1781928228.000\n"
        "loc=US\ncolo=LAX\nwarp=off\n";
    CHECK(ParseTraceField(trace, "ip") == L"69.63.196.167");
    CHECK(ParseTraceField(trace, "loc") == L"US");
    CHECK(ParseTraceField(trace, "colo") == L"LAX");
    CHECK(ParseTraceField(trace, "warp") == L"off");
    CHECK(ParseTraceField(trace, "missing_field").empty());
    CHECK(ParseTraceField("loc=SG\r\n", "loc") == L"SG");
    CHECK(ParseTraceField("location=US\n", "loc").empty());

    CHECK(IsRestrictedCountry(L"CN"));
    CHECK(IsRestrictedCountry(L"cn"));
    CHECK(IsRestrictedCountry(L"RU"));
    CHECK(IsRestrictedCountry(L"UA"));
    CHECK(!IsRestrictedCountry(L"US"));
    CHECK(!IsRestrictedCountry(L""));

    CHECK(ComputeRotationLevel(0) == RotationLevel::None);
    CHECK(ComputeRotationLevel(1) == RotationLevel::None);
    CHECK(ComputeRotationLevel(2) == RotationLevel::Notice);
    CHECK(ComputeRotationLevel(3) == RotationLevel::Notice);
    CHECK(ComputeRotationLevel(4) == RotationLevel::Warning);
    CHECK(ComputeRotationLevel(6) == RotationLevel::Warning);
    CHECK(ComputeRotationLevel(7) == RotationLevel::Severe);
    CHECK(ComputeRotationLevel(100) == RotationLevel::Severe);

    CHECK(ParseIpInfoOrgField(R"({"ip":"69.63.196.167","country":"US","org":"AS13335 Cloudflare, Inc."})") ==
          L"AS13335 Cloudflare, Inc.");

    TemporaryDirectory directory;
    CHECK(!directory.path.empty());
    if (!directory.path.empty()) {
        CHECK(UpdateAndCountHistory(directory.path, L"1.1.1.1", L"US") == 1);
        CHECK(UpdateAndCountHistory(directory.path, L"1.1.1.1", L"US") == 1);
        CHECK(UpdateAndCountHistory(directory.path, L"2.2.2.2", L"CN") == 2);
        CHECK(UpdateAndCountHistory(directory.path, L"3.3.3.3", L"JP") == 3);

        const std::wstring history = directory.path + L"\\tm_ip_plugin_iphistory.log";
        {
            std::wofstream file(history, std::ios::trunc);
            CHECK(file.is_open());
            const long long now = static_cast<long long>(std::time(nullptr));
            file << now - 31LL * 24 * 3600 << L"|198.51.100.1|US\n";
            file << now - 60 << L"|203.0.113.2|JP\n";
        }
        CHECK(UpdateAndCountHistory(directory.path, L"203.0.113.2", L"JP") == 1);
        CHECK(UpdateAndCountHistory(directory.path, L"203.0.113.3", L"SG") == 2);
    }

    if (failures != 0) return 1;
    std::cout << "Claude runtime tests passed\n";
    return 0;
}
