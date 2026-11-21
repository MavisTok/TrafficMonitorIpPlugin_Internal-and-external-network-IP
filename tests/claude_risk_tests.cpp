#include "../src/claude_risk_parse.h"

#include <iostream>
#include <string>

namespace {
int failures = 0;
void Check(bool condition, int line) {
    if (!condition) {
        std::cerr << "Risk response check failed at line " << line << '\n';
        ++failures;
    }
}
}

#define CHECK(condition) Check(condition, __LINE__)

int main() {
    using namespace claude_risk;
    RiskFlags flags;
    CHECK(ParseRiskResponse(R"({"status":"success","proxy":true,"hosting":false,"mobile":true})", flags));
    CHECK(flags.proxy && !flags.hosting && flags.mobile);
    CHECK(ParseRiskResponse(" { \"mobile\": false, \"hosting\": true,\n\"proxy\": false, \"status\": \"success\" } ", flags));
    CHECK(!flags.proxy && flags.hosting && !flags.mobile);
    CHECK(ParseRiskResponse(R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"extra":{"a":[null,1,-2.3e+4,"ignored"]}})", flags));
    CHECK(!flags.proxy && !flags.hosting && !flags.mobile);
    CHECK(ParseRiskResponse(R"({"\u0073tatus":"success","proxy":false,"hosting":false,"mobile":false})", flags));

    const char* invalid[] = {
        R"({"status":"fail","message":"invalid query"})",
        R"({"status":"success","proxy":false,"hosting":false})",
        R"({"status":"success","proxy":"false","hosting":false,"mobile":false})",
        R"({"status":"success","proxy":null,"hosting":false,"mobile":false})",
        R"({"status":"success","proxy":falsehood,"hosting":false,"mobile":false})",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false)",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false,})",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false}garbage)",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"proxy":true})",
        R"({"status":"success","nested":{"proxy":false,"hosting":false,"mobile":false}})",
        R"({"nested":{"status":"success"},"proxy":false,"hosting":false,"mobile":false})",
        R"({"status":"fail","proxy":false,"hosting":false,"mobile":false})",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"extra":01})",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"extra":1.})",
        R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"extra":1e})",
        "", "[]", "<html>error</html>"
    };
    for (const char* json : invalid) {
        flags = {true, true, true};
        CHECK(!ParseRiskResponse(json, flags));
        CHECK(flags.proxy && flags.hosting && flags.mobile);
    }
    CHECK(!ParseRiskResponse(std::string(65537, ' '), flags));
    const std::string prefix = R"({"status":"success","proxy":false,"hosting":false,"mobile":false,"extra":)";
    CHECK(!ParseRiskResponse(prefix + std::string(40, '[') + "0" + std::string(40, ']') + "}", flags));

    if (failures != 0) return 1;
    std::cout << "Claude risk response tests passed\n";
    return 0;
}
