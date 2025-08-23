#include <iostream>
#include <string>
#include "src/ip_utils.h"

int main() {
    // 测试ipinfo.io API
    iputils::ExternalIpOptions opt;
    std::wcout << L"Testing ipinfo.io API..." << std::endl;
    std::wcout << L"Host: " << opt.host << std::endl;
    std::wcout << L"Path: " << opt.path << std::endl;
    
    auto result = iputils::GetExternalIPv4WithCountry(opt, true);
    
    if (result.IsValid()) {
        std::wcout << L"Success!" << std::endl;
        std::wcout << L"IP: " << result.ip << std::endl;
        std::wcout << L"Country: " << result.country << std::endl;
        std::wcout << L"Display: " << result.GetDisplayString() << std::endl;
    } else {
        std::wcout << L"Failed to get external IP" << std::endl;
    }
    
    return 0;
}