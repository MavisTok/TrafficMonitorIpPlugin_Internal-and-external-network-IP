#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include "src/ip_utils.h"

int main() {
    // 测试ipinfo.io API
    iputils::ExternalIpOptions opt;
    std::wcout << L"Testing ipinfo.io API..." << std::endl;
    std::wcout << L"Host: " << opt.host << std::endl;
    std::wcout << L"Path: " << opt.path << std::endl;
    
    auto result = iputils::GetExternalIPv4WithCountry(opt, true);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!result.IsValid() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        result = iputils::GetExternalIPv4WithCountry(opt);
    }
    iputils::ShutdownExternalIpWorker();
    
    if (result.IsValid()) {
        std::wcout << L"Success!" << std::endl;
        std::wcout << L"IP: " << result.ip << std::endl;
        std::wcout << L"Country: " << result.country << std::endl;
        std::wcout << L"Display: " << result.GetDisplayString() << std::endl;
    } else {
        std::wcout << L"Failed to get external IP" << std::endl;
    }
    
    return result.IsValid() ? 0 : 1;
}
