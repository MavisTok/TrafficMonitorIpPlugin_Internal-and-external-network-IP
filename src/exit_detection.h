#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <string>

namespace exit_detection {

enum class Site { Google, YouTube, OpenAI, Claude, Netflix, Count };
enum class ResultState { Pending, Success, Unknown };

struct SiteResult {
    Site site = Site::Google;
    ResultState state = ResultState::Pending;
    std::wstring country_code;
};

struct Snapshot {
    bool has_completed = false;
    bool refresh_in_flight = false;
    std::array<SiteResult, static_cast<std::size_t>(Site::Count)> sites{};
};

enum class RefreshDecision { Skip, Start, QueueForced };
enum class RefreshCompletionDecision { Stop, RunAgain };

struct RefreshQueueState {
    bool refresh_in_flight = false;
    bool forced_pending = false;
    bool forced_rerun_consumed = false;
    bool shutdown_requested = false;
};

std::wstring NormalizeCountryCode(const std::wstring& value);
std::wstring ParseGoogleMappingIp(const std::string& body);
std::wstring ParseYouTubeCountry(const std::string& body);
std::wstring ParseTraceCountry(const std::string& body);
std::wstring ParseNetflixCountry(const std::string& body);
std::wstring ParseIpInfoCountry(const std::string& body);

std::wstring CountryFlag(const std::wstring& country_code);
std::wstring CountryName(const std::wstring& country_code);
Snapshot MakeInitialSnapshot();
std::wstring FormatTooltip(const Snapshot& snapshot);

RefreshDecision EvaluateRefresh(bool has_completed,
                                bool refresh_in_flight,
                                std::chrono::steady_clock::duration age,
                                bool force_refresh);
void StartRefreshQueue(RefreshQueueState& state);
bool QueueForcedRefresh(RefreshQueueState& state);
RefreshCompletionDecision CompleteRefreshIteration(RefreshQueueState& state);

Snapshot GetSnapshot();
void RequestRefreshAsync(bool force_refresh);
void ShutdownRefreshWorker();

} // namespace exit_detection
