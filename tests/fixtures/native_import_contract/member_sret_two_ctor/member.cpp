#include "member_abi.h"

class DetectorLike {
public:
    explicit DetectorLike(std::uint64_t seed) noexcept {
        value_.first.words[0] = seed;
        value_.first.words[1] = seed ^ 0x1122334455667788ui64;
        value_.first.words[2] = seed + 0x8877665544332211ui64;
        value_.second.words[0] = ~seed;
        value_.second.words[1] = (seed << 3) + (seed >> 2);
        value_.second.words[2] = seed - 0x1020304050607080ui64;
        value_.marker = seed | 0x8000000000000001ui64;
    }

    __declspec(dllexport) __declspec(noinline)
    ConfigLike config() const noexcept;

private:
    ConfigLike value_;
};

ConfigLike DetectorLike::config() const noexcept {
    return ConfigLike(value_.first, value_.second, value_.marker);
}

extern "C" __declspec(dllexport) __declspec(noinline)
int __cdecl xfg_member_two_invoke()
{
    static constexpr std::uint64_t kSeed = 0x0123456789ABCDEFui64;
    DetectorLike detector(kSeed);
    ConfigLike result = detector.config();
    return result.first.words[0] == kSeed
        && result.first.words[1] == (kSeed ^ 0x1122334455667788ui64)
        && result.first.words[2] == (kSeed + 0x8877665544332211ui64)
        && result.second.words[0] == ~kSeed
        && result.second.words[1] == ((kSeed << 3) + (kSeed >> 2))
        && result.second.words[2] == (kSeed - 0x1020304050607080ui64)
        && result.marker == (kSeed | 0x8000000000000001ui64);
}
