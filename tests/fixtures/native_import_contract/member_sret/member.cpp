#include "member_abi.h"

class DetectorLike {
public:
    explicit DetectorLike(std::uint64_t seed) noexcept {
        value_.words[0] = seed;
        value_.words[1] = seed ^ 0x1122334455667788ui64;
        value_.words[2] = seed + 0x8877665544332211ui64;
        value_.words[3] = ~seed;
        value_.words[4] = (seed << 3) + (seed >> 2);
        value_.words[5] = seed - 0x1020304050607080ui64;
        value_.words[6] = seed | 0x8000000000000001ui64;
    }

    __declspec(dllexport) __declspec(noinline)
    ConfigLike config() const noexcept;

private:
    ConfigLike value_;
};

ConfigLike DetectorLike::config() const noexcept {
    ConfigLike result;
    xfg_copy_config(&result, &value_);
    return result;
}

extern "C" __declspec(dllexport) __declspec(noinline)
int __cdecl xfg_member_invoke()
{
    static constexpr std::uint64_t kSeed = 0x0123456789ABCDEFui64;
    DetectorLike detector(kSeed);
    ConfigLike result = detector.config();
    return result.words[0] == kSeed
        && result.words[1] == (kSeed ^ 0x1122334455667788ui64)
        && result.words[2] == (kSeed + 0x8877665544332211ui64)
        && result.words[3] == ~kSeed
        && result.words[4] == ((kSeed << 3) + (kSeed >> 2))
        && result.words[5] == (kSeed - 0x1020304050607080ui64)
        && result.words[6] == (kSeed | 0x8000000000000001ui64);
}
