#pragma once

#include <cstdint>
#include <type_traits>

struct ConfigLike {
    std::uint64_t words[7];
    ~ConfigLike() noexcept {}
};

static_assert(sizeof(ConfigLike) == 56, "expected a 56-byte hidden-sret result");
static_assert(!std::is_trivially_destructible<ConfigLike>::value,
              "the result must retain non-trivial C++ ABI lowering");

using xfg_member_invoke_fn = int (__cdecl *)();

extern "C" __declspec(dllimport) void __cdecl xfg_copy_config(
    ConfigLike* destination, ConfigLike const* source
) noexcept;
