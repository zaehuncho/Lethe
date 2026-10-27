#pragma once

#include <cstdint>
#include <type_traits>

#if defined(STRINGLIKE_SUPPORT_EXPORTS)
#define STRINGLIKE_API __declspec(dllexport)
#else
#define STRINGLIKE_API __declspec(dllimport)
#endif

struct StringLike {
    std::uint64_t words[3];
    StringLike() noexcept = default;
    STRINGLIKE_API __declspec(noinline) StringLike(StringLike const& other) noexcept;
    ~StringLike() noexcept {}
};

struct ConfigLike {
    StringLike first;
    StringLike second;
    std::uint64_t marker;

    ConfigLike() noexcept = default;
    ConfigLike(StringLike const& a, StringLike const& b, std::uint64_t value) noexcept
        : first(a), second(b), marker(value) {}
    ~ConfigLike() noexcept {}
};

static_assert(sizeof(StringLike) == 24, "expected a 24-byte StringLike member");
static_assert(sizeof(ConfigLike) == 56, "expected a 56-byte hidden-sret result");
static_assert(!std::is_trivially_destructible<ConfigLike>::value,
              "the result must retain non-trivial C++ ABI lowering");

using xfg_member_two_invoke_fn = int (__cdecl *)();
