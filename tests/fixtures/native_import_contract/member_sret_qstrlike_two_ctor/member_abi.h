#pragma once

#include <cstdint>
#include <type_traits>

#if defined(QSTRLIKE_SUPPORT_EXPORTS)
#define QSTRLIKE_API __declspec(dllexport)
#else
#define QSTRLIKE_API __declspec(dllimport)
#endif

struct RefData {
    volatile long refs;
    std::uint32_t tag;
    std::uint32_t reserved;
};

struct QStrLike {
    RefData* d;
    char16_t const* data;
    std::int64_t size;

    QStrLike() noexcept = default;
    QSTRLIKE_API __declspec(noinline) QStrLike(QStrLike const& other) noexcept;
    QSTRLIKE_API __declspec(noinline) ~QStrLike() noexcept;
};

struct ConfigLike {
    QStrLike first;
    QStrLike second;
    std::uint64_t marker;

    ConfigLike() noexcept = default;
    ConfigLike(QStrLike const& a, QStrLike const& b, std::uint64_t value) noexcept
        : first(a), second(b), marker(value) {}
    ~ConfigLike() noexcept {}
};

static_assert(sizeof(QStrLike) == 24, "expected a 24-byte QString-like value");
static_assert(sizeof(ConfigLike) == 56, "expected a 56-byte hidden-sret result");
static_assert(!std::is_trivially_destructible<ConfigLike>::value,
              "the result must retain non-trivial C++ ABI lowering");

using xfg_qstrlike_two_invoke_fn = int (__cdecl *)();