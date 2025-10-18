#pragma once

#include <expected>
#include <string>
#include <vector>

namespace dscstools
{
    /**
     * Represents the compressor interface, detailing all the static functions an implementation is required to have.
     */
    template<typename T>
    concept Compressor = requires(const std::vector<char>& input, size_t size) {
        /**
         * Decompresses the passed data. If the data isn't compressed or the passed size doesn't match the decompressed
         * size, the input data is returned.
         */
        { T::decompress(input, size) } -> std::same_as<std::expected<std::vector<char>, std::string>>;
        /**
         * Compresses the passed data.
         */
        { T::compress(input) } -> std::same_as<std::expected<std::vector<char>, std::string>>;
        /**
         * Returns whether the passed data is compressed using the algorithm.
         */
        { T::isCompressed(input) } -> std::same_as<bool>;
    };

    // See Compressor concept for details
    struct Doboz
    {
        static std::expected<std::vector<char>, std::string> decompress(const std::vector<char>& input, size_t size);
        static std::expected<std::vector<char>, std::string> compress(const std::vector<char>& input);
        static bool isCompressed(const std::vector<char>& input);
    };

    // See Compressor concept for details
    struct LZ4
    {
        static std::expected<std::vector<char>, std::string> decompress(const std::vector<char>& input, size_t size);
        static std::expected<std::vector<char>, std::string> compress(const std::vector<char>& input);
        static bool isCompressed(const std::vector<char>& input);
    };
} // namespace dscstools
