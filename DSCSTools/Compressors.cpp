
#include "Compressors.h"

#include <Compressor.h>
#include <Decompressor.h>
#include <lz4hc.h>

#include <format>
#include <utility>

namespace dscstools
{
    std::expected<std::vector<char>, std::string> Doboz::decompress(const std::vector<char>& input, size_t size)
    {
        doboz::Decompressor decomp;
        doboz::CompressionInfo info;
        auto result1 = decomp.getCompressionInfo(input.data(), input.size(), info);

        if (result1 != doboz::RESULT_OK) return input;
        if (info.compressedSize != input.size()) return input;
        if (info.version != 0) return input;
        if (info.uncompressedSize != size) return input;

        std::vector<char> output(info.uncompressedSize);

        auto result = decomp.decompress(input.data(), input.size(), output.data(), output.size());
        if (result != doboz::RESULT_OK)
            return std::unexpected(std::format("Error: something went wrong while decompressing, doboz error code: {}",
                                               std::to_underlying(result)));

        return output;
    }

    std::expected<std::vector<char>, std::string> Doboz::compress(const std::vector<char>& input)
    {
        doboz::Compressor comp;
        auto maxSize = comp.getMaxCompressedSize(input.size());
        std::vector<char> output(maxSize);
        size_t destSize;

        auto result = comp.compress(input.data(), input.size(), output.data(), output.size(), destSize);

        if (result != doboz::RESULT_OK)
            return std::unexpected(std::format("Error: something went wrong while compressing, doboz error code: {}",
                                               std::to_underlying(result)));

        output.resize(destSize);
        return output;
    }

    bool Doboz::isCompressed(const std::vector<char>& input)
    {
        doboz::Decompressor decomp;
        doboz::CompressionInfo info;
        auto result = decomp.getCompressionInfo(input.data(), input.size(), info);

        if (result != doboz::RESULT_OK) return false;
        if (info.version == 0) return false;
        if (info.compressedSize != input.size()) return false;

        return true;
    }

    std::expected<std::vector<char>, std::string> LZ4::decompress(const std::vector<char>& input, size_t size)
    {
        if (input.size() == size) return input;

        std::vector<char> output(size);
        auto result = LZ4_decompress_safe(input.data(), output.data(), input.size(), output.size());

        if (result != size) return std::unexpected(std::format("Error: something went wrong while decompressing."));
        return output;
    }

    std::expected<std::vector<char>, std::string> LZ4::compress(const std::vector<char>& input)
    {
        std::vector<char> output(LZ4_compressBound(input.size()));

        auto result = LZ4_compress_HC(input.data(), output.data(), input.size(), output.size(), LZ4HC_CLEVEL_MAX);
        if (result == 0) return std::unexpected(std::format("Error: something went wrong while compressing."));

        output.resize(result);
        return output;
    }

    bool LZ4::isCompressed(const std::vector<char>& input)
    {
        std::vector<char> output(256);
        auto result =
            LZ4_decompress_safe_partial(input.data(), output.data(), input.size(), output.size(), output.size());

        if (result < 0) return false;

        return true;
    }
} // namespace dscstools