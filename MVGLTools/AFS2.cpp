#include "include/AFS2.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iosfwd>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace mvgltools::afs2
{
    constexpr auto AFS2_MAGIC_VALUE = 0x32534641;

    struct AFS2Header
    {
        uint32_t magic;
        uint32_t flags;
        uint32_t numFiles;
        int32_t blockSize;
    };

    void extractAFS2(const std::filesystem::path& source, const std::filesystem::path& target)
    {
        if (std::filesystem::exists(target) && !std::filesystem::is_directory(target))
            throw std::invalid_argument("Error: Target path exists and is not a directory, aborting.");
        if (!std::filesystem::is_regular_file(source))
            throw std::invalid_argument("Error: Source path doesn't point to a file, aborting.");

        std::ifstream input(source, std::ios::in | std::ios::binary);

        AFS2Header header{};
        input.read(reinterpret_cast<char*>(&header), 0x10);

        if (header.magic != AFS2_MAGIC_VALUE) throw std::invalid_argument("Error: not an AFS2 file. Value: ");

        std::vector<uint16_t> fileIds(header.numFiles);
        input.read(reinterpret_cast<char*>(fileIds.data()), header.numFiles * 2L);

        std::vector<uint32_t> offsets(header.numFiles + 1);
        input.read(reinterpret_cast<char*>(offsets.data()), (header.numFiles + 1) * 4L);

        if (input.tellg() < header.blockSize) input.seekg(header.blockSize);
        if (input.tellg() != offsets[0]) throw std::invalid_argument("AFS2: Didn't reach expected end of header.");

        if (target.has_parent_path()) std::filesystem::create_directories(target);

        for (size_t i = 0; i < header.numFiles; i++)
        {
            input.seekg((static_cast<uint32_t>(input.tellg()) + header.blockSize - 1) & -header.blockSize); // NOLINT
            uint32_t size = offsets[i + 1] - (uint32_t)input.tellg();

            std::vector<char> data(size);
            input.read(data.data(), size);

            std::stringstream sstream;
            sstream << std::setw(6) << std::setfill('0') << std::hex << i << ".hca";

            std::filesystem::path path(target / sstream.str());
            std::ofstream output(path, std::ios::out | std::ios::binary);

            output.write(data.data(), size);
        }
    }

    void packAFS2(const std::filesystem::path& source, const std::filesystem::path& target)
    {
        if (!std::filesystem::is_directory(source))
            throw std::invalid_argument("Error: source path is not a directory.");

        if (!std::filesystem::exists(target))
        {
            if (target.has_parent_path()) std::filesystem::create_directories(target.parent_path());
        }
        else if (!std::filesystem::is_regular_file(target))
            throw std::invalid_argument("Error: target path already exists and is not a file.");

        std::ofstream output(target, std::ios::out | std::ios::binary);

        std::vector<std::filesystem::path> files;

        for (const auto& i : std::filesystem::directory_iterator(source))
            if (std::filesystem::is_regular_file(i)) files.push_back(i);

        AFS2Header header{};
        header.magic     = AFS2_MAGIC_VALUE;
        header.flags     = 0x00020402;
        header.numFiles  = (uint32_t)files.size();
        header.blockSize = 0x20;

        output.write(reinterpret_cast<char*>(&header), 0x10);

        std::vector<uint16_t> id(header.numFiles);
        std::vector<uint32_t> offsets(header.numFiles + 1);

        offsets[0] = 0x10 + header.numFiles * 0x06 + 4;
        offsets[0] = std::max(offsets[0], static_cast<uint32_t>(header.blockSize));

        for (size_t i = 0; i < files.size(); i++)
        {
            output.seekp((offsets[i] + header.blockSize - 1) & -header.blockSize); // NOLINT

            std::ifstream input(files[i], std::ios::in | std::ios::binary);
            input.seekg(0, std::ios::end);
            std::streamoff length = input.tellg();
            input.seekg(0, std::ios::beg);

            std::vector<char> buffer(length);
            input.read(buffer.data(), length);
            output.write(buffer.data(), length);

            id[i]          = (uint16_t)i;
            offsets[i + 1] = (uint32_t)output.tellp();
        }

        output.seekp(0x10);
        output.write(reinterpret_cast<char*>(id.data()), header.numFiles * 2L);
        output.write(reinterpret_cast<char*>(offsets.data()), (header.numFiles + 1) * 4L);
    }
} // namespace mvgltools::afs2
