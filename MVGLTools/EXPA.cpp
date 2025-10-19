#include "EXPA.h"

#include "Helpers.h"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/regex.hpp>
#include <boost/regex/v5/regex_fwd.hpp>
#include <boost/regex/v5/regex_search.hpp>
#include <parser.hpp>

#include <algorithm>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iomanip>
#include <ios>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace
{
    using namespace mvgltools;
    using namespace mvgltools::expa;

    constexpr auto getAlignment(EntryType type) -> uint32_t
    {
        switch (type)
        {
            case EntryType::UNK1: return 0;
            case EntryType::INT32: return 4;
            case EntryType::INT16: return 2;
            case EntryType::INT8: return 1;
            case EntryType::FLOAT: return 4;
            case EntryType::STRING3:
            case EntryType::STRING:
            case EntryType::STRING2: return 8;
            case EntryType::BOOL: return 4;
            case EntryType::EMPTY: return 0;
            case EntryType::INT32_ARRAY: return 8;
            default: return 0;
        }
    }

    constexpr auto getSize(EntryType type) -> uint32_t
    {
        switch (type)
        {
            case EntryType::UNK1: return 0;
            case EntryType::INT32: return 4;
            case EntryType::INT16: return 2;
            case EntryType::INT8: return 1;
            case EntryType::FLOAT: return 4;
            case EntryType::STRING3:
            case EntryType::STRING:
            case EntryType::STRING2: return 8;
            case EntryType::BOOL: return 4;
            case EntryType::EMPTY: return 0;
            case EntryType::INT32_ARRAY: return 16;
            default: return 0;
        }
    }

    auto getCSVString(const EntryType& type, const EntryValue& value) -> std::string
    {
        switch (type)
        {
            case EntryType::INT32: return std::format("{}", std::get<int32_t>(value));
            case EntryType::INT16: return std::format("{}", std::get<int16_t>(value));
            case EntryType::INT8: return std::format("{}", std::get<int8_t>(value));
            case EntryType::FLOAT: return std::format("{}", std::get<float>(value));
            case EntryType::BOOL: return std::format("{}", std::get<bool>(value));

            case EntryType::STRING3: [[fallthrough]];
            case EntryType::STRING: [[fallthrough]];
            case EntryType::STRING2:
            {
                std::stringstream sstream;
                sstream << std::quoted(std::get<std::string>(value), '\"', '\"');
                return sstream.str();
            }
            case EntryType::INT32_ARRAY:
            {
                auto data = std::get<std::vector<int32_t>>(value) |
                            std::views::transform([](auto val) { return std::to_string(val); });
                return std::views::join_with(data, ' ') | std::ranges::to<std::string>();
            }
            case EntryType::EMPTY: [[fallthrough]];
            case EntryType::UNK1: [[fallthrough]];
            default: return "";
        }
    }

    auto getCSVValue(const EntryType& type, const std::string& value) -> EntryValue
    {
        switch (type)
        {
            default:
            case EntryType::UNK1: [[fallthrough]];
            case EntryType::EMPTY: return std::nullopt;

            case EntryType::INT32: return std::stoi(value);
            case EntryType::INT16: return static_cast<int16_t>(std::stoi(value));
            case EntryType::INT8: return static_cast<int8_t>(std::stoi(value));
            case EntryType::FLOAT: return std::stof(value);

            case EntryType::STRING3: [[fallthrough]];
            case EntryType::STRING: [[fallthrough]];
            case EntryType::STRING2: return value;

            case EntryType::BOOL: return value == "true";
            case EntryType::INT32_ARRAY:
                return value | std::views::split(' ') | std::ranges::to<std::vector<std::string>>() |
                       std::views::transform([](const auto& val) { return std::stoi(val); }) |
                       std::ranges::to<std::vector<int32_t>>();
        }
    }

    auto writeEXPAEntry(size_t base_offset, char* data, EntryType type, const EntryValue& value)
        -> std::optional<CHNKEntry>
    {
        switch (type)
        {
            case EntryType::INT32: *reinterpret_cast<int32_t*>(data) = get<int32_t>(value); break;
            case EntryType::INT16: *reinterpret_cast<int16_t*>(data) = get<int16_t>(value); break;
            case EntryType::INT8: *reinterpret_cast<int8_t*>(data) = get<int8_t>(value); break;
            case EntryType::FLOAT: *reinterpret_cast<float*>(data) = get<float>(value); break;

            case EntryType::STRING3: [[fallthrough]];
            case EntryType::STRING: [[fallthrough]];
            case EntryType::STRING2:
            {
                *reinterpret_cast<uint64_t*>(data) = 0;
                auto str                           = get<std::string>(value);
                if (!str.empty()) return CHNKEntry(base_offset, str);
                break;
            }
            case EntryType::INT32_ARRAY:
            {
                const auto& array                      = get<std::vector<int32_t>>(value);
                *reinterpret_cast<uint32_t*>(data)     = static_cast<int32_t>(array.size());
                *reinterpret_cast<uint64_t*>(data + 8) = 0;
                if (!array.empty()) return CHNKEntry(base_offset + 8, array);
                break;
            }

            case EntryType::EMPTY: [[fallthrough]];
            case EntryType::BOOL: [[fallthrough]];
            case EntryType::UNK1: [[fallthrough]];
            default: break;
        }
        return std::nullopt;
    }

    auto readEXPAEntry(EntryType type, const char* data, uint32_t bitCounter) -> EntryValue
    {
        switch (type)
        {
            default:
            case EntryType::UNK1: [[fallthrough]];
            case EntryType::EMPTY: return std::nullopt;

            case EntryType::INT32: return *reinterpret_cast<const int32_t*>(data);
            case EntryType::INT16: return *reinterpret_cast<const int16_t*>(data);
            case EntryType::INT8: return *reinterpret_cast<const int8_t*>(data);
            case EntryType::FLOAT: return *reinterpret_cast<const float*>(data);
            case EntryType::STRING3: [[fallthrough]];
            case EntryType::STRING: [[fallthrough]];
            case EntryType::STRING2:
            {
                auto* ptr = *reinterpret_cast<char* const*>(data);
                return (ptr != nullptr) ? std::string(ptr) : "";
            }
            case EntryType::BOOL: return ((*reinterpret_cast<const uint32_t*>(data) >> bitCounter) & 1u) == 1u;
            case EntryType::INT32_ARRAY:
            {
                auto count = *reinterpret_cast<const int32_t*>(data);
                auto* ptr  = *reinterpret_cast<int32_t* const*>(data + 8);
                std::vector<int32_t> values;
                for (int32_t i = 0; i < count; i++)
                    values.push_back(ptr[i]);
                return values;
            }
        }
    }

} // namespace

namespace mvgltools::expa
{
    Structure::Structure(std::vector<StructureEntry> structure)
        : structure(std::move(structure))
    {
    }

    auto Structure::getStructure() const -> std::vector<StructureEntry>
    {
        return structure;
    }

    auto Structure::writeEXPA(const std::vector<EntryValue>& entries) const -> EXPAEntry
    {
        auto offset     = 0u;
        auto bitCounter = 0;
        std::bitset<32> currentBool;
        std::vector<CHNKEntry> chunkEntries;
        std::vector<char> new_data(getEXPASize(), '\xCC');

        for (const auto& val : std::views::zip(structure, entries))
        {
            auto type  = get<0>(val).type;
            auto entry = get<1>(val);

            if (type != EntryType::BOOL || bitCounter >= 32)
            {
                if (bitCounter > 0)
                {
                    *reinterpret_cast<uint32_t*>(new_data.data() + offset) = currentBool.to_ulong();
                    offset += sizeof(uint32_t);
                    bitCounter  = 0;
                    currentBool = {};
                }
                offset = ceilInteger(offset, getAlignment(type));
            }

            auto result = writeEXPAEntry(offset, new_data.data() + offset, type, entry);
            if (result) chunkEntries.push_back(result.value());

            if (type == EntryType::BOOL)
                currentBool.set(bitCounter++, get<bool>(entry));
            else
                offset += getSize(type);
        }

        if (bitCounter > 0) *reinterpret_cast<uint32_t*>(new_data.data() + offset) = currentBool.to_ulong();

        return {.data = new_data, .chunk = chunkEntries};
    }

    auto Structure::readEXPA(const char* data) const -> std::vector<EntryValue>
    {
        if (structure.empty()) return {};

        std::vector<EntryValue> values;
        auto offset     = 0u;
        auto bitCounter = 0u;

        for (const auto& val : structure)
        {
            if (val.type != EntryType::BOOL || bitCounter >= 32)
            {
                if (bitCounter > 0) offset += getSize(EntryType::BOOL);

                offset     = ceilInteger(offset, getAlignment(val.type));
                bitCounter = 0;
            }

            values.push_back(readEXPAEntry(val.type, data + offset, bitCounter));

            if (val.type == EntryType::BOOL)
                bitCounter++;
            else
                offset += getSize(val.type);
        }

        return values;
    }

    auto Structure::readCSV(const std::vector<std::string>& data) const -> std::vector<EntryValue>
    {
        return std::views::zip_transform([](const auto& val, const auto& val2) { return getCSVValue(val.type, val2); },
                                         structure,
                                         data) |
               std::ranges::to<std::vector<EntryValue>>();
    }

    auto Structure::getCSVHeader() const -> std::string
    {
        return structure | std::views::transform([](const auto& val) { return val.name; }) |
               std::views::join_with(',') | std::ranges::to<std::string>();
    }

    auto Structure::writeCSV(const std::vector<EntryValue>& entries) const -> std::string
    {
        std::stringstream stream;
        auto result = structure | std::views::transform([](const auto& val) { return val.name; }) |
                      std::views::join_with(',') | std::ranges::to<std::string>();
        stream << result << "\n";

        return std::views::zip_transform([](const auto& val, const auto& val2) { return getCSVString(val.type, val2); },
                                         structure,
                                         entries) |
               std::views::join_with(',') | std::ranges::to<std::string>();
    }

    auto Structure::getEXPASize() const -> uint32_t
    {
        if (structure.empty()) return 0;

        auto currentSize = 0u;
        auto bitCounter  = 0u;

        for (const auto& val : structure)
        {
            if (bitCounter == 0 || bitCounter >= 32 || val.type != EntryType::BOOL)
            {
                currentSize = ceilInteger(currentSize, getAlignment(val.type));
                bitCounter  = 0;
            }

            if (bitCounter == 0) currentSize += getSize(val.type);
            if (val.type == EntryType::BOOL) bitCounter++;
        }

        return ceilInteger(currentSize, 8);
    }

    auto Structure::getEntryCount() const -> size_t
    {
        return structure.size();
    }

    CHNKEntry::CHNKEntry(uint32_t offset, const std::string& data)
        : offset(offset)
    {
        value = std::vector<char>(ceilInteger(static_cast<int64_t>(data.size() + 2), 4));
        std::ranges::copy(data, value.begin());
    }

    CHNKEntry::CHNKEntry(uint32_t offset, const std::vector<int32_t>& data)
        : offset(offset)
    {
        value = std::vector<char>(data.size() * sizeof(int32_t));
        std::copy_n(reinterpret_cast<const char*>(data.data()), value.size(), value.begin());
    }

    auto exportCSV(const TableFile& file, const std::filesystem::path& target) -> std::expected<void, std::string>
    {
        if (std::filesystem::exists(target) && !std::filesystem::is_directory(target))
            return std::unexpected("Target path exists and is not a directory.");

        std::filesystem::create_directories(target);

        int32_t table_id = 0;
        for (const auto& table : file.tables)
        {
            auto path = target / std::format("{:03}_{}.csv", table_id++, table.name);
            std::ofstream stream(path, std::ios::out);

            if (!stream) return std::unexpected("Failed to write target file.");

            stream << table.structure.getCSVHeader() << "\n";
            std::ranges::for_each(table.entries,
                                  [&](const auto& val) { stream << table.structure.writeCSV(val) << "\n"; });
        }

        return {};
    }

} // namespace mvgltools::expa
