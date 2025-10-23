// extract_mmap_single.cpp
#include <vector>
#include <fstream>
#include <algorithm>
#include "mmap_utils.h"
#include "crypto_xor.h"

// assumes your existing headers:
// - getArchiveInfo
// - ArchiveInfo, FileInfo, DataEntry
// - doboz::Decompressor

using dscstools::mdb1::ArchiveInfo;
using dscstools::mdb1::FileInfo;
using dscstools::mdb1::DataEntry;

void extractMDB1_mmap_single(const std::filesystem::path& source,
                             const std::filesystem::path& target,
                             bool decompress) {
  ArchiveInfo info = dscstools::mdb1::getArchiveInfo(source);
  if (info.status == dscstools::mdb1::invalid) {
    throw std::runtime_error("Not a valid MDB1 file");
  }

  MappedFile mappedFile = mmap_readonly(source);

  // Collect valid files and sort by physical offset (good for HDDs)
  std::vector<FileInfo> files;
  files.reserve(info.fileInfo.size());
  for (const auto& file : info.fileInfo) {
    if (file.file.compareBit != 0xFFFF && file.file.dataId != 0xFFFF) {
      files.push_back(file);
    }
  }
  std::sort(files.begin(),
            files.end(),
            [](const FileInfo& a, const FileInfo& b) {
              return a.data.offset < b.data.offset;
            });

  std::vector<char> chunk(1 << 20); // 1 MB for streaming copies
  doboz::Decompressor decomp;

  for (const auto& file : files) {
    const DataEntry& data = file.data;
    const uint64_t abs = static_cast<uint64_t>(info.dataStart) + data.offset;
    if (abs + data.compSize > mappedFile.size) {
      throw std::runtime_error("Range exceeds mapped file size");
    }

    const auto outPath = target / file.name.toPath();
    const auto parent = outPath.parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);

    std::ofstream out(outPath, std::ios::binary);
    // Optional: give the ofstream a bigger buffer
    std::vector<char> outBuf(1 << 20);
    out.rdbuf()->pubsetbuf(outBuf.data(), outBuf.size());

    const uint8_t* encPtr = mappedFile.ptr + abs;

    const bool needsDecomp =
        (data.compSize != data.size) && decompress;

    if (!needsDecomp) {
      // Stream copy: XOR from mapped memory into chunk and write
      uint64_t remain = decompress ? data.size : data.compSize;
      uint64_t pos = 0;
      while (remain) {
        const size_t n =
            static_cast<size_t>(std::min<uint64_t>(remain, chunk.size()));
        mdb1_fastxor::xor_into(encPtr + pos, chunk.data(), n, abs + pos);
        out.write(chunk.data(), n);
        pos += n;
        remain -= n;
      }
      if (!out.good()) {
        throw std::runtime_error("Write failed: " + outPath.string());
      }
      continue;
    }

    // Compressed: XOR compressed bytes into compBuf, then decompress
    std::unique_ptr<char[]> comp(new char[data.compSize]);
    mdb1_fastxor::xor_into(encPtr, comp.get(), data.compSize, abs);

    std::unique_ptr<char[]> plain(new char[data.size]);
    auto res = decomp.decompress(comp.get(),
                                 data.compSize,
                                 plain.get(),
                                 data.size);
    if (res != doboz::RESULT_OK) {
      throw std::runtime_error("Doboz error: " + std::to_string(res));
    }

    out.write(plain.get(), data.size);
    if (!out.good()) {
      throw std::runtime_error("Write failed: " + outPath.string());
    }
  }
}