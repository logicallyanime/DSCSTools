#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <filesystem>

#ifdef _WIN32      // Support for Linux Systems
  #define NOMINMAX
  #ifndef WIN32_LEAN_AND_MEAN
  
  #define WIN32_LEAN_AND_MEAN
  
  #endif
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

struct MappedFile {
  const uint8_t* ptr = nullptr;
  size_t size = 0;

#ifdef _WIN32
  HANDLE hFile = INVALID_HANDLE_VALUE;
  HANDLE hMap = nullptr;
#else
  int fd = -1;
#endif

  ~MappedFile() { close(); }

  void close() {
#ifdef _WIN32
    if (ptr) UnmapViewOfFile(ptr);
    if (hMap) CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    ptr = nullptr;
    hMap = nullptr;
    hFile = INVALID_HANDLE_VALUE;
#else
    if (ptr) munmap((void*)ptr, size);
    if (fd >= 0) ::close(fd);
    ptr = nullptr;
    fd = -1;
#endif
    size = 0;
  }
};

inline MappedFile mmap_readonly(const std::filesystem::path& source) {
  MappedFile mf;

#ifdef _WIN32
  HANDLE hFile = CreateFileW(
      source.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    throw std::runtime_error("CreateFile failed");
  }

  LARGE_INTEGER fileSizeLgInt{};
  if (!GetFileSizeEx(hFile, &fileSizeLgInt)) {
    CloseHandle(hFile);
    throw std::runtime_error("GetFileSizeEx failed");
  }
  const uint64_t fileSize = static_cast<uint64_t>(fileSizeLgInt.QuadPart);
  if (fileSize > SIZE_MAX) {
    CloseHandle(hFile);
    throw std::runtime_error("File too large for size_t");
  }

  HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY,
                                   fileSizeLgInt.HighPart, fileSizeLgInt.LowPart, nullptr);
  if (!hMap) {
    CloseHandle(hFile);
    throw std::runtime_error("CreateFileMapping failed");
  }

  void* view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  if (!view) {
    CloseHandle(hMap);
    CloseHandle(hFile);
    throw std::runtime_error("MapViewOfFile failed");
  }

  mf.ptr = static_cast<const uint8_t*>(view);
  mf.size = static_cast<size_t>(fileSize);
  mf.hFile = hFile;
  mf.hMap = hMap;
#else
  int fd = ::open(source.c_str(), O_RDONLY);
  if (fd < 0) throw std::runtime_error("open failed");

  struct stat st {};
  if (fstat(fd, &st) != 0) {
    ::close(fd);
    throw std::runtime_error("fstat failed");
  }
  if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > SIZE_MAX) {
    ::close(fd);
    throw std::runtime_error("File too large for size_t");
  }

  size_t sz = static_cast<size_t>(st.st_size);
  void* addr = mmap(nullptr, sz, PROT_READ, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    ::close(fd);
    throw std::runtime_error("mmap failed");
  }

  mf.ptr = static_cast<const uint8_t*>(addr);
  mf.size = sz;
  mf.fd = fd;
#endif

  return mf;
}