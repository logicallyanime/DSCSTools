#pragma once
#include <filesystem>

namespace dscstools::savefile
{
    /**
     * Encrypts the PC save file given by sourceFile into targetFile.
     */
    void decryptSaveFile(const std::filesystem::path& source, const std::filesystem::path& target);

    /**
     * Decrypts the PC save file given by sourceFile into targetFile.
     */
    void encryptSaveFile(const std::filesystem::path& source, const std::filesystem::path& target);
} // namespace dscstools::savefile
