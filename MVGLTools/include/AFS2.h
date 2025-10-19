#pragma once
#include <filesystem>

namespace mvgltools::afs2
{
    /**
     * Extracts the AFS2 archive given by sourceFile into targetPath.
     */
    void extractAFS2(const std::filesystem::path& source, const std::filesystem::path& target);

    /**
     * Packs the folder given by sourcePath into an AFS2 archive saved into targetFile.
     */
    void packAFS2(const std::filesystem::path& source, const std::filesystem::path& target);
} // namespace mvgltools::afs2
