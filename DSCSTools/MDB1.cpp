#include "include/crypto_xor.h"
#include "include/mmap_utils.h"
#include "include/MDB1.h"
#include <map>
#include <future>
#include <iostream>
#include <deque>
#include <exception>
#include <array>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <mutex>
#if __cpp_lib_semaphore >= 201907L
#include <semaphore>
#endif
#include <boost/asio.hpp>
#include <boost/crc.hpp>


#include "../libs/doboz/Compressor.h"
#include "../libs/doboz/Decompressor.h"


	namespace dscstools::mdb1 {
		constexpr auto MDB1_MAGIC_VALUE = 0x3142444D;
		constexpr auto MDB1_CRYPTED_MAGIC_VALUE = 0x608D920C;

		struct TimeTracker {
			std::mutex m;
			int active = 0;
			std::chrono::steady_clock::time_point start, end;
			std::chrono::nanoseconds elapsed = std::chrono::nanoseconds::zero();

			void begin() {
				auto now = std::chrono::steady_clock::now();
				std::lock_guard<std::mutex> lk(m);
				if (active++ == 0) start = now;
			}
			void finish() {
				auto now = std::chrono::steady_clock::now();
				std::lock_guard<std::mutex> lk(m);
				if (--active == 0)
				{
					end = now;
					elapsed += end - start;
				}
				else
					active = 0; // Just in case
			}
			[[nodiscard]] std::chrono::nanoseconds duration() const {
				return elapsed;
			}
			void reset() {
				active = 0;
				elapsed = std::chrono::nanoseconds::zero();
			}
		};

		static TimeTracker preextractionTracker, cryptTracker, compressionTracker, writeTracker, tracker;

		/*std::atomic<long long> cryptTime{0};
		std::atomic<long long> compressionTime{0};
		std::atomic<long long> writeTime{ 0 };*/

		//void printTimeTaken(std::chrono::steady_clock::time_point end, std::chrono::steady_clock::time_point start) {
		//	auto timeElapsed = end - start;
		//	printTimeTaken(timeElapsed);
		//}
		void printTimeTaken(std::chrono::nanoseconds timeElapsed) {
			timeElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(timeElapsed);
			auto timeMin = std::chrono::duration_cast<std::chrono::minutes>(timeElapsed);
			timeElapsed -= timeMin;
			auto timeSec = std::chrono::duration_cast<std::chrono::seconds>(timeElapsed);
			timeElapsed -= timeSec;
			auto timeMilli = std::chrono::duration_cast<std::chrono::milliseconds>(timeElapsed);
			//std::stringstream ss;
			std::cout << "Time taken: "
				<< std::setfill('0') << std::setw(2) << timeMin.count() << ":"
				<< std::setfill('0') << std::setw(2) << timeSec.count() << "."
				<< std::setfill('0') << std::setw(3) << timeMilli.count() << std::endl;
			//OutputDebugString(ss.str().c_str());
		}

		template<std::size_t SIZE>
		void cryptArray(std::array<char, SIZE>& array, uint64_t offset) {
			cryptArray(array.data(), array.size(), offset);
		}

		void cryptArray(char* array, std::size_t size, uint64_t offset) {
			for (int i = 0; i < size; i++)
				array[i] ^= CRYPT_KEY_1[(offset + i) % 997] ^ CRYPT_KEY_2[(offset + i) % 991];
		}

		class mdb1_ifstream : public std::ifstream {
		private:
			bool doCrypt = false;
		public:
			mdb1_ifstream(const std::filesystem::path path, bool doCrypt) : doCrypt(doCrypt), std::ifstream(path, std::ios::in | std::ios::binary) {}
			mdb1_ifstream(const std::filesystem::path path) : std::ifstream(path, std::ios::in | std::ios::binary) {
				uint32_t val = 0;
				read(reinterpret_cast<char*>(&val), 4);
				doCrypt = val == MDB1_CRYPTED_MAGIC_VALUE;
				seekg(0);
			}

			std::istream& read(char* dst, std::streamsize count) {
				std::streampos offset = tellg();
				std::ifstream::read(dst, count);
				if (doCrypt)
					cryptArray(dst, count, offset);
				return *this;
			}
		};

		class mdb1_ofstream : public std::ofstream {
			using std::ofstream::ofstream;
		private:
			bool doCrypt = false;
		public:
			mdb1_ofstream(const std::filesystem::path path, bool doCrypt = false) : doCrypt(doCrypt), std::ofstream(path, std::ios::out | std::ios::binary) {}

			std::ostream& write(char* dst, std::streamsize count) {
				if (doCrypt)
					cryptArray(dst, count, tellp());
				std::ofstream::write(dst, count);
				return *this;
			}
		};

		ArchiveInfo getArchiveInfo(const std::filesystem::path source) {
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: Source path doesn't point to a file, aborting.");

			ArchiveInfo info;

			mdb1_ifstream input(source);

			MDB1Header header;
			input.read(reinterpret_cast<char*>(&header), 0x14);

			if (header.magicValue == MDB1_CRYPTED_MAGIC_VALUE)
				info.status = encrypted;
			else if (header.magicValue == MDB1_MAGIC_VALUE)
				info.status = decrypted;
			else {
				info.status = invalid;
				return info;
			}

			auto fileEntries = std::make_unique<FileEntry[]>(header.fileEntryCount);
			auto nameEntries = std::make_unique<FileNameEntry[]>(header.fileNameCount);
			auto dataEntries = std::make_unique<DataEntry[]>(header.dataEntryCount);

			input.read(reinterpret_cast<char*>(fileEntries.get()), header.fileEntryCount * sizeof(FileEntry));
			input.read(reinterpret_cast<char*>(nameEntries.get()), header.fileNameCount * sizeof(FileNameEntry));
			input.read(reinterpret_cast<char*>(dataEntries.get()), header.dataEntryCount * sizeof(DataEntry));

			info.magicValue = header.magicValue;
			info.fileCount = header.fileEntryCount;
			info.dataStart = header.dataStart;

			for (int i = 0; i < header.fileEntryCount; i++) {
				FileInfo fileInfo;
				fileInfo.file = fileEntries[i];
				fileInfo.name = nameEntries[i];
				if (fileInfo.file.compareBit != 0xFFFF && fileInfo.file.dataId != 0xFFFF)
					fileInfo.data = dataEntries[fileEntries[i].dataId];

				info.fileInfo.push_back(fileInfo);
			}

			return info;
		}

		std::string buildMDB1Path(std::string fileName, std::string extension) {
			if (extension.length() == 3)
				extension = extension.append(" ");

			std::replace(fileName.begin(), fileName.end(), '/', '\\');

			char name[0x41];
			strncpy(name, extension.c_str(), 4);
			strncpy(name + 4, fileName.c_str(), 0x3C);
			name[0x40] = 0; // prevent overflow

			return std::string(name);
		}

		FileInfo findFileEntry(const std::vector<FileInfo>& entries, std::string path) {
			std::replace(path.begin(), path.end(), '/', '\\');
			size_t delimPos = path.rfind('.');

			if (delimPos == -1 || path.size() - delimPos > 5)
				return entries[0];

			std::string finalName = buildMDB1Path(path.substr(0, delimPos), path.substr(delimPos + 1));

			FileInfo currentNode = entries[1];

			while (true) {
				bool isSet = ((finalName[currentNode.file.compareBit >> 3]) >> (currentNode.file.compareBit & 7)) & 1;
				FileInfo nextNode = entries[isSet ? currentNode.file.right : currentNode.file.left];

				if (nextNode.file.compareBit <= currentNode.file.compareBit)
					return std::string(reinterpret_cast<char*>(&nextNode.name)) == finalName ? nextNode : entries[0];

				currentNode = nextNode;
			}

			return entries[0];
		}

		void dobozCompress(const std::filesystem::path source, const std::filesystem::path target) {
			if (std::filesystem::equivalent(source, target))
				throw std::invalid_argument("Error: input and output path must be different!");
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: input path is not a file.");

			if (!std::filesystem::exists(target)) {
				if (target.has_parent_path())
					std::filesystem::create_directories(target.parent_path());
			}
			else if (!std::filesystem::is_regular_file(target))
				throw std::invalid_argument("Error: target path already exists and is not a file.");

			std::ifstream input(source, std::ios::in | std::ios::binary);
			std::ofstream output(target, std::ios::out | std::ios::binary);

			input.seekg(0, std::ios::end);
			std::streampos length = input.tellg();
			input.seekg(0, std::ios::beg);

			auto data = std::make_unique<char[]>(length);
			input.read(data.get(), length);

			doboz::Compressor comp_buf;
			size_t destSize;

			auto outputData = std::make_unique<char[]>(comp_buf.getMaxCompressedSize(length));
			doboz::Result result = comp_buf.compress(data.get(), length, outputData.get(), comp_buf.getMaxCompressedSize(length), destSize);

			if (result != doboz::RESULT_OK)
				throw std::runtime_error("Error: something went wrong while compressing, doboz error code: " + std::to_string(result));

			output.write(outputData.get(), destSize);
		}

		void dobozDecompress(const std::filesystem::path source, const std::filesystem::path target) {
			if (std::filesystem::equivalent(source, target))
				throw std::invalid_argument("Error: input and output path must be different!");
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: input path is not a file.");

			if (!std::filesystem::exists(target)) {
				if (target.has_parent_path())
					std::filesystem::create_directories(target.parent_path());
			}
			else if (!std::filesystem::is_regular_file(target))
				throw std::invalid_argument("Error: target path already exists and is not a file.");

			std::ifstream input(source, std::ios::in | std::ios::binary);
			std::ofstream output(target, std::ios::out | std::ios::binary);
			input.seekg(0, std::ios::end);
			std::streampos length = input.tellg();
			input.seekg(0, std::ios::beg);

			auto data = std::make_unique<char[]>(length);
			input.read(data.get(), length);

			doboz::CompressionInfo info;
			doboz::Decompressor decomp;

			decomp.getCompressionInfo(data.get(), length, info);

			if (info.compressedSize != length || info.version != 0)
				throw std::runtime_error("Error: input file is not doboz compressed!");

			auto outputData = std::make_unique<char[]>(info.uncompressedSize);

			auto result = decomp.decompress(data.get(), length, outputData.get(), info.uncompressedSize);

			if(result != doboz::RESULT_OK)
				throw std::runtime_error("Error: something went wrong while decompressing, doboz error code: " + std::to_string(result));

			std::cout << info.compressedSize << " " << info.uncompressedSize << " " << info.version << std::endl;

			output.write(outputData.get(), info.uncompressedSize);
		}

		void extractMDB1File(const std::filesystem::path source, const std::filesystem::path targetDir, FileInfo fileInfo, uint64_t offset, bool decompress) {
			preextractionTracker.begin();
			mdb1_ifstream input(source);
			std::vector<char> buf(1 << 20);
			input.rdbuf()->pubsetbuf(buf.data(), buf.size());
			doboz::Decompressor decomp;

			if (fileInfo.file.compareBit == 0xFFFF || fileInfo.file.dataId == 0xFFFF)
			{
				preextractionTracker.finish();
				return;
			}

			DataEntry data = fileInfo.data;

			std::filesystem::path path(targetDir / fileInfo.name.toPath());
			if (path.has_parent_path())
				std::filesystem::create_directories(path.parent_path());
			mdb1_ofstream output(path, false);

			auto outputSize = decompress ? data.size : data.compSize;
			auto outputArr = std::make_unique<char[]>(outputSize);
			input.seekg(data.offset + offset);

			preextractionTracker.finish();

			if (data.compSize == data.size || !decompress)
			{
				cryptTracker.begin();
				input.read(outputArr.get(), outputSize);
				cryptTracker.finish();
			}
			else {
				auto dataArr = std::make_unique<char[]>(data.compSize);

				cryptTracker.begin();
				input.read(dataArr.get(), data.compSize);
				cryptTracker.finish();

				compressionTracker.begin();
				doboz::Result result = decomp.decompress(dataArr.get(), data.compSize, outputArr.get(), data.size);
				compressionTracker.finish();

				if (result != doboz::RESULT_OK)
					throw std::runtime_error("Error while decompressing '" + fileInfo.name.toString() + "'. doboz error code : " + std::to_string(result));
			}
			writeTracker.begin();
			output.write(outputArr.get(), outputSize);
			writeTracker.finish();

			if (!output.good())
				throw std::runtime_error("Error: something went wrong while writing " + path.string());
		}

		void extractMDB1File(const std::filesystem::path source, const std::filesystem::path target, FileInfo fileInfo, const bool decompress) {
			extractMDB1File(source, target, fileInfo, getArchiveInfo(source).dataStart, decompress);
		}

		void extractMDB1File(const std::filesystem::path source, const std::filesystem::path target, std::string fileName, const bool decompress) {
			ArchiveInfo info = getArchiveInfo(source);
			FileInfo fileInfo = findFileEntry(info.fileInfo, fileName);

			if (fileInfo.file.compareBit == 0xFFFF || fileInfo.file.dataId == 0xFFFF)
				throw std::invalid_argument("MDB1 File Extraction: File not found in archive");

			extractMDB1File(source, target, fileInfo, info.dataStart, decompress);
		}

		void extractMDB1File(const MappedFile& archiveMap, const Job& job, const bool decompress, const bool multithread = false) {
			//ArchiveInfo info = getArchiveInfo(source);
			//FileInfo fileInfo = findFileEntry(info.fileInfo, fileName);
			//
			//if (fileInfo.file.compareBit == 0xFFFF || fileInfo.file.dataId == 0xFFFF)
			//	throw std::invalid_argument("MDB1 File Extraction: File not found in archive");

			// extractMDB1File(source, target, fileInfo, info.dataStart, decompress);

			const unsigned cores = multithread ? std::max(1u, std::thread::hardware_concurrency()) : 1u;
			
		}

		void extractMDB1_MMAP_parallel(const std::filesystem::path source, const std::filesystem::path target, bool decompress) {
			ArchiveInfo info = dscstools::mdb1::getArchiveInfo(source);
			if (info.status == dscstools::mdb1::invalid) {
				throw std::runtime_error("Not a valid MDB1 file");
			}

			if (!std::filesystem::exists(target)) {
				std::filesystem::create_directories(target);
			}else if (!std::filesystem::is_directory(target))
				throw std::invalid_argument("Error: target path is not a directory.");

			MappedFile archiveMap = mmap_readonly(source);

			std::vector<Job> jobs;
			jobs.reserve(info.fileInfo.size());
			for (auto& fi : info.fileInfo) {
				if (fi.file.compareBit == 0xFFFF || fi.file.dataId == 0xFFFF) continue;
				std::filesystem::path outPath = target / fi.name.toPath();
				jobs.push_back({ fi, outPath });
				if(!std::filesystem::exists(outPath.parent_path()))
					std::filesystem::create_directories(outPath.parent_path());
			}

			const unsigned cores = std::max(1u, std::thread::hardware_concurrency());
			
			boost::asio::thread_pool pool(cores);

			#if __cpp_lib_semaphore >= 201907L
				std::cout << "***USING SEMAPHORES***" << std::endl;
				const unsigned io_slots = std::min(8u, std::max(1u, cores/2));
				std::counting_semaphore<> write_slots(io_slots);
			#endif

			for (const auto& job : jobs) {
				boost::asio::post(pool, [&, job] {
						const auto fn = job.fileInfo.name.toString();
						const auto& data = job.fileInfo.data;
						const uint64_t offset =
							static_cast<uint64_t>(info.dataStart) + data.offset;

						if (offset + data.compSize > archiveMap.size) {
							throw std::runtime_error("Range exceeds mapped file size");
						}
						const uint8_t* archiveFilePtr = archiveMap.ptr + offset;

					thread_local doboz::Decompressor decomp;
					thread_local std::vector<char> comp_buf;
					thread_local std::vector<char> plain_buf;
					thread_local std::vector<char> chunk_buf(8u << 20); // 8 MiB
					thread_local std::vector<char> io_buf(8u << 20);    // 8 MiB stream buffer

						const bool needsDecomp =
							(data.compSize != data.size) && decompress;

					//if (!needsDecomp) {

					//	if (20000 <= data.compSize)
					//		std::cout << "File: " << fn << " CompSize: " << data.compSize << " Size: " << data.size << std::endl;

					//	maxSize = std::max<uint32_t>(maxSize, data.compSize);

					//	continue;

						if (!needsDecomp) {

							// Stream XOR -> write

							uint64_t remain = decompress ? data.size : data.compSize;
							uint64_t pos = 0;

					//	while (remain) {
					//		const size_t chunkSize = static_cast<size_t>(
					//			std::min<uint64_t>(remain, chunk.size()));
					//		fast_xor_cipher::xor_into(archiveFilePtr + pos, chunk.data(), chunkSize, offset + pos);
					//		out.write(chunk.data(), chunkSize);
					//		pos += chunkSize;
					//		remain -= chunkSize;
					//	}
					//	out.flush();
					//	out.close();
					//	if (!out.good()) {
					//		throw std::runtime_error("Write failed: " +
					//			job.outPath.string());
					//	}
					//	#if __cpp_lib_semaphore >= 201907L
					//		//write_slots.release();
					//	#endif
					//	//return;
					//	continue;
					//}
					//continue;
							#if __cpp_lib_semaphore >= 201907L
								write_slots.acquire();
							#endif

							{
								std::ofstream out(job.outPath, std::ios::binary);
								out.rdbuf()->pubsetbuf(io_buf.data(), static_cast<std::streamsize>(io_buf.size()));

								while (remain) {
									const size_t chunkSize = static_cast<size_t>(
										std::min<uint64_t>(remain, chunk_buf.size()));
									fast_xor_cipher::xor_into(archiveFilePtr + pos, chunk_buf.data(), chunkSize, offset + pos);
									out.write(chunk_buf.data(), static_cast<std::streamsize>(chunkSize));
									pos += chunkSize;
									remain -= chunkSize;
								}

								if (out.bad()) {
									throw std::runtime_error("Write failed: " +
										job.outPath.string());
								}
							}

							#if __cpp_lib_semaphore >= 201907L
								write_slots.release();
							#endif
							return;
						}

						// Compressed: XOR comp -> decompress -> write
						if(comp_buf.size() < data.compSize)
							comp_buf.resize(data.compSize);
						if (plain_buf.size() < data.size)
							plain_buf.resize(data.size);
						fast_xor_cipher::xor_into(archiveFilePtr, comp_buf.data(), data.compSize, offset);

						auto res = decomp.decompress(comp_buf.data(),
							data.compSize,
							plain_buf.data(),
							data.size);
						if (res != doboz::RESULT_OK) {
							throw std::runtime_error("Doboz error: " + std::to_string(res));
						}

						#if __cpp_lib_semaphore >= 201907L
						write_slots.acquire();
						#endif
						{
							std::ofstream out(job.outPath, std::ios::binary);
							out.rdbuf()->pubsetbuf(io_buf.data(), static_cast<std::streamsize>(io_buf.size()));
							out.write(plain_buf.data(), static_cast<std::streamsize>(data.size));

							if (out.bad()) {
								throw std::runtime_error("Write failed: " +
									job.outPath.string());
							}
						}

						#if __cpp_lib_semaphore >= 201907L
						write_slots.release();
						#endif
				});
			}
			pool.join();
		}

		void extractMDB1_MMAP_single(const std::filesystem::path source, const std::filesystem::path target, bool decompress) {
			if (std::filesystem::exists(target) && !std::filesystem::is_directory(target))
				throw std::invalid_argument("Error: Target path exists and is not a directory, aborting.");
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: Source path doesn't point to a file, aborting.");

			std::cout << "  Getting Archive Info..." << std::endl;

			tracker.begin();
			ArchiveInfo info = getArchiveInfo(source);
			tracker.finish();

			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();

			if (info.status == invalid)
				throw std::invalid_argument("Error: not a MDB1 file. Value: " + std::to_string(info.magicValue));

			

			// Map Entire File to Memory

			std::cout << "  Mapping File to Memory..." << std::endl;

			tracker.begin();
			MappedFile mappedFile = mmap_readonly(source);
			tracker.finish();

			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();


			std::cout << "  Sorting Files before extraction..." << std::endl;

			tracker.begin();
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
			tracker.finish();

			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();


			std::cout << "  Extracting..." << std::endl;

			tracker.begin();
			std::vector<char> chunk(1 << 20); // 1 MB for streaming copies
			doboz::Decompressor decomp;

			for (FileInfo& file : files) {

				preextractionTracker.begin();
				const DataEntry& data = file.data;
				const uint64_t offset = static_cast<uint64_t>(info.dataStart) + data.offset; // Find absolute offset for file
				if (offset + data.compSize > mappedFile.size) {
					throw std::runtime_error("Range exceeds mapped file size");
				}

				// Next 3 lines: 13~sec
				std::filesystem::path outPath(target / file.name.toPath());
				const auto parent = outPath.parent_path();
				if (!parent.empty()) std::filesystem::create_directories(parent);

				std::ofstream out(outPath, std::ios::binary); // 5~sec

				const uint8_t* fileDataPtr = mappedFile.ptr + offset;

				const bool needsDecomp =
					(data.compSize != data.size) && decompress;
				preextractionTracker.finish();
				if (!needsDecomp) {
					// Stream copy: XOR from mapped memory into chunk and write
					uint64_t remain = decompress ? data.size : data.compSize;
					uint64_t pos = 0;
					while (remain) {
						const size_t chunk_size =
							static_cast<size_t>(std::min<uint64_t>(remain, chunk.size()));
						cryptTracker.begin();
						fast_xor_cipher::xor_into(fileDataPtr + pos, chunk.data(), chunk_size, offset + pos);
						cryptTracker.finish();
						writeTracker.begin();
						out.write(chunk.data(), chunk_size);
						writeTracker.finish();
						pos += chunk_size;
						remain -= chunk_size;
					}
					if (!out.good()) {
						throw std::runtime_error("Write failed: " + outPath.string());
					}
					continue;
				}

				// Compressed: XOR compressed bytes into compBuf, then decompress
				std::unique_ptr<char[]> comp_buf(new char[data.compSize]);
				cryptTracker.begin();
				fast_xor_cipher::xor_into(fileDataPtr, comp_buf.get(), data.compSize, offset);
				cryptTracker.finish();
				std::unique_ptr<char[]> plain(new char[data.size]);
				compressionTracker.begin();
				auto res = decomp.decompress(comp_buf.get(),
					data.compSize,
					plain.get(),
					data.size);
				if (res != doboz::RESULT_OK) {
					throw std::runtime_error("Doboz error: " + std::to_string(res));
				}
				compressionTracker.finish();
				writeTracker.begin();
				out.write(plain.get(), data.size);
				writeTracker.finish();
				if (!out.good()) {
					throw std::runtime_error("Write failed: " + outPath.string());
				}
			}
			tracker.finish();

			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();

			std::cout << std::endl << "Average speed:" << std::endl;
			std::cout << "  PreExtraction "; printTimeTaken(preextractionTracker.duration());
			std::cout << "  Decryption "; printTimeTaken(cryptTracker.duration());
			std::cout << "  Decompression "; printTimeTaken(compressionTracker.duration());
			std::cout << "  File writing "; printTimeTaken(writeTracker.duration());
		}

		void extractMDB1(const std::filesystem::path source, const std::filesystem::path target, bool decompress) {
			if (std::filesystem::exists(target) && !std::filesystem::is_directory(target))
				throw std::invalid_argument("Error: Target path exists and is not a directory, aborting.");
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: Source path doesn't point to a file, aborting.");

			std::cout << "  Getting Archive Info..." << std::endl;

			tracker.begin();
			ArchiveInfo info = getArchiveInfo(source);
			tracker.finish();

			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();

			if (info.status == invalid)
				throw std::invalid_argument("Error: not a MDB1 file. Value: " + std::to_string(info.magicValue));

			std::cout << "  Extracting Files..." << std::endl;
			tracker.begin();
			for (FileInfo& fileInfo : info.fileInfo)
				extractMDB1File(source, target, fileInfo, info.dataStart, decompress);
			tracker.finish();
			std::cout << "    Done! ";
			printTimeTaken(tracker.duration());
			tracker.reset();

			std::cout << std::endl << "Average speed:" << std::endl;
			std::cout << "  PreExtraction "; printTimeTaken(preextractionTracker.duration());
			std::cout << "  Decryption "; printTimeTaken(cryptTracker.duration());
			std::cout << "  Decompression "; printTimeTaken(compressionTracker.duration());
			std::cout << "  File writing "; printTimeTaken(writeTracker.duration());
		}

		TreeNode findFirstBitMismatch(const uint16_t first, const std::vector<std::string>& nodeless, const std::vector<std::string>& withNode) {
			if (withNode.size() == 0)
				return { first, 0, 0, nodeless[0] };

			for (uint16_t i = first; i < 512; i++) {
				bool set = false;
				bool unset = false;

				for (auto file : withNode) {
					if ((file[i >> 3] >> (i & 7)) & 1)
						set = true;
					else
						unset = true;

					if (set && unset)
						return { i, 0, 0, nodeless[0] };
				}

				auto itr = std::find_if(nodeless.begin(), nodeless.end(), [set, unset, i](const std::string &file) {
					bool val = (file[i >> 3] >> (i & 7)) & 1;
					return val && unset || !val && set;
					});

				if (itr != nodeless.end())
					return { i, 0, 0, *itr };
			}

			return { 0xFFFF, 0xFFFF, 0, "" };
		}

		std::vector<TreeNode> generateTree(const std::filesystem::path path) {
			std::vector<std::string> fileNames;

			std::filesystem::recursive_directory_iterator itr(path);

			for (auto i : itr) {
				if (std::filesystem::is_regular_file(i)) {
					std::string ext = i.path().extension().string().substr(1, 5);
					std::string filePath = std::filesystem::relative(i.path(), path).replace_extension("").string();

					fileNames.push_back(buildMDB1Path(filePath, ext));
				}
			}

			// sort filesnames for consistent results
			std::sort(fileNames.begin(), fileNames.end(), [](std::string first, std::string second) {
				int result = first.compare(4, first.size() - 4, second, 4, second.size() - 4);
				return (result == 0 ? first.compare(0, 4, second, 0, 4) : result) < 0;
				});

			struct QueueEntry {
				uint16_t parentNode;
				uint16_t val1;
				std::vector<std::string> list;
				std::vector<std::string> nodeList;
				bool left;
			};

			std::vector<TreeNode> nodes = { { 0xFFFF, 0, 0, "" } };
			std::deque<QueueEntry> queue = { { 0, 0xFFFF, fileNames, std::vector<std::string>(), false } };

			while (!queue.empty()) {
				QueueEntry entry = queue.front();
				queue.pop_front();
				TreeNode &parent = nodes[entry.parentNode];

				std::vector <std::string> nodeless;
				std::vector <std::string> withNode;

				for (auto file : entry.list) {
					if (std::find(entry.nodeList.begin(), entry.nodeList.end(), file) == entry.nodeList.end())
						nodeless.push_back(file);
					else
						withNode.push_back(file);
				}

				if (nodeless.size() == 0) {
					auto firstFile = entry.list[0];
					auto itr = std::find_if(nodes.begin(), nodes.end(), [firstFile](const TreeNode &node) { return node.name == firstFile; });
					ptrdiff_t offset = std::distance(nodes.begin(), itr);

					if (entry.left)
						parent.left = (uint16_t)offset;
					else
						parent.right = (uint16_t)offset;

					continue;
				}

				TreeNode child = findFirstBitMismatch(entry.val1 + 1, nodeless, withNode);

				if (entry.left)
					parent.left = (uint16_t)nodes.size();
				else
					parent.right = (uint16_t)nodes.size();

				std::vector<std::string> left;
				std::vector<std::string> right;

				for (auto file : entry.list) {
					if ((file[child.compareBit >> 3] >> (child.compareBit & 7)) & 1)
						right.push_back(file);
					else
						left.push_back(file);
				}

				std::vector<std::string> newNodeList = entry.nodeList;
				newNodeList.push_back(child.name);

				if (left.size() > 0) queue.push_front({ static_cast<uint16_t>(nodes.size()), child.compareBit, left, newNodeList, true });
				if (right.size() > 0) queue.push_front({ static_cast<uint16_t>(nodes.size()), child.compareBit, right, newNodeList, false });
				nodes.push_back(child);
			}

			return nodes;
		}

		CompressionResult getFileData(const std::filesystem::path path, const CompressMode compress) {
			std::ifstream input(path, std::ios::in | std::ios::binary);

			input.seekg(0, std::ios::end);
			std::streampos length = input.tellg();
			input.seekg(0, std::ios::beg);

			auto data = std::make_unique<char[]>(length);
			input.read(data.get(), length);

			boost::crc_32_type crc;
			if (compress == advanced)
				crc.process_bytes(data.get(), length);

			if (!input.good())
				throw std::runtime_error("Error: something went wrong while reading " + path.string());
			
			doboz::Decompressor decomp;
			doboz::CompressionInfo info;
			doboz::Result result = decomp.getCompressionInfo(data.get(), length, info);

			if (length != 0) {
				if (result == doboz::RESULT_OK && info.uncompressedSize != 0 && info.version == 0 && info.compressedSize == length)
					return { (uint32_t)info.uncompressedSize, (uint32_t)info.compressedSize, static_cast<uint32_t>(crc.checksum()), std::move(data) };

				if (compress >= normal) {
					doboz::Compressor comp_buf;
					size_t destSize;
					auto outputData = std::make_unique<char[]>(comp_buf.getMaxCompressedSize(length));
					doboz::Result res = comp_buf.compress(data.get(), length, outputData.get(), comp_buf.getMaxCompressedSize(length), destSize);

					if (res != doboz::RESULT_OK)
						throw std::runtime_error("Error: something went wrong while compressing, doboz error code: " + std::to_string(res));

					if (destSize + 4 < static_cast<size_t>(length))
						return { (uint32_t)length, (uint32_t)destSize, static_cast<uint32_t>(crc.checksum()), std::move(outputData) };
				}
			}

			return { (uint32_t)length, (uint32_t)length, static_cast<uint32_t>(crc.checksum()), std::move(data) };
		}

		void packMDB1(const std::filesystem::path source, const std::filesystem::path target, const CompressMode compress, bool doCrypt, std::ostream& progressStream) {
			if (!std::filesystem::is_directory(source))
				throw std::invalid_argument("Error: source path is not a directory.");

			if (!std::filesystem::exists(target)) {
				if (target.has_parent_path())
					std::filesystem::create_directories(target.parent_path());
			}
			else if (!std::filesystem::is_regular_file(target))
				throw std::invalid_argument("Error: target path already exists and is not a file.");

			progressStream << "Generating file tree..." << std::endl;
			std::vector<std::filesystem::path> files;
			std::vector<TreeNode> nodes = generateTree(source);

			for (auto i : std::filesystem::recursive_directory_iterator(source))
				if (std::filesystem::is_regular_file(i))
					files.push_back(i);

			std::sort(files.begin(), files.end());

			// start compressing files
			std::map<std::string, std::promise<CompressionResult>> futureMap;

			size_t coreCount = std::thread::hardware_concurrency();
			boost::asio::thread_pool pool(coreCount * 2); // twice the core count to account for blocking threads
			progressStream << "Start compressing files with " << coreCount * 2 << " threads..." << std::endl;

			for (auto file : files) {
				futureMap[file.string()] = std::promise<CompressionResult>();

				boost::asio::post(pool, [&promise = futureMap[file.string()], file, compress]{
					try {
						promise.set_value(getFileData(file, compress));
					}
					catch (std::exception ex) {
						promise.set_exception(std::make_exception_ptr(ex));
					} });
			}

			std::vector<FileEntry> header1(files.size() + 1);
			std::vector<FileNameEntry> header2(files.size() + 1);
			std::vector<DataEntry> header3;

			mdb1_ofstream output(target, doCrypt);

			size_t dataStart = 0x14 + (1 + files.size()) * 0x08 + (1 + files.size()) * 0x40 + (files.size()) * 0x0C;
			MDB1Header header = { MDB1_MAGIC_VALUE, (uint16_t)(files.size() + 1), (uint16_t)(files.size() + 1), (uint32_t)files.size(), (uint32_t)dataStart };

			header1[0] = { 0xFFFF, 0xFFFF, 0, 1 };
			header2[0] = FileNameEntry();

			uint32_t fileCount = 0;
			size_t numFiles = files.size();
			progressStream << "Start writing " << numFiles << " files..." << std::endl;

			uint32_t offset = 0;
			std::map<uint32_t, size_t> dataMap;

			for (auto file : files) {
				if (++fileCount % 200 == 0)
					progressStream << "File " << fileCount << " of " << numFiles << std::endl;

				// fill in name
				FileNameEntry entry2;

				std::string ext = file.extension().string().substr(1, 5);
				if (ext.length() == 3)
					ext = ext.append(" ");

				// strncpy weirdness intended
				std::string filePath = std::filesystem::relative(file, source).replace_extension("").string();
				std::replace(filePath.begin(), filePath.end(), '/', '\\');

				strncpy(entry2.extension, ext.c_str(), 4);
				strncpy(entry2.name, filePath.c_str(), 0x3C);

				// find corresponding node, create table entry
				auto found = std::find_if(nodes.begin(), nodes.end(), [entry2](const TreeNode &node) { return node.name == entry2.extension; });
				if (found == nodes.end())
					throw std::runtime_error("Fatal error: Couldn't find node for " + entry2.toString());

				TreeNode treeNode = *found;
				ptrdiff_t nodeId = std::distance(nodes.begin(), found);

				// get data and write it
				CompressionResult data = futureMap[file.string()].get_future().get();
				futureMap.erase(file.string());

				bool hasEntry = compress == advanced && dataMap.find(data.crc) != dataMap.end();

				// store table entries
				header1[nodeId] = { treeNode.compareBit, (uint16_t)(hasEntry ? dataMap.at(data.crc) : header3.size()), treeNode.left, treeNode.right };
				header2[nodeId] = entry2;
				if (!hasEntry) {
					dataMap[data.crc] = header3.size();
					header3.push_back({ offset, data.originalSize, data.size });

					output.seekp(dataStart + offset);
					output.write(data.data.get(), data.size);
					offset += data.size;
				}
			}

			progressStream << "Writing and compressing files complete." << std::endl;

			// write file table and header
			output.seekp(0x14);

			for (auto entry : header1)
				output.write(reinterpret_cast<char*>(&entry), 0x08);
			for (auto entry : header2)
				output.write(reinterpret_cast<char*>(&entry), 0x40);
			for (auto entry : header3)
				output.write(reinterpret_cast<char*>(&entry), 0x0C);

			output.seekp(0x00);
			output.seekp(0, std::ios::end);
			std::streamoff length = output.tellp();
			output.seekp(0, std::ios::beg);

			header.totalSize = (uint32_t)length;
			header.dataEntryCount = (uint32_t)header3.size();
			output.write(reinterpret_cast<char*>(&header), 0x14);

			if (!output.good())
				throw std::runtime_error("Error: something went wrong with the output stream.");
		}

		void cryptFile(const std::filesystem::path source, const std::filesystem::path target) {
			if (std::filesystem::equivalent(source, target))
				throw std::invalid_argument("Error: input and output path must be different!");
			if (!std::filesystem::is_regular_file(source))
				throw std::invalid_argument("Error: input path is not a file.");

			if (!std::filesystem::exists(target)) {
				if (target.has_parent_path())
					std::filesystem::create_directories(target.parent_path());
			}
			else if (!std::filesystem::is_regular_file(target))
				throw std::invalid_argument("Error: target path already exists and is not a file.");

			mdb1_ifstream input(source, false);
			mdb1_ofstream output(target, true);

			std::streamsize offset = 0;

			std::array<char, 0x2000> inArr;

			while (!input.eof()) {
				input.read(inArr.data(), 0x2000);
				std::streamsize count = input.gcount();
				output.write(inArr.data(), count);
				offset += count;
			}
		}
	}
}