#pragma once

#include "fixer.hpp"

namespace fixer {
class Directory;

class DirectoryLock {
  struct Impl;
  std::unique_ptr<Impl> impl_;
  DirectoryLock(const Directory &directory, const std::string &name);
  friend class Directory;

 public:
  ~DirectoryLock();
};

// An opened directory, not a path that is resolved again for each operation.
// Child directories retain their parent. All names are single path components.
class Directory {
  struct Impl;
  std::shared_ptr<Impl> impl_;
  explicit Directory(std::shared_ptr<Impl> impl);
  friend class DirectoryLock;

 public:
  struct Entry {
    std::string name;
    bool directory;
  };

  explicit Directory(const fs::path &path);
  Directory child(const std::string &name) const;
  bool exists(const std::string &name) const;
  void create_private(const std::string &name) const;
  Bytes read(const std::string &name, std::size_t limit) const;
  void write(const std::string &name,
             std::span<const unsigned char> bytes) const;
  void write_text(const std::string &name, const std::string &text) const;
  void replace(const std::string &name, const std::string &text) const;
  void rename(const std::string &name, const Directory &destination,
              const std::string &destination_name) const;
  std::vector<Entry> entries() const;
  void sync() const;
  void verify_location() const;
  std::unique_ptr<DirectoryLock> lock(const std::string &name) const;
};

Json directory_inventory(const Directory &directory);
Cdm read_cdm(const Directory &directory);
}  // namespace fixer
