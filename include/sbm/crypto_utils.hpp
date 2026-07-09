#pragma once

#include <string>
#include <vector>

namespace sbm::security {

constexpr size_t KEY_SIZE = 32;
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t AES_GCM_IV_BYTES = 12;
constexpr size_t AES_GCM_TAG_BYTES = 16;

void secure_zero_memory(void *ptr, size_t size);

class secure_string {
public:
  secure_string() = default;
  explicit secure_string(std::string s);
  ~secure_string();

  secure_string(const secure_string &other);
  secure_string &operator=(const secure_string &other);

  secure_string(secure_string &&other) noexcept;
  secure_string &operator=(secure_string &&other) noexcept;

  [[nodiscard]] const std::string &value() const { return data_; }
  [[nodiscard]] bool empty() const { return data_.empty(); }

private:
  std::string data_;
};

std::vector<unsigned char> derive_machine_key();

// Writes AES-256-GCM: "gcm:IV:TAG:CIPHERTEXT" (hex segments).
std::string encrypt_string(const std::string &plaintext,
                           const std::vector<unsigned char> &key);

// Reads GCM, legacy AES-CBC ("IV:CIPHER"), or legacy Watchdog DPAPI (hex blob).
std::string decrypt_string(const std::string &encrypted_format,
                           const std::vector<unsigned char> &key);

} // namespace sbm::security
