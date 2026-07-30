#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace sbm::security {

constexpr size_t KEY_SIZE = 32;
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t AES_GCM_IV_BYTES = 12;
constexpr size_t AES_GCM_TAG_BYTES = 16;

void secure_zero_memory(void *ptr, size_t size);

// Move-only secret buffer. Copy is deleted so plaintext is not silently
// duplicated; move-assign / destructor wipe the prior backing store.
class secure_string {
public:
  secure_string() = default;
  explicit secure_string(std::string s);
  ~secure_string();

  secure_string(const secure_string &) = delete;
  secure_string &operator=(const secure_string &) = delete;

  secure_string(secure_string &&other) noexcept;
  secure_string &operator=(secure_string &&other) noexcept;

  [[nodiscard]] const std::string &value() const { return data_; }
  [[nodiscard]] bool empty() const { return data_.empty(); }

private:
  std::string data_;
};

// Wide counterpart for ODBC connection strings and SQL passwords held in memory.
// Move-only; destructor / clear / move-assign zeroize the backing buffer.
class secure_wstring {
public:
  secure_wstring() = default;
  explicit secure_wstring(std::wstring s);
  ~secure_wstring();

  secure_wstring(const secure_wstring &) = delete;
  secure_wstring &operator=(const secure_wstring &) = delete;

  secure_wstring(secure_wstring &&other) noexcept;
  secure_wstring &operator=(secure_wstring &&other) noexcept;

  secure_wstring &append(std::wstring_view sv);
  secure_wstring &append(const wchar_t *p);
  secure_wstring &append(wchar_t c);
  secure_wstring &operator+=(std::wstring_view sv) { return append(sv); }
  secure_wstring &operator+=(const wchar_t *p) { return append(p); }
  secure_wstring &operator+=(wchar_t c) { return append(c); }

  void reserve(size_t n) { data_.reserve(n); }
  void clear();

  [[nodiscard]] const std::wstring &value() const { return data_; }
  [[nodiscard]] const wchar_t *c_str() const { return data_.c_str(); }
  [[nodiscard]] size_t size() const { return data_.size(); }
  [[nodiscard]] bool empty() const { return data_.empty(); }

  friend bool operator==(const secure_wstring &a, const secure_wstring &b) {
    return a.data_ == b.data_;
  }
  friend bool operator!=(const secure_wstring &a, const secure_wstring &b) {
    return !(a == b);
  }

private:
  std::wstring data_;
};

std::vector<unsigned char> derive_machine_key();

// Writes AES-256-GCM: "gcm:IV:TAG:CIPHERTEXT" (hex segments).
// Uses the key from derive_machine_key() (HMAC over a DPAPI LocalMachine secret).
std::string encrypt_string(const std::string &plaintext,
                           const std::vector<unsigned char> &key);

// Reads GCM, legacy AES-CBC ("IV:CIPHER"), or legacy Watchdog DPAPI (hex blob).
// For GCM/CBC, if `key` fails authentication, retries once with the legacy
// SHA256(MachineGuid) key so older on-disk credentials keep decrypting.
std::string decrypt_string(const std::string &encrypted_format,
                           const std::vector<unsigned char> &key);

} // namespace sbm::security
