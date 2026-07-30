#include "sbm/crypto_utils.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace sbm::security {
namespace {

namespace fs = std::filesystem;

#ifndef CRYPT_PROTECT_LOCAL_MACHINE
#define CRYPT_PROTECT_LOCAL_MACHINE 0x00000004
#endif

void wipe_buffer(void *ptr, const size_t size) noexcept {
  if (ptr && size > 0) {
    SecureZeroMemory(ptr, size);
  }
}

void wipe_vector(std::vector<unsigned char> &v) noexcept {
  if (!v.empty()) {
    wipe_buffer(v.data(), v.size());
  }
  v.clear();
  v.shrink_to_fit();
}

struct evp_cipher_ctx_deleter {
  void operator()(EVP_CIPHER_CTX *ctx) const noexcept {
    EVP_CIPHER_CTX_free(ctx);
  }
};

using evp_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, evp_cipher_ctx_deleter>;

[[nodiscard]] evp_ctx_ptr make_evp_ctx() {
  evp_ctx_ptr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }
  return ctx;
}

std::string wide_to_utf8(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                    static_cast<int>(w.size()), nullptr, 0,
                                    nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  if (n > 0) {
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), n, nullptr, nullptr);
  }
  return s;
}

std::string to_hex(const unsigned char *data, const size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(data[i]);
  }
  return ss.str();
}

std::vector<unsigned char> from_hex(const std::string &hex) {
  if (hex.length() % 2 != 0) {
    throw std::runtime_error("Invalid hex string length");
  }
  std::vector<unsigned char> bytes;
  bytes.reserve(hex.length() / 2);
  for (size_t i = 0; i < hex.length(); i += 2) {
    const std::string byte_string = hex.substr(i, 2);
    bytes.push_back(static_cast<unsigned char>(
        strtol(byte_string.c_str(), nullptr, 16)));
  }
  return bytes;
}

std::string get_openssl_error() {
  char buf[256]{};
  ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
  return std::string(buf);
}

constexpr char k_gcm_prefix[] = "gcm:";

std::optional<std::string> try_decrypt_dpapi(const std::vector<unsigned char> &cipher_bytes,
                                             const DWORD flags) {
  DATA_BLOB input{};
  input.pbData = const_cast<BYTE *>(cipher_bytes.data());
  input.cbData = static_cast<DWORD>(cipher_bytes.size());

  DATA_BLOB output{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, flags,
                          &output)) {
    return std::nullopt;
  }

  std::string plaintext(reinterpret_cast<char *>(output.pbData), output.cbData);
  // Zeroize DPAPI plaintext before returning the heap to the allocator.
  wipe_buffer(output.pbData, output.cbData);
  LocalFree(output.pbData);
  return plaintext;
}

std::optional<std::vector<unsigned char>>
try_unprotect_dpapi_bytes(const std::vector<unsigned char> &cipher_bytes,
                          const DWORD flags) {
  DATA_BLOB input{};
  input.pbData = const_cast<BYTE *>(cipher_bytes.data());
  input.cbData = static_cast<DWORD>(cipher_bytes.size());

  DATA_BLOB output{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, flags,
                          &output)) {
    return std::nullopt;
  }

  std::vector<unsigned char> plain(output.pbData, output.pbData + output.cbData);
  wipe_buffer(output.pbData, output.cbData);
  LocalFree(output.pbData);
  return plain;
}

std::vector<unsigned char>
protect_dpapi_bytes(const std::vector<unsigned char> &plain, const DWORD flags) {
  DATA_BLOB input{};
  input.pbData = const_cast<BYTE *>(plain.data());
  input.cbData = static_cast<DWORD>(plain.size());

  DATA_BLOB output{};
  if (!CryptProtectData(&input, L"SBM machine AES key material", nullptr,
                        nullptr, nullptr, flags, &output)) {
    throw std::runtime_error(
        "CryptProtectData failed while protecting machine key material. "
        "Win32=" +
        std::to_string(GetLastError()));
  }

  std::vector<unsigned char> blob(output.pbData, output.pbData + output.cbData);
  wipe_buffer(output.pbData, output.cbData);
  LocalFree(output.pbData);
  return blob;
}

std::string decrypt_cbc_legacy(const std::string &encrypted_format,
                               const std::vector<unsigned char> &key) {
  const auto delim_pos = encrypted_format.find(':');
  if (delim_pos == std::string::npos) {
    throw std::invalid_argument("Invalid encrypted format (missing colon)");
  }

  const std::string iv_hex = encrypted_format.substr(0, delim_pos);
  const std::string ct_hex = encrypted_format.substr(delim_pos + 1);

  const std::vector<unsigned char> iv = from_hex(iv_hex);
  const std::vector<unsigned char> ciphertext = from_hex(ct_hex);

  if (iv.size() != BLOCK_SIZE) {
    throw std::runtime_error("Invalid IV size");
  }

  auto ctx = make_evp_ctx();

  if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(),
                              iv.data())) {
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  std::vector<unsigned char> plaintext(ciphertext.size() + BLOCK_SIZE);
  int len = 0;
  int plaintext_len = 0;

  if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                             static_cast<int>(ciphertext.size()))) {
    wipe_vector(plaintext);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
    wipe_vector(plaintext);
    throw std::runtime_error(
        "Decryption failed (CBC padding check failed). Ensure this is the "
        "same machine where encryption occurred.");
  }
  plaintext_len += len;
  plaintext.resize(static_cast<size_t>(plaintext_len));
  ctx.reset();

  std::string out(plaintext.begin(), plaintext.end());
  wipe_vector(plaintext);
  return out;
}

std::string decrypt_gcm(const std::string &encrypted_format,
                        const std::vector<unsigned char> &key) {
  constexpr int IV_LEN = static_cast<int>(AES_GCM_IV_BYTES);
  constexpr int TAG_LEN = static_cast<int>(AES_GCM_TAG_BYTES);

  const std::string rest =
      encrypted_format.substr(sizeof(k_gcm_prefix) - 1);
  const auto p1 = rest.find(':');
  const auto p2 =
      (p1 == std::string::npos) ? std::string::npos : rest.find(':', p1 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos) {
    throw std::invalid_argument("Invalid GCM encrypted format");
  }

  const std::vector<unsigned char> iv = from_hex(rest.substr(0, p1));
  const std::vector<unsigned char> tag =
      from_hex(rest.substr(p1 + 1, p2 - p1 - 1));
  const std::vector<unsigned char> ciphertext = from_hex(rest.substr(p2 + 1));

  if (static_cast<int>(iv.size()) != IV_LEN) {
    throw std::runtime_error("Invalid GCM IV size");
  }
  if (static_cast<int>(tag.size()) != TAG_LEN) {
    throw std::runtime_error("Invalid GCM tag size");
  }

  auto ctx = make_evp_ctx();

  if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                              nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) ||
      1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
    throw std::runtime_error("EVP_DecryptInit_ex (GCM) failed");
  }

  std::vector<unsigned char> plaintext(ciphertext.size() + BLOCK_SIZE);
  int len = 0;
  int plaintext_len = 0;

  if (!ciphertext.empty()) {
    if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                               static_cast<int>(ciphertext.size()))) {
      wipe_vector(plaintext);
      throw std::runtime_error("EVP_DecryptUpdate (GCM) failed");
    }
    plaintext_len = len;
  }

  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                               const_cast<unsigned char *>(tag.data()))) {
    wipe_vector(plaintext);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl(SET_TAG) failed");
  }

  const int rc =
      EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len);
  ctx.reset();
  if (rc != 1) {
    wipe_vector(plaintext);
    throw std::runtime_error(
        "Decryption failed (GCM authentication check failed). The credential "
        "blob was tampered with, or this is not the machine where it was "
        "encrypted.");
  }
  plaintext_len += len;
  plaintext.resize(static_cast<size_t>(plaintext_len));

  std::string out(plaintext.begin(), plaintext.end());
  wipe_vector(plaintext);
  return out;
}

std::string decrypt_dpapi_legacy(const std::string &stored) {
  const std::vector<unsigned char> cipher_bytes = from_hex(stored);
  if (auto plain = try_decrypt_dpapi(cipher_bytes, CRYPT_PROTECT_LOCAL_MACHINE)) {
    return *plain;
  }
  if (auto plain = try_decrypt_dpapi(cipher_bytes, 0)) {
    return *plain;
  }
  throw std::runtime_error(
      "DPAPI decryption failed. Re-encrypt credentials with PLAINTEXT status "
      "and restart the service on this machine.");
}

std::wstring read_machine_guid_w() {
  wchar_t guid_buf[256]{};
  DWORD buf_size = sizeof(guid_buf);
  const LSTATUS status = RegGetValueW(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
      RRF_RT_REG_SZ, nullptr, guid_buf, &buf_size);
  if (status != ERROR_SUCCESS) {
    wipe_buffer(guid_buf, sizeof(guid_buf));
    throw std::runtime_error(
        "derive_machine_key: MachineGuid is unavailable "
        "(HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid). Refusing to "
        "derive a weak fallback key. LSTATUS=" +
        std::to_string(status));
  }
  std::wstring guid(guid_buf);
  wipe_buffer(guid_buf, sizeof(guid_buf));
  return guid;
}

// Pre-1.2610.191.14 key: SHA256(MachineGuid). Kept for decrypting older blobs.
std::vector<unsigned char> derive_machine_key_legacy_sha256_guid() {
  const std::wstring guid_w = read_machine_guid_w();
  std::string guid = wide_to_utf8(guid_w);

  std::vector<unsigned char> key(SHA256_DIGEST_LENGTH);
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    wipe_buffer(guid.data(), guid.size());
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }

  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) ||
      1 != EVP_DigestUpdate(mdctx, guid.data(), guid.size()) ||
      1 != EVP_DigestFinal_ex(mdctx, key.data(), nullptr)) {
    EVP_MD_CTX_free(mdctx);
    wipe_buffer(guid.data(), guid.size());
    wipe_vector(key);
    throw std::runtime_error("SHA256 calculation failed");
  }
  EVP_MD_CTX_free(mdctx);
  wipe_buffer(guid.data(), guid.size());
  return key;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char> &key,
                                       const std::vector<unsigned char> &data) {
  std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
  unsigned int out_len = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
           data.size(), out.data(), &out_len) == nullptr) {
    wipe_vector(out);
    throw std::runtime_error("HMAC-SHA256 failed");
  }
  return out;
}

fs::path machine_secret_path() {
  wchar_t buf[MAX_PATH]{};
  const DWORD n = GetEnvironmentVariableW(L"PROGRAMDATA", buf, MAX_PATH);
  const std::wstring root =
      (n > 0 && n < MAX_PATH) ? std::wstring(buf) : std::wstring(L"C:\\ProgramData");
  return fs::path(root) / L"SBM" / L"crypto" / L"machine_secret.dpapi";
}

std::vector<unsigned char> load_or_create_machine_secret() {
  const fs::path path = machine_secret_path();
  std::error_code ec;

  if (fs::exists(path, ec) && !ec) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
      throw std::runtime_error(
          "Failed to open DPAPI machine secret file: " + path.string());
    }
    std::vector<unsigned char> blob((std::istreambuf_iterator<char>(ifs)),
                                    std::istreambuf_iterator<char>());
    if (blob.empty()) {
      throw std::runtime_error("DPAPI machine secret file is empty: " +
                               path.string());
    }

    if (auto plain =
            try_unprotect_dpapi_bytes(blob, CRYPT_PROTECT_LOCAL_MACHINE)) {
      wipe_vector(blob);
      return *plain;
    }
    if (auto plain = try_unprotect_dpapi_bytes(blob, 0)) {
      wipe_vector(blob);
      return *plain;
    }
    wipe_vector(blob);
    throw std::runtime_error(
        "Failed to unprotect DPAPI machine secret at " + path.string() +
        ". Delete the file on this machine to regenerate (will invalidate "
        "credentials encrypted after 1.2610.191.14).");
  }

  std::vector<unsigned char> secret(KEY_SIZE);
  if (1 != RAND_bytes(secret.data(), static_cast<int>(secret.size()))) {
    wipe_vector(secret);
    throw std::runtime_error("RAND_bytes failed while creating machine secret");
  }

  std::vector<unsigned char> blob =
      protect_dpapi_bytes(secret, CRYPT_PROTECT_LOCAL_MACHINE);

  fs::create_directories(path.parent_path(), ec);
  if (ec) {
    wipe_vector(secret);
    wipe_vector(blob);
    throw std::runtime_error(
        "Failed to create directory for machine secret: " +
        path.parent_path().string() + " ec=" + std::to_string(ec.value()));
  }

  {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
      wipe_vector(secret);
      wipe_vector(blob);
      throw std::runtime_error(
          "Failed to write DPAPI machine secret file: " + path.string());
    }
    ofs.write(reinterpret_cast<const char *>(blob.data()),
              static_cast<std::streamsize>(blob.size()));
    if (!ofs) {
      wipe_vector(secret);
      wipe_vector(blob);
      throw std::runtime_error(
          "Failed while writing DPAPI machine secret file: " + path.string());
    }
  }
  wipe_vector(blob);
  return secret;
}

std::string decrypt_aes_with_key(const std::string &encrypted_format,
                                 const std::vector<unsigned char> &key) {
  if (encrypted_format.rfind(k_gcm_prefix, 0) == 0) {
    return decrypt_gcm(encrypted_format, key);
  }
  return decrypt_cbc_legacy(encrypted_format, key);
}

} // namespace

void secure_zero_memory(void *ptr, const size_t size) {
  wipe_buffer(ptr, size);
}

secure_string::secure_string(std::string s) : data_(std::move(s)) {}

secure_string::~secure_string() {
  if (!data_.empty()) {
    secure_zero_memory(&data_[0], data_.size());
  }
}

secure_string::secure_string(secure_string &&other) noexcept
    : data_(std::move(other.data_)) {}

secure_string &secure_string::operator=(secure_string &&other) noexcept {
  if (this != &other) {
    if (!data_.empty()) {
      secure_zero_memory(&data_[0], data_.size());
    }
    data_ = std::move(other.data_);
  }
  return *this;
}

secure_wstring::secure_wstring(std::wstring s) : data_(std::move(s)) {}

secure_wstring::~secure_wstring() {
  if (!data_.empty()) {
    secure_zero_memory(&data_[0], data_.size() * sizeof(wchar_t));
  }
}

secure_wstring::secure_wstring(secure_wstring &&other) noexcept
    : data_(std::move(other.data_)) {}

secure_wstring &secure_wstring::operator=(secure_wstring &&other) noexcept {
  if (this != &other) {
    if (!data_.empty()) {
      secure_zero_memory(&data_[0], data_.size() * sizeof(wchar_t));
    }
    data_ = std::move(other.data_);
  }
  return *this;
}

secure_wstring &secure_wstring::append(const std::wstring_view sv) {
  data_.append(sv);
  return *this;
}

secure_wstring &secure_wstring::append(const wchar_t *p) {
  if (p) {
    data_.append(p);
  }
  return *this;
}

secure_wstring &secure_wstring::append(const wchar_t c) {
  data_.push_back(c);
  return *this;
}

void secure_wstring::clear() {
  if (!data_.empty()) {
    secure_zero_memory(&data_[0], data_.size() * sizeof(wchar_t));
  }
  data_.clear();
}

std::vector<unsigned char> derive_machine_key() {
  // Strengthened key (1.2610.191.14+):
  //   AES-256 key = HMAC-SHA256(DPAPI LocalMachine secret, MachineGuid_utf8)
  // Secret file: %PROGRAMDATA%\SBM\crypto\machine_secret.dpapi
  // Older blobs remain decryptable via SHA256(MachineGuid) fallback in
  // decrypt_string().
  const std::wstring guid_w = read_machine_guid_w();
  std::string guid_utf8 = wide_to_utf8(guid_w);
  std::vector<unsigned char> guid_bytes(guid_utf8.begin(), guid_utf8.end());
  wipe_buffer(guid_utf8.data(), guid_utf8.size());

  std::vector<unsigned char> secret = load_or_create_machine_secret();
  std::vector<unsigned char> key = hmac_sha256(secret, guid_bytes);
  wipe_vector(secret);
  wipe_vector(guid_bytes);

  if (key.size() != KEY_SIZE) {
    wipe_vector(key);
    throw std::runtime_error("derive_machine_key: unexpected HMAC length");
  }
  return key;
}

std::string encrypt_string(const std::string &plaintext,
                           const std::vector<unsigned char> &key) {
  if (key.size() != KEY_SIZE) {
    throw std::invalid_argument("Key size must be 32 bytes (256 bits)");
  }

  constexpr int IV_LEN = static_cast<int>(AES_GCM_IV_BYTES);
  constexpr int TAG_LEN = static_cast<int>(AES_GCM_TAG_BYTES);

  std::vector<unsigned char> iv(static_cast<size_t>(IV_LEN));
  if (1 != RAND_bytes(iv.data(), IV_LEN)) {
    throw std::runtime_error("RAND_bytes failed");
  }

  auto ctx = make_evp_ctx();

  if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                              nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) ||
      1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
    throw std::runtime_error("EVP_EncryptInit_ex failed: " + get_openssl_error());
  }

  std::vector<unsigned char> ciphertext(plaintext.size() + BLOCK_SIZE);
  int len = 0;
  int ciphertext_len = 0;

  if (!plaintext.empty()) {
    if (1 != EVP_EncryptUpdate(
                 ctx.get(), ciphertext.data(), &len,
                 reinterpret_cast<const unsigned char *>(plaintext.data()),
                 static_cast<int>(plaintext.size()))) {
      throw std::runtime_error("EVP_EncryptUpdate failed: " +
                               get_openssl_error());
    }
    ciphertext_len = len;
  }

  if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len, &len)) {
    throw std::runtime_error("EVP_EncryptFinal_ex failed: " +
                             get_openssl_error());
  }
  ciphertext_len += len;
  ciphertext.resize(static_cast<size_t>(ciphertext_len));

  std::vector<unsigned char> tag(static_cast<size_t>(TAG_LEN));
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data())) {
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl(GET_TAG) failed");
  }
  ctx.reset();

  return std::string(k_gcm_prefix) + to_hex(iv.data(), iv.size()) + ":" +
         to_hex(tag.data(), tag.size()) + ":" +
         to_hex(ciphertext.data(), ciphertext.size());
}

std::string decrypt_string(const std::string &encrypted_format,
                           const std::vector<unsigned char> &key) {
  if (key.size() != KEY_SIZE) {
    throw std::invalid_argument("Key size must be 32 bytes (256 bits)");
  }

  // Legacy Watchdog DPAPI hex blob (no colon / no gcm: prefix).
  if (encrypted_format.rfind(k_gcm_prefix, 0) != 0 &&
      encrypted_format.find(':') == std::string::npos) {
    return decrypt_dpapi_legacy(encrypted_format);
  }

  try {
    return decrypt_aes_with_key(encrypted_format, key);
  } catch (const std::exception &) {
    // Fall back to pre-1.2610.191.14 SHA256(MachineGuid) key so hosts with
    // existing ENCRYPTED sql_connection.json keep working after upgrade.
    std::vector<unsigned char> legacy = derive_machine_key_legacy_sha256_guid();
    try {
      std::string plain = decrypt_aes_with_key(encrypted_format, legacy);
      wipe_vector(legacy);
      return plain;
    } catch (...) {
      wipe_vector(legacy);
      throw;
    }
  }
}

} // namespace sbm::security
