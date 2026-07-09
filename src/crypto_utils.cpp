#include "sbm/crypto_utils.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace sbm::security {
namespace {

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
  LocalFree(output.pbData);
  return plaintext;
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

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                              iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  std::vector<unsigned char> plaintext(ciphertext.size() + BLOCK_SIZE);
  int len = 0;
  int plaintext_len = 0;

  if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                             static_cast<int>(ciphertext.size()))) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error(
        "Decryption failed (CBC padding check failed). Ensure this is the "
        "same machine where encryption occurred.");
  }
  plaintext_len += len;
  plaintext.resize(static_cast<size_t>(plaintext_len));
  EVP_CIPHER_CTX_free(ctx);

  return std::string(plaintext.begin(), plaintext.end());
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

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                              nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) ||
      1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex (GCM) failed");
  }

  std::vector<unsigned char> plaintext(ciphertext.size() + BLOCK_SIZE);
  int len = 0;
  int plaintext_len = 0;

  if (!ciphertext.empty()) {
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                               static_cast<int>(ciphertext.size()))) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_DecryptUpdate (GCM) failed");
    }
    plaintext_len = len;
  }

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                               const_cast<unsigned char *>(tag.data()))) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl(SET_TAG) failed");
  }

  const int rc =
      EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
  EVP_CIPHER_CTX_free(ctx);
  if (rc != 1) {
    throw std::runtime_error(
        "Decryption failed (GCM authentication check failed). The credential "
        "blob was tampered with, or this is not the machine where it was "
        "encrypted.");
  }
  plaintext_len += len;
  plaintext.resize(static_cast<size_t>(plaintext_len));

  return std::string(plaintext.begin(), plaintext.end());
}

std::string decrypt_dpapi_legacy(const std::string &stored) {
  const std::vector<unsigned char> cipher_bytes = from_hex(stored);
#ifndef CRYPT_PROTECT_LOCAL_MACHINE
#define CRYPT_PROTECT_LOCAL_MACHINE 0x00000004
#endif
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

} // namespace

void secure_zero_memory(void *ptr, const size_t size) {
  if (ptr && size > 0) {
    SecureZeroMemory(ptr, size);
  }
}

secure_string::secure_string(std::string s) : data_(std::move(s)) {}

secure_string::~secure_string() {
  if (!data_.empty()) {
    secure_zero_memory(&data_[0], data_.size());
  }
}

secure_string::secure_string(const secure_string &other) : data_(other.data_) {}

secure_string &secure_string::operator=(const secure_string &other) {
  if (this != &other) {
    data_ = other.data_;
  }
  return *this;
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

std::vector<unsigned char> derive_machine_key() {
  wchar_t guid_buf[256]{};
  DWORD buf_size = sizeof(guid_buf);
  const LSTATUS status = RegGetValueW(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
      RRF_RT_REG_SZ, nullptr, guid_buf, &buf_size);

  std::vector<unsigned char> input_material;
  if (status == ERROR_SUCCESS) {
    const std::string guid = wide_to_utf8(std::wstring(guid_buf));
    input_material.assign(guid.begin(), guid.end());
  } else {
    throw std::runtime_error(
        "derive_machine_key: MachineGuid is unavailable "
        "(HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid). Refusing to "
        "derive a weak fallback key. LSTATUS=" +
        std::to_string(status));
  }

  std::vector<unsigned char> key(SHA256_DIGEST_LENGTH);
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }

  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) ||
      1 != EVP_DigestUpdate(mdctx, input_material.data(),
                            input_material.size()) ||
      1 != EVP_DigestFinal_ex(mdctx, key.data(), nullptr)) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("SHA256 calculation failed");
  }
  EVP_MD_CTX_free(mdctx);

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

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                              nullptr) ||
      1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) ||
      1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex (GCM) failed");
  }

  std::vector<unsigned char> ciphertext(plaintext.size() + BLOCK_SIZE);
  int len = 0;
  int ciphertext_len = 0;

  if (!plaintext.empty()) {
    if (1 != EVP_EncryptUpdate(
                 ctx, ciphertext.data(), &len,
                 reinterpret_cast<const unsigned char *>(plaintext.data()),
                 static_cast<int>(plaintext.size()))) {
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;
  }

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed: " +
                             get_openssl_error());
  }
  ciphertext_len += len;
  ciphertext.resize(static_cast<size_t>(ciphertext_len));

  std::vector<unsigned char> tag(static_cast<size_t>(TAG_LEN));
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data())) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl(GET_TAG) failed");
  }
  EVP_CIPHER_CTX_free(ctx);

  return std::string(k_gcm_prefix) + to_hex(iv.data(), iv.size()) + ":" +
         to_hex(tag.data(), tag.size()) + ":" +
         to_hex(ciphertext.data(), ciphertext.size());
}

std::string decrypt_string(const std::string &encrypted_format,
                           const std::vector<unsigned char> &key) {
  if (key.size() != KEY_SIZE) {
    throw std::invalid_argument("Key size must be 32 bytes (256 bits)");
  }

  if (encrypted_format.rfind(k_gcm_prefix, 0) == 0) {
    return decrypt_gcm(encrypted_format, key);
  }
  if (encrypted_format.find(':') != std::string::npos) {
    return decrypt_cbc_legacy(encrypted_format, key);
  }
  return decrypt_dpapi_legacy(encrypted_format);
}

} // namespace sbm::security
