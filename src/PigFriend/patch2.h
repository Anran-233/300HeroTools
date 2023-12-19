#ifndef PATCH2_H
#define PATCH2_H

namespace Patch2 {
class cstring {
    char *m_data;
    int m_len;
public:
    cstring() = delete;
    cstring(const int &len) : m_data(new char[len + 1]{0}), m_len(len){}
    cstring(const cstring &other) : m_data(new char[other.m_len + 1]{0}), m_len(other.m_len){}
    cstring(cstring &&other) : m_data(other.m_data), m_len(other.m_len) { other.m_data = nullptr; }
    ~cstring() { if (m_data) delete[] m_data; }
    const char *toString() const { return m_data; }
};
/// 加密补丁信息(返回:密文)(plaintext 明文)
cstring encrypt(const char *plaintext);
/// 解密补丁信息(返回:明文)(ciphertext 密文)
cstring decrypt(const char *ciphertext);
}

#endif  // PATCH2_H
