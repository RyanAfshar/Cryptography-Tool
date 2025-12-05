#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits>

using namespace std;

// ---- Helpers ---------------------------------------------------------------

// Return true if c is printable ASCII we want to transform (space..~)
static inline bool isPrintable(char c) {
    return c >= 32 && c <= 126;
}

// Map printable ASCII to [0,94] and back, preserving others
static inline char shiftPrintable(char c, int shift) {
    if (!isPrintable(c)) return c;
    int idx = c - 32;                  // [0..94]
    int out = (idx + shift) % 95;      // wrap in 95 symbols
    if (out < 0) out += 95;
    return static_cast<char>(out + 32);
}

// Rotate a vector segment right by r (r may be > len)
template <typename T>
void rotateRight(vector<T>& v, size_t start, size_t len, size_t r) {
    if (len == 0) return;
    r %= len;
    if (r == 0) return;
    // 3-reverse trick
    auto rev = [&](size_t a, size_t b){
        while (a < b) swap(v[a++], v[b--]);
    };
    rev(start, start + len - 1);
    rev(start, start + r - 1);
    rev(start + r, start + len - 1);
}

// ---- Core algorithm --------------------------------------------------------
// Step A: Keyed printable-ASCII substitution (Vigenère-style).
// shift_i = ( key[i % k].byte + i ) % 95  (keeps strong diffusion while printable)
string subst_encrypt(const string& plain, const string& key) {
    string out = plain;
    const size_t k = key.size();
    for (size_t i = 0; i < out.size(); ++i) {
        int ks = static_cast<unsigned char>(key[i % k]);
        int shift = (ks + static_cast<int>(i)) % 95;
        out[i] = shiftPrintable(out[i], shift);
    }
    return out;
}

string subst_decrypt(const string& cipher, const string& key) {
    string out = cipher;
    const size_t k = key.size();
    for (size_t i = 0; i < out.size(); ++i) {
        int ks = static_cast<unsigned char>(key[i % k]);
        int shift = (ks + static_cast<int>(i)) % 95;
        out[i] = shiftPrintable(out[i], -shift);
    }
    return out;
}

// Step B: Lightweight block transposition derived from key.
// Block size b = (|key| % 7) + 3  in [3..9]
// r = (sum(key bytes) % b)
// For block j: if j even -> reverse; if j odd -> rotate right by r
string transpose_encrypt(const string& s, const string& key) {
    if (s.empty()) return s;
    size_t b = (key.size() % 7) + 3;
    size_t r = 0;
    for (unsigned char c : key) r += c;
    r %= b;

    vector<char> v(s.begin(), s.end());
    size_t nBlocks = (v.size() + b - 1) / b;
    for (size_t j = 0; j < nBlocks; ++j) {
        size_t start = j * b;
        size_t len = min(b, v.size() - start);
        if (j % 2 == 0) { // reverse block
            size_t a = start, bnd = start + len - 1;
            while (a < bnd) swap(v[a++], v[bnd--]);
        } else {          // rotate right by r
            rotateRight(v, start, len, r);
        }
    }
    return string(v.begin(), v.end());
}

string transpose_decrypt(const string& s, const string& key) {
    if (s.empty()) return s;
    size_t b = (key.size() % 7) + 3;
    size_t r = 0;
    for (unsigned char c : key) r += c;
    r %= b;

    vector<char> v(s.begin(), s.end());
    size_t nBlocks = (v.size() + b - 1) / b;
    for (size_t j = 0; j < nBlocks; ++j) {
        size_t start = j * b;
        size_t len = min(b, v.size() - start);
        if (j % 2 == 0) { // reverse is its own inverse
            size_t a = start, bnd = start + len - 1;
            while (a < bnd) swap(v[a++], v[bnd--]);
        } else {          // inverse of rotate-right(r) is rotate-left(r)
            // rotate-left by r = rotate-right(len - (r % len))
            if (len > 0) rotateRight(v, start, len, len - (r % len));
        }
    }
    return string(v.begin(), v.end());
}

// Full pipeline
string encrypt_string(const string& plaintext, const string& key) {
    return transpose_encrypt(subst_encrypt(plaintext, key), key);
}

string decrypt_string(const string& ciphertext, const string& key) {
    return subst_decrypt(transpose_decrypt(ciphertext, key), key);
}

// ---- File I/O --------------------------------------------------------------
bool processFile(const string& inName, const string& outName,
                 const string& key, bool doEncrypt) {
    if (inName == outName) {
        cerr << "Input and output file names must differ.\n";
        return false;
    }
    if (key.empty()) {
        cerr << "Key must not be empty.\n";
        return false;
    }
    ifstream in(inName, ios::in);
    if (!in) {
        cerr << "Failed to open input file: " << inName << "\n";
        return false;
    }
    ofstream out(outName, ios::out | ios::trunc);
    if (!out) {
        cerr << "Failed to create output file: " << outName << "\n";
        return false;
    }

    string line;
    while (getline(in, line)) {
        string x = doEncrypt ? encrypt_string(line, key)
                             : decrypt_string(line, key);
        out << x << '\n';
    }
    return true;
}

// ---- Simple menu UI --------------------------------------------------------
int main() {
    cout << "=== Simple File Encrypt/Decrypt ===\n";
    cout << "1) Encrypt a file\n";
    cout << "2) Decrypt a file\n";
    cout << "Choose: ";

    int choice = 0;
    if (!(cin >> choice)) return 0;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    string inFile, outFile, key;
    cout << "Enter input file name: ";
    getline(cin, inFile);
    cout << "Enter output file name: ";
    getline(cin, outFile);
    cout << "Enter key (string): ";
    getline(cin, key);

    bool ok = false;
    if (choice == 1) {
        ok = processFile(inFile, outFile, key, true);
    } else if (choice == 2) {
        ok = processFile(inFile, outFile, key, false);
    } else {
        cerr << "Invalid choice.\n";
        return 1;
    }

    if (ok) cout << "Done.\n";
    else    cout << "Failed.\n";
    return ok ? 0 : 1;
}