#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using Byte  = uint8_t;
using Block = std::array<Byte,16>;   // 4x4 state (column-major)

// AES-128 constants
static constexpr int Nb = 4;   // block columns
static constexpr int Nk = 4;   // key words (4*4 = 16 bytes)
static constexpr int Nr = 10;  // rounds

// S-box
static const Byte sbox[256] = {
  // 0x00 .. 0x0F
  0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
  // 0x10 .. 0x1F
  0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
  // 0x20 .. 0x2F
  0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
  // 0x30 .. 0x3F
  0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
  // 0x40 .. 0x4F
  0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
  // 0x50 .. 0x5F
  0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
  // 0x60 .. 0x6F
  0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
  // 0x70 .. 0x7F
  0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
  // 0x80 .. 0x8F
  0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
  // 0x90 .. 0x9F
  0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
  // 0xA0 .. 0xAF
  0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
  // 0xB0 .. 0xBF
  0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
  // 0xC0 .. 0xCF
  0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
  // 0xD0 .. 0xDF
  0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
  // 0xE0 .. 0xEF
  0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
  // 0xF0 .. 0xFF
  0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

// Rcon (only first 10 used for AES-128)
static const Byte Rcon[11] = {
  0x00, // unused (round 0)
  0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// ---------- Helpers ----------

static inline Byte xtime(Byte x) {
  return (Byte)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static inline Byte gf_mul(Byte a, Byte b) {
  // multiply in GF(2^8) with AES poly 0x11B
  Byte r = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) r ^= a;
    bool hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return r;
}

// Print state as 4x4 matrix (bytes in hex), column-major
static void print_state(const char* label, const Block& s) {
  std::cout << label << "\n";
  for (int r = 0; r < 4; ++r) {
    std::cout << "  ";
    for (int c = 0; c < 4; ++c) {
      Byte v = s[c*4 + r]; // column-major
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)v << " ";
    }
    std::cout << std::dec << "\n";
  }
}

// ---------- Core AES transforms on the 4x4 state ----------

static void SubBytes(Block& s) {
  for (auto& b : s) b = sbox[b];
}

static void ShiftRows(Block& s) {
  // state is column-major: s[c*4 + r]
  // Row 0: no shift
  // Row 1: shift left by 1
  // Row 2: shift left by 2
  // Row 3: shift left by 3
  // Implement by extracting rows and rotating
  for (int r = 1; r <= 3; ++r) {
    Byte row[4];
    for (int c = 0; c < 4; ++c) row[c] = s[c*4 + r];
    // rotate left by r
    Byte tmp[4];
    for (int c = 0; c < 4; ++c) tmp[c] = row[(c + r) & 3];
    for (int c = 0; c < 4; ++c) s[c*4 + r] = tmp[c];
  }
}

static void MixColumns(Block& s) {
  // multiply each column by fixed matrix:
  // [02 03 01 01; 01 02 03 01; 01 01 02 03; 03 01 01 02]
  for (int c = 0; c < 4; ++c) {
    Byte s0 = s[c*4 + 0];
    Byte s1 = s[c*4 + 1];
    Byte s2 = s[c*4 + 2];
    Byte s3 = s[c*4 + 3];
    Byte r0 = (Byte)(gf_mul(0x02,s0) ^ gf_mul(0x03,s1) ^ s2 ^ s3);
    Byte r1 = (Byte)(s0 ^ gf_mul(0x02,s1) ^ gf_mul(0x03,s2) ^ s3);
    Byte r2 = (Byte)(s0 ^ s1 ^ gf_mul(0x02,s2) ^ gf_mul(0x03,s3));
    Byte r3 = (Byte)(gf_mul(0x03,s0) ^ s1 ^ s2 ^ gf_mul(0x02,s3));
    s[c*4 + 0] = r0;
    s[c*4 + 1] = r1;
    s[c*4 + 2] = r2;
    s[c*4 + 3] = r3;
  }
}

static void AddRoundKey(Block& s, const Byte* roundKey) {
  // roundKey is 16 bytes for each round
  for (int i = 0; i < 16; ++i) s[i] ^= roundKey[i];
}

// ---------- Key expansion (AES-128) ----------

static void RotWord(Byte w[4]) {
  Byte t = w[0]; w[0]=w[1]; w[1]=w[2]; w[2]=w[3]; w[3]=t;
}
static void SubWord(Byte w[4]) {
  for (int i=0;i<4;++i) w[i] = sbox[w[i]];
}

static std::array<Byte, Nb*(Nr+1)*4> KeyExpansion(const Byte key[16]) {
  // output 176 bytes (11 round keys * 16 bytes)
  std::array<Byte, Nb*(Nr+1)*4> w{}; // 176
  // first Nk words = key
  for (int i = 0; i < 16; ++i) w[i] = key[i];

  int bytesGenerated = 16;
  int rconIter = 1;
  Byte temp[4];

  while (bytesGenerated < (Nb*(Nr+1)*4)) {
    // last 4 bytes as temp
    for (int i=0;i<4;++i) temp[i] = w[bytesGenerated - 4 + i];

    if ((bytesGenerated % 16) == 0) {
      RotWord(temp);
      SubWord(temp);
      temp[0] ^= Rcon[rconIter++];
    }

    for (int i=0;i<4;++i) {
      w[bytesGenerated] = (Byte)(w[bytesGenerated - 16] ^ temp[i]);
      ++bytesGenerated;
    }
  }
  return w;
}

// ---------- Utility: parse hex string (32 hex chars => 16 bytes) ----------

static bool parse_hex_16(const std::string& hex, Byte out[16]) {
  if (hex.size() != 32) return false;
  auto hexval = [](char c)->int{
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return 10 + (c-'a');
    if ('A'<=c && c<='F') return 10 + (c-'A');
    return -1;
  };
  for (int i=0;i<16;++i) {
    int hi = hexval(hex[2*i]);
    int lo = hexval(hex[2*i+1]);
    if (hi<0 || lo<0) return false;
    out[i] = (Byte)((hi<<4) | lo);
  }
  return true;
}

static std::string to_hex(const Byte* b, size_t n) {
  std::ostringstream oss;
  for (size_t i=0;i<n;++i) {
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)b[i];
  }
  return oss.str();
}

// ---------- AES-128 block encrypt with verbose logging ----------

static Block AES128_Encrypt_Block_Verbose(const Block& in, const Byte key[16]) {
  auto roundKeys = KeyExpansion(key);

  Block state = in;

  print_state("Initial State:", state);
  AddRoundKey(state, &roundKeys[0]);
  print_state("Round 0 - AddRoundKey:", state);

  // Rounds 1..Nr-1
  for (int round = 1; round < Nr; ++round) {
    SubBytes(state);
    print_state(("Round " + std::to_string(round) + " - SubBytes:").c_str(), state);

    ShiftRows(state);
    print_state(("Round " + std::to_string(round) + " - ShiftRows:").c_str(), state);

    MixColumns(state);
    print_state(("Round " + std::to_string(round) + " - MixColumns:").c_str(), state);

    AddRoundKey(state, &roundKeys[round*16]);
    print_state(("Round " + std::to_string(round) + " - AddRoundKey:").c_str(), state);
  }

  // Final round (no MixColumns)
  SubBytes(state);
  print_state(("Round " + std::to_string(Nr) + " - SubBytes:").c_str(), state);

  ShiftRows(state);
  print_state(("Round " + std::to_string(Nr) + " - ShiftRows:").c_str(), state);

  AddRoundKey(state, &roundKeys[Nr*16]);
  print_state(("Round " + std::to_string(Nr) + " - AddRoundKey (final):").c_str(), state);

  return state;
}

// Load a 16-byte block from bytes (column-major by AES spec)
static Block load_block_from_bytes(const Byte b[16]) {
  Block out;
  for (int i=0;i<16;++i) out[i] = b[i];
  return out;
}

int main(int argc, char** argv) {
  // Example from FIPS-197 (classic):
  // key:     000102030405060708090a0b0c0d0e0f
  // plaintext:00112233445566778899aabbccddeeff
  // ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a

  Byte key[16];
  Byte pt[16];

  std::string keyHex = (argc > 1) ? argv[1] : "000102030405060708090a0b0c0d0e0f";
  std::string ptHex  = (argc > 2) ? argv[2] : "00112233445566778899aabbccddeeff";

  if (!parse_hex_16(keyHex, key) || !parse_hex_16(ptHex, pt)) {
    std::cerr << "Usage: " << argv[0] << " <32-hex-key> <32-hex-plaintext>\n";
    return 1;
  }

  Block in  = load_block_from_bytes(pt);
  Block out = AES128_Encrypt_Block_Verbose(in, key);

  std::cout << "Ciphertext: " << to_hex(out.data(), out.size()) << "\n";
  return 0;
}
