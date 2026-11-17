#pragma once

// TDS wire framing for one direction of a connection, and PRELOGIN parsing.
// No Envoy dependency, so it can be unit-tested on its own.
//
// What travels on a TDS 7.x connection, told apart by the first byte of each unit:
// - raw TLS records (content type 0x14-0x17): after the TLS handshake, when
//   encryption is on, and for LOGIN7 under login-only encryption. No TDS packet
//   type uses these values.
// - MARS SMP packets (0x53), only once MARS has been negotiated.
// - TDS packets (anything else): 8-byte header, length includes the header.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace MssqlProxy {

// TDS packet types (MS-TDS 2.2.3.1.1).
inline constexpr uint8_t kTdsSqlBatch = 0x01;
inline constexpr uint8_t kTdsRpc = 0x03;
inline constexpr uint8_t kTdsTabularResult = 0x04;
inline constexpr uint8_t kTdsAttention = 0x06;
inline constexpr uint8_t kTdsBulkLoad = 0x07;
inline constexpr uint8_t kTdsFedAuthToken = 0x08;
inline constexpr uint8_t kTdsTransactionManager = 0x0e;
inline constexpr uint8_t kTdsLogin7 = 0x10;
inline constexpr uint8_t kTdsSspi = 0x11;
inline constexpr uint8_t kTdsPrelogin = 0x12;

inline constexpr uint8_t kTdsStatusEom = 0x01;

inline constexpr size_t kTdsHeaderSize = 8;
// Largest packet size a client can negotiate (MS-TDS 2.2.6.4, PacketSize).
inline constexpr size_t kTdsMaxPacketSize = 32767;

inline constexpr size_t kTlsHeaderSize = 5;
// TLSCiphertext.length may not exceed 2^14 + 2048 (RFC 5246 6.2.3).
inline constexpr size_t kTlsMaxRecordPayload = (1 << 14) + 2048;

inline constexpr uint8_t kSmpId = 0x53;
inline constexpr size_t kSmpHeaderSize = 16;

enum class UnitKind { TdsPacket, TlsRecord, SmpPacket };

const char* unitKindName(UnitKind kind);

// One complete unit, viewing bytes owned by the splitter; valid only during the
// callback that receives it.
struct Unit {
  UnitKind kind;
  // TDS: packet type; TLS: content type; SMP: SMP flags.
  uint8_t type;
  // TDS only: status has the EOM bit set.
  bool eom;
  // Header and payload together, exactly as on the wire.
  std::string_view bytes;
  std::string_view payload() const;
};

class UnitSink {
public:
  virtual ~UnitSink() = default;
  // Returns an error message to stop splitting, or nullopt to continue.
  virtual std::optional<std::string> onUnit(const Unit& unit) = 0;
};

// Splits one direction's byte stream into units, across arbitrary read
// boundaries. Buffers at most one incomplete unit.
class StreamSplitter {
public:
  // SMP packets are only recognised after MARS has been negotiated; before
  // that 0x53 is just an unknown TDS packet type.
  void setMarsEnabled(bool enabled) { mars_enabled_ = enabled; }

  // Largest TDS packet accepted: the TDS maximum until the login negotiates a
  // packet size. SMP packets may carry one TDS packet plus their own header.
  void setMaxTdsPacketSize(size_t size) { max_tds_packet_ = size; }

  // Feeds the next bytes. Calls sink.onUnit for every unit completed by them.
  // Returns an error message on malformed framing or when the sink stops; the
  // splitter is then unusable.
  std::optional<std::string> feed(std::string_view data, UnitSink& sink);

  size_t bufferedBytes() const { return buffer_.size(); }

private:
  std::string buffer_;
  bool mars_enabled_ = false;
  size_t max_tds_packet_ = kTdsMaxPacketSize;
  bool failed_ = false;
};

enum class PreloginEncryption : uint8_t {
  Off = 0x00,
  On = 0x01,
  NotSupported = 0x02,
  Required = 0x03,
};

struct PreloginOptions {
  // ENCRYPTION option with the client-certificate bit (0x80) masked off.
  std::optional<PreloginEncryption> encryption;
  // The client-certificate bit was set (client asks to authenticate with a
  // certificate in the TLS handshake).
  bool client_cert = false;
  // Where the ENCRYPTION byte sits in the payload, for rewriting it in place.
  std::optional<size_t> encryption_offset;
  // INSTOPT: the instance name (client), or 0x00 valid / 0x01 rejected (server).
  std::optional<std::string> instance;
  bool thread_id = false;                  // THREADID present.
  std::optional<uint8_t> fedauth_required; // FEDAUTHREQUIRED.
  bool nonce = false;                      // NONCEOPT present (federated authentication).
  // MARS option: 1 when requested (client) or accepted (server).
  std::optional<bool> mars;
};

// Parses a PRELOGIN message payload (all packets of the message concatenated,
// headers removed). Every offset and length is bounds-checked.
// Returns nullopt and sets error on malformed input.
std::optional<PreloginOptions> parsePrelogin(std::string_view payload, std::string& error);

// A PRELOGIN response payload answering client: VERSION (version, 6 bytes),
// ENCRYPTION, and INSTOPT (valid), THREADID (empty) and MARS (as requested)
// when the client sent them.
std::string buildPreloginResponse(const PreloginOptions& client, PreloginEncryption encryption,
                                  std::string_view version);

// Builds a TDS message from a payload: packets of at most max_packet bytes
// (header included), packet IDs from 1, EOM on the last packet. spid: the
// header's SPID (big-endian on the wire), which servers set and clients 0.
std::string makeTdsMessage(uint8_t type, std::string_view payload, size_t max_packet,
                           uint16_t spid = 0);

// Smallest and largest packet size a login can negotiate (MS-TDS 2.2.6.4).
inline constexpr uint32_t kTdsMinPacketSize = 512;

// What a scan of one server message during login found.
struct LoginResponseScan {
  bool login_ack = false;              // LOGINACK token present: login succeeded.
  std::optional<uint32_t> packet_size; // From ENVCHANGE type 4 (packet size).
  std::optional<uint32_t> error;       // Number of the first ERROR token, e.g. 18456.
  std::optional<std::string> sspi;     // SSPI token data: the server's next auth token.
  // Every SSPI token's place in the payload: (offset, size), token type and
  // length included.
  std::vector<std::pair<size_t, size_t>> sspi_tokens;
  bool fully_scanned = false; // False when an unknown token stopped the scan.
};

// An SSPI token (0xED, USHORT length, data); data must fit 64 KB.
std::string sspiToken(std::string_view data);

// The server message payload with its SSPI tokens (as scan found them)
// replaced by one carrying replacement, or removed when it's empty. With no
// SSPI token there, a non-empty replacement goes first.
std::string replaceSspiTokens(std::string_view payload, const LoginResponseScan& scan,
                              std::string_view replacement);

// An ERROR token (number, state, class, message; ServerName, ProcName empty)
// followed by DONE with the error bit: what SQL Server sends for a refused
// login. A TDS 7.2+ layout (8-byte DONE row count, 4-byte line number).
std::string buildLoginError(uint32_t number, uint8_t state, uint8_t severity,
                            std::string_view message_utf8);

// UTF-8 to UTF-16LE; invalid bytes become U+FFFD.
std::string utf8ToUtf16le(std::string_view utf8);

// Walks the tokens of a server message (TDS type 0x04 payload) sent during
// login: SSPI, ERROR, INFO, LOGINACK, ENVCHANGE, FEATUREEXTACK, SESSIONSTATE,
// FEDAUTHINFO, RETURNSTATUS and DONE tokens. Stops quietly at any other token,
// since token lengths can't be derived generically. Returns nullopt and sets
// error when a known token is malformed.
std::optional<LoginResponseScan> scanLoginResponse(std::string_view payload, std::string& error);

} // namespace MssqlProxy
