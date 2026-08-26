import '../utils/device_identity.dart';

/// Builds the `MediaBrowser` Authorization header value understood by both
/// Jellyfin and Emby. Field values only percent-encode what the header cannot
/// carry verbatim — quotes, commas, `%`, and anything outside printable ASCII
/// — and the server reverses that encoding while parsing the header. Spaces
/// and other printable ASCII stay raw: official clients send them verbatim
/// (e.g. `Client="Emby for iOS"`), and allowlisting gateways in front of Emby
/// servers string-match the raw value, so `Emby%20for%20iOS` would be rejected
/// as an unknown client.
///
/// Encoding non-ASCII is what keeps the header sendable at all. A device name
/// like `Bjørn PC` cannot travel verbatim: `dart:io` rejects header values
/// above 0x7F outright, and CFNetwork puts the raw code unit on the wire as a
/// Latin-1 byte, which the server rejects as a malformed header before the
/// request is routed. Encoding also removes the grammar hazards the header
/// has no escape for: quotes, commas, and `=` inside a value.
///
/// Both dialects require non-empty client, device, and version fields when
/// creating a session, so those values use stable fallbacks. An empty device
/// ID is omitted for authenticated requests, where the server can recover it
/// from the token; unauthenticated entry points must call
/// [requireJellyfinDeviceId].
String buildJellyfinAuthHeader({
  required String clientName,
  required String clientVersion,
  required String deviceName,
  required String deviceId,
  String? accessToken,
}) {
  String field(String name, String value) => '$name="${_escapeFieldValue(value)}"';

  final client = _meaningful(clientName);
  final effectiveClient = client.isEmpty ? 'Plezy' : client;
  final device = _meaningful(deviceName);
  final version = _meaningful(clientVersion);
  final id = _meaningful(deviceId);
  final token = _meaningful(accessToken ?? '');

  final parts = <String>[
    field('Client', effectiveClient),
    field('Device', device.isEmpty ? effectiveClient : device),
    if (id.isNotEmpty) field('DeviceId', id),
    field('Version', version.isEmpty ? '1.0' : version),
    if (token.isNotEmpty) field('Token', token),
  ];
  return 'MediaBrowser ${parts.join(', ')}';
}

final RegExp _controlCharacters = RegExp(r'[\x00-\x1f\x7f-\x9f]');

/// Escape only the characters the quoted-field grammar or the transport layer
/// cannot carry; everything else (notably spaces) goes verbatim.
String _escapeFieldValue(String value) {
  const escapes = {0x22 /* " */, 0x25 /* % */, 0x2c /* , */, 0x3d /* = */};
  final buffer = StringBuffer();
  for (final rune in value.runes) {
    final mustEscape = escapes.contains(rune) || rune < 0x20 || rune > 0x7e;
    buffer.write(mustEscape ? Uri.encodeComponent(String.fromCharCode(rune)) : String.fromCharCode(rune));
  }
  return buffer.toString();
}

/// Percent-encoding makes any byte transportable, so the only values worth
/// filtering are the ones that carry no identity at all — a name of control
/// characters would otherwise reach the server's device list as `%00` noise
/// instead of falling back to a readable label.
String _meaningful(String value) => value.replaceAll(_controlCharacters, '').trim();

/// Validates the stable device identity required by unauthenticated
/// MediaBrowser session creation. Never substitute a placeholder: both
/// dialects key sessions and access tokens by this value, so a shared fallback
/// would collide across installations.
String requireJellyfinDeviceId(String deviceId) {
  final sanitized = sanitizeHeaderValue(deviceId);
  if (sanitized == null || sanitized != deviceId || sanitized.contains('"')) {
    throw ArgumentError.value(deviceId, 'deviceId', 'must be a non-empty HTTP-safe value');
  }
  return sanitized;
}
