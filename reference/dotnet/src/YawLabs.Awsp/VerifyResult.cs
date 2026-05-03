// AWSP -- A2A Webhook Security Profile reference implementation.

namespace YawLabs.Awsp;

/// <summary>
/// Result of <see cref="Awsp.Verify"/>.
/// <para>
/// On success, <see cref="Ok"/> is <c>true</c> and <see cref="Reason"/> is <c>null</c>.
/// On failure, <see cref="Ok"/> is <c>false</c> and <see cref="Reason"/> carries one of the
/// stable enum values defined by SPEC.md section 9:
/// </para>
/// <list type="bullet">
///   <item><description><c>malformed_header</c></description></item>
///   <item><description><c>unknown_algorithm</c></description></item>
///   <item><description><c>stale</c></description></item>
///   <item><description><c>future</c></description></item>
///   <item><description><c>replayed</c></description></item>
///   <item><description><c>unknown_kid</c></description></item>
///   <item><description><c>bad_hmac</c></description></item>
/// </list>
/// </summary>
/// <param name="Ok">True if verification succeeded.</param>
/// <param name="Reason">
/// Stable error enum on failure; <c>null</c> on success. Receivers MAY return this in
/// <c>{"error":"invalid_signature","reason":...}</c> JSON bodies but MUST NOT return any
/// free-form diagnostic.
/// </param>
public sealed record VerifyResult(bool Ok, string? Reason);
