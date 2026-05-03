// AWSP -- A2A Webhook Security Profile reference implementation.

namespace YawLabs.Awsp;

/// <summary>
/// The four headers produced by <see cref="Awsp.Sign"/>. All values are strings, suitable for
/// attaching to an outgoing HTTP request.
/// </summary>
/// <param name="XA2ASignature">Value of the <c>X-A2A-Signature</c> header.</param>
/// <param name="XA2AWebhookId">Value of the <c>X-A2A-Webhook-Id</c> header.</param>
/// <param name="XA2AEventType">Value of the <c>X-A2A-Event-Type</c> header.</param>
/// <param name="XA2ATimestamp">Value of the <c>X-A2A-Timestamp</c> header (decimal unix seconds).</param>
public sealed record SignedHeaders(
    string XA2ASignature,
    string XA2AWebhookId,
    string XA2AEventType,
    string XA2ATimestamp);
