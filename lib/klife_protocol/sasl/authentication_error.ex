defmodule KlifeProtocol.SASL.AuthenticationError do
  @moduledoc """
  Raised when the broker refuses the credentials during SASL authentication.

  `error_code` is the Kafka error code of the `SaslAuthenticate` response (58,
  `SASL_AUTHENTICATION_FAILED`, for refused credentials) and `error_message` the
  broker's explanation: the RFC 7628 error JSON for a refused `OAUTHBEARER` token.
  Other failures during authentication, such as a closed socket, raise other errors,
  so callers can tell refused credentials from network problems.
  """

  defexception [:mechanism, :error_code, :error_message, :message]
end
