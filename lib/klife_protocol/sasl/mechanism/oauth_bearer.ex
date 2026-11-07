defmodule KlifeProtocol.SASL.Mechanism.OAuthBearer do
  @behaviour KlifeProtocol.SASL.Mechanism.Behaviour

  require Logger

  alias KlifeProtocol.SASL.AuthenticationError

  # RFC 7628 initial client response the way Kafka parses it (KIP-255, extensions KIP-342).
  # Getting the token (OIDC client credentials, caching, refresh) is the caller's job:
  # `token_mfa` is applied on every authentication, so it should hand out a cached token.
  # When the broker refuses the token, the optional `on_rejected_mfa` is applied with the
  # refused token and the broker's error appended to its args, so a cache can drop it:
  # otherwise every new connection would be refused with it until it expires

  @sep <<1>>

  def execute_auth(send_recv_fun, opts) do
    {mod, fun, args} = Keyword.fetch!(opts, :token_mfa)
    extensions = Keyword.get(opts, :extensions, %{})

    token =
      case apply(mod, fun, args) do
        token when is_binary(token) and token != "" ->
          token

        other ->
          raise "OAUTHBEARER token_mfa must return a non-empty binary, got: #{inspect(other)}"
      end

    kvpairs = Enum.map(extensions, fn {key, value} -> [key, "=", value, @sep] end)
    message = IO.iodata_to_binary(["n,,", @sep, "auth=Bearer ", token, @sep, kvpairs, @sep])

    resp =
      try do
        send_recv_fun.(message)
      rescue
        # Refused without a challenge
        error in AuthenticationError ->
          notify_rejected(opts, token, error.error_message)
          reraise error, __STACKTRACE__
      end

    case resp do
      %{auth_bytes: ""} = final_resp ->
        {:ok, final_resp}

      # RFC 7628 §3.2.2: the error comes as a challenge; answering %x01 makes Kafka
      # fail the exchange with ErrorCode 58. The token is refused either way, so
      # however that last exchange goes, the error raised is about the token
      %{auth_bytes: error_json} ->
        try do
          send_recv_fun.(@sep)
        rescue
          _ -> :ok
        end

        notify_rejected(opts, token, error_json)

        raise AuthenticationError,
          mechanism: "OAUTHBEARER",
          error_code: 58,
          error_message: error_json,
          message:
            "SASL OAUTHBEARER authentication failed. ErrorCode: 58 ErrorMessage: #{error_json}"
    end
  end

  # A failing callback must not hide the authentication error
  defp notify_rejected(opts, token, error) do
    case Keyword.get(opts, :on_rejected_mfa) do
      nil ->
        :ok

      {mod, fun, args} ->
        try do
          apply(mod, fun, args ++ [token, error])
        catch
          kind, reason ->
            Logger.warning(
              "OAUTHBEARER on_rejected_mfa #{inspect({mod, fun, args})} failed: #{Exception.format(kind, reason, __STACKTRACE__)}"
            )
        end

        :ok
    end
  end
end
