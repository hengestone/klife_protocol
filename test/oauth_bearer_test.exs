defmodule KlifeProtocol.OAuthBearerTest do
  use ExUnit.Case, async: true

  @moduletag core: true

  import ExUnit.CaptureLog

  alias KlifeProtocol.SASL.AuthenticationError
  alias KlifeProtocol.SASL.Mechanism.OAuthBearer

  @error_json ~s({"status":"invalid_token"})

  def token(token), do: token

  def rejected(test_pid, token, error), do: send(test_pid, {:rejected, token, error})

  def raising_callback(_token, _error), do: raise("callback failed")

  defp opts(extra \\ []), do: [token_mfa: {__MODULE__, :token, ["some-token"]}] ++ extra

  # Answers like a broker that refuses the token with a challenge, then fails the
  # exchange with ErrorCode 58 once the client answers %x01
  defp refusing_broker(test_pid) do
    fn
      <<"n,,", _::binary>> = msg ->
        send(test_pid, {:sent, msg})
        %{auth_bytes: @error_json}

      <<1>> ->
        send(test_pid, :sent_sep)

        raise AuthenticationError,
          mechanism: "OAUTHBEARER",
          error_code: 58,
          error_message: "Authentication failed",
          message: "refused"
    end
  end

  test "succeeds when the broker accepts the token" do
    send_recv = fn _ -> %{auth_bytes: "", session_lifetime_ms: 1_000} end

    assert {:ok, %{session_lifetime_ms: 1_000}} = OAuthBearer.execute_auth(send_recv, opts())
  end

  test "raises an AuthenticationError with the broker's error when the token is refused" do
    error =
      assert_raise AuthenticationError, fn ->
        OAuthBearer.execute_auth(refusing_broker(self()), opts())
      end

    assert %AuthenticationError{
             mechanism: "OAUTHBEARER",
             error_code: 58,
             error_message: @error_json
           } = error

    assert error.message =~ "ErrorCode: 58"
    assert error.message =~ "invalid_token"

    # RFC 7628: the challenge is answered with %x01 before failing
    assert_received {:sent, _}
    assert_received :sent_sep
  end

  test "calls on_rejected_mfa with the refused token and the broker's error" do
    opts = opts(on_rejected_mfa: {__MODULE__, :rejected, [self()]})

    assert_raise AuthenticationError, fn ->
      OAuthBearer.execute_auth(refusing_broker(self()), opts)
    end

    assert_received {:rejected, "some-token", @error_json}
  end

  test "calls on_rejected_mfa when the token is refused without a challenge" do
    send_recv = fn _ ->
      raise AuthenticationError,
        mechanism: "OAUTHBEARER",
        error_code: 58,
        error_message: "Authentication failed",
        message: "refused"
    end

    opts = opts(on_rejected_mfa: {__MODULE__, :rejected, [self()]})

    assert_raise AuthenticationError, fn -> OAuthBearer.execute_auth(send_recv, opts) end
    assert_received {:rejected, "some-token", "Authentication failed"}
  end

  test "does not call on_rejected_mfa when the token is accepted" do
    send_recv = fn _ -> %{auth_bytes: ""} end
    opts = opts(on_rejected_mfa: {__MODULE__, :rejected, [self()]})

    assert {:ok, _} = OAuthBearer.execute_auth(send_recv, opts)
    refute_received {:rejected, _, _}
  end

  test "does not call on_rejected_mfa on network errors" do
    send_recv = fn _ -> raise MatchError, term: {:error, :closed} end
    opts = opts(on_rejected_mfa: {__MODULE__, :rejected, [self()]})

    assert_raise MatchError, fn -> OAuthBearer.execute_auth(send_recv, opts) end
    refute_received {:rejected, _, _}
  end

  test "a failing on_rejected_mfa does not hide the AuthenticationError" do
    opts = opts(on_rejected_mfa: {__MODULE__, :raising_callback, []})

    log =
      capture_log(fn ->
        assert_raise AuthenticationError, fn ->
          OAuthBearer.execute_auth(refusing_broker(self()), opts)
        end
      end)

    assert log =~ "on_rejected_mfa"
    assert log =~ "callback failed"
  end

  test "raises an AuthenticationError even if the %x01 answer fails on the network" do
    send_recv = fn
      <<"n,,", _::binary>> -> %{auth_bytes: @error_json}
      <<1>> -> raise MatchError, term: {:error, :closed}
    end

    assert_raise AuthenticationError, ~r/invalid_token/, fn ->
      OAuthBearer.execute_auth(send_recv, opts())
    end
  end
end
