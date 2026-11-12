import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { ConnectInput, Profile } from "@/lib/api";

/** Which fields to show. */
export interface Ask {
  login: boolean;
  /** The profile's static challenge (OTP). */
  otp: boolean;
  key: boolean;
  proxy: boolean;
}

export interface CredentialsRequest {
  profile: Profile;
  ask: Ask;
  /** A question from the server, answered on its own. */
  challenge?: { text: string; echo: boolean };
  /** Shown above the fields, e.g. after a failed sign-in. */
  message?: string;
  /** The service is waiting for this answer; cancelling disconnects. */
  fromService?: boolean;
}

export const noAsk: Ask = { login: false, otp: false, key: false, proxy: false };

const userKey = (id: string) => `portal.username.${id}`;
const proxyUserKey = "portal.proxy-username";

function stored(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: fine, we just won't prefill next time */
  }
}

function Field({
  id,
  label,
  value,
  onChange,
  type = "text",
  autoFocus,
  autoComplete,
  inputMode,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  autoFocus?: boolean;
  autoComplete?: string;
  inputMode?: "numeric" | "text";
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        autoFocus={autoFocus}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        inputMode={inputMode}
      />
    </div>
  );
}

function title(r: CredentialsRequest): string {
  const { ask, profile } = r;
  if (r.challenge) return profile.name;
  if (ask.login) return `Sign in to ${profile.name}`;
  if (ask.key && !ask.proxy && !ask.otp) return "Unlock private key";
  if (ask.proxy && !ask.key && !ask.otp) return "Proxy sign-in";
  if (ask.otp && !ask.key && !ask.proxy) return profile.challenge ?? "One-time code";
  return `Connect to ${profile.name}`;
}

function description(r: CredentialsRequest): string {
  if (r.message) return r.message;
  if (r.challenge) return "The server asks for one more step.";
  const { ask, profile } = r;
  if (ask.key && !ask.login && !ask.proxy) return `The private key of ${profile.name} is protected by a passphrase.`;
  if (ask.proxy && !ask.login && !ask.key) return "The proxy you connect through asks for a username and password.";
  if (ask.otp && !ask.login && !ask.key && !ask.proxy) return `Your saved password for ${profile.name} is used with this code.`;
  return "Saved passwords are kept in your keyring, encrypted with your login.";
}

export function CredentialsDialog({
  request,
  onSubmit,
  onAnswer,
  onCancel,
}: {
  request: CredentialsRequest | null;
  onSubmit: (input: ConnectInput, remember: boolean) => void;
  onAnswer: (response: string) => void;
  onCancel: () => void;
}) {
  const ask = request?.ask ?? noAsk;
  const profile = request?.profile ?? null;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [response, setResponse] = useState("");
  const [key, setKey] = useState("");
  const [proxyUser, setProxyUser] = useState("");
  const [proxyPass, setProxyPass] = useState("");
  const [remember, setRemember] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!request) return;
    setUsername(stored(userKey(request.profile.id)));
    setPassword("");
    setResponse("");
    setKey("");
    setProxyUser(stored(proxyUserKey));
    setProxyPass("");
    setRemember(true);
    setError(null);
  }, [request]);

  const edit = (set: (v: string) => void) => (v: string) => {
    set(v);
    setError(null);
  };

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!request || !profile) return;
    if (request.challenge) {
      if (!response.trim()) return setError("Enter your answer.");
      onAnswer(response.trim());
      return;
    }
    if (ask.login && (!username.trim() || !password)) return setError("Enter your username and password.");
    if (ask.otp && !response.trim()) return setError(`Enter the ${profile.challenge ?? "response"}.`);
    if (ask.key && !key) return setError("Enter the private key passphrase.");
    if (ask.proxy && (!proxyUser.trim() || !proxyPass)) return setError("Enter the proxy's username and password.");
    if (ask.login) store(userKey(profile.id), username.trim());
    if (ask.proxy) store(proxyUserKey, proxyUser.trim());
    onSubmit(
      {
        username: ask.login ? username.trim() : "",
        password: ask.login ? password : "",
        response: ask.otp ? response.trim() : "",
        key_passphrase: ask.key ? key : "",
        proxy_username: ask.proxy ? proxyUser.trim() : "",
        proxy_password: ask.proxy ? proxyPass : "",
      },
      remember,
    );
  }

  const canRemember = !request?.challenge && (ask.login || ask.key || ask.proxy);
  // Focus the first empty field.
  const focus = ask.login ? (username ? "pass" : "user") : ask.otp ? "otp" : ask.key ? "key" : "proxy";

  return (
    <Dialog open={request !== null} onOpenChange={(open) => !open && onCancel()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{request ? title(request) : ""}</DialogTitle>
            <DialogDescription>{request ? description(request) : ""}</DialogDescription>
          </DialogHeader>
          {request?.challenge ? (
            <Field
              id="cred-challenge"
              label={request.challenge.text || "Response"}
              type={request.challenge.echo ? "text" : "password"}
              autoFocus
              value={response}
              onChange={edit(setResponse)}
              autoComplete="one-time-code"
            />
          ) : (
            <>
              {ask.login && (
                <>
                  <Field id="cred-user" label="Username" autoFocus={focus === "user"} value={username} onChange={edit(setUsername)} autoComplete="username" />
                  <Field
                    id="cred-pass"
                    label="Password"
                    type="password"
                    autoFocus={focus === "pass"}
                    value={password}
                    onChange={edit(setPassword)}
                    autoComplete="current-password"
                  />
                </>
              )}
              {ask.otp && (
                <Field
                  id="cred-resp"
                  label={profile?.challenge ?? "Response"}
                  inputMode="numeric"
                  autoFocus={focus === "otp"}
                  value={response}
                  onChange={edit(setResponse)}
                  autoComplete="one-time-code"
                />
              )}
              {ask.key && (
                <Field id="cred-key" label="Private key passphrase" type="password" autoFocus={focus === "key"} value={key} onChange={edit(setKey)} autoComplete="off" />
              )}
              {ask.proxy && (
                <div className="grid gap-3 rounded-lg border p-3">
                  <span className="text-xs text-muted-foreground">Proxy</span>
                  <Field id="cred-proxy-user" label="Username" autoFocus={focus === "proxy"} value={proxyUser} onChange={edit(setProxyUser)} autoComplete="off" />
                  <Field id="cred-proxy-pass" label="Password" type="password" value={proxyPass} onChange={edit(setProxyPass)} autoComplete="off" />
                </div>
              )}
            </>
          )}
          {canRemember && (
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor="cred-remember" className="text-[13.5px] font-normal">
                {ask.key && !ask.login && !ask.proxy ? "Remember passphrase" : "Remember in keyring"}
              </Label>
              <Switch id="cred-remember" checked={remember} onCheckedChange={setRemember} />
            </div>
          )}
          {error && <p className="text-[13.5px] text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
            <Button type="submit">{request?.challenge ? "Continue" : "Connect"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
