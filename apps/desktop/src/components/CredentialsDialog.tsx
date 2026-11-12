import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { Profile } from "@/lib/api";

export interface Credentials {
  /// Empty when the saved username and password should be used.
  username: string;
  password: string;
  response: string;
  remember?: boolean;
}

export interface CredentialsRequest {
  profile: Profile;
  /// The password is in the keyring; only the one-time code is needed.
  otpOnly: boolean;
  /// Shown above the fields, e.g. after a failed sign-in.
  message?: string;
}

const userKey = (id: string) => `tunnel.username.${id}`;

function rememberedUsername(id: string): string {
  try {
    return localStorage.getItem(userKey(id)) ?? "";
  } catch {
    return "";
  }
}

export function CredentialsDialog({
  request,
  onSubmit,
  onCancel,
}: {
  request: CredentialsRequest | null;
  onSubmit: (c: Credentials) => void;
  onCancel: () => void;
}) {
  const profile = request?.profile ?? null;
  const otpOnly = request?.otpOnly ?? false;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [response, setResponse] = useState("");
  const [remember, setRemember] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (profile) {
      setUsername(rememberedUsername(profile.id));
      setPassword("");
      setResponse("");
      setRemember(true);
      setError(null);
    }
  }, [profile]);

  const needsResponse = profile?.auth === "user_pass_challenge";

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!profile) return;
    if (!otpOnly && (!username.trim() || !password)) {
      setError("Enter your username and password.");
      return;
    }
    if (needsResponse && !response.trim()) {
      setError(`Enter the ${profile.challenge ?? "response"}.`);
      return;
    }
    if (otpOnly) {
      onSubmit({ username: "", password: "", response: response.trim() });
      return;
    }
    try {
      localStorage.setItem(userKey(profile.id), username.trim());
    } catch {
      /* storage unavailable: fine, we just won't prefill next time */
    }
    onSubmit({ username: username.trim(), password, response: response.trim(), remember });
  }

  return (
    <Dialog open={profile !== null} onOpenChange={(open) => !open && onCancel()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{otpOnly ? `${profile?.challenge ?? "One-time code"}` : `Sign in to ${profile?.name}`}</DialogTitle>
            <DialogDescription>
              {request?.message ??
                (otpOnly
                  ? `Your saved password for ${profile?.name} is used with this code.`
                  : "Saved passwords are kept in your keyring, encrypted with your login.")}
            </DialogDescription>
          </DialogHeader>
          {!otpOnly && (
            <>
              <div className="grid gap-2">
                <Label htmlFor="cred-user">Username</Label>
                <Input
                  id="cred-user"
                  autoFocus={!username}
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    setError(null);
                  }}
                  autoComplete="username"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="cred-pass">Password</Label>
                <Input
                  id="cred-pass"
                  type="password"
                  autoFocus={!!username}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setError(null);
                  }}
                  autoComplete="current-password"
                />
              </div>
            </>
          )}
          {needsResponse && (
            <div className="grid gap-2">
              <Label htmlFor="cred-resp">{profile?.challenge ?? "Response"}</Label>
              <Input
                id="cred-resp"
                inputMode="numeric"
                autoFocus={otpOnly}
                value={response}
                onChange={(e) => {
                  setResponse(e.target.value);
                  setError(null);
                }}
                autoComplete="one-time-code"
              />
            </div>
          )}
          {!otpOnly && (
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor="cred-remember" className="text-[13px] font-normal">
                Remember password
              </Label>
              <Switch id="cred-remember" checked={remember} onCheckedChange={setRemember} />
            </div>
          )}
          {error && <p className="text-[13px] text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
            <Button type="submit">Connect</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
