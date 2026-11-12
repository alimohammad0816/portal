import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Profile } from "@/lib/api";

export interface Credentials {
  username: string;
  password: string;
  response: string;
}

const userKey = (id: string) => `tunnel.username.${id}`;

export function rememberedUsername(id: string): string {
  try {
    return localStorage.getItem(userKey(id)) ?? "";
  } catch {
    return "";
  }
}

export function CredentialsDialog({
  profile,
  onSubmit,
  onCancel,
}: {
  profile: Profile | null;
  onSubmit: (c: Credentials) => void;
  onCancel: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [response, setResponse] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (profile) {
      setUsername(rememberedUsername(profile.id));
      setPassword("");
      setResponse("");
      setError(null);
    }
  }, [profile]);

  const needsResponse = profile?.auth === "user_pass_challenge";

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!profile) return;
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    if (needsResponse && !response.trim()) {
      setError(`Enter the ${profile.challenge ?? "response"}.`);
      return;
    }
    try {
      localStorage.setItem(userKey(profile.id), username.trim());
    } catch {
      /* storage unavailable: fine, we just won't prefill next time */
    }
    onSubmit({ username: username.trim(), password, response: response.trim() });
  }

  return (
    <Dialog open={profile !== null} onOpenChange={(open) => !open && onCancel()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Sign in to {profile?.name}</DialogTitle>
            <DialogDescription>Your password is sent to OpenVPN and isn't stored.</DialogDescription>
          </DialogHeader>
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
          {needsResponse && (
            <div className="grid gap-2">
              <Label htmlFor="cred-resp">{profile?.challenge ?? "Response"}</Label>
              <Input
                id="cred-resp"
                inputMode="numeric"
                value={response}
                onChange={(e) => {
                  setResponse(e.target.value);
                  setError(null);
                }}
                autoComplete="one-time-code"
              />
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
