//! Saved VPN passwords in the user's keyring (GNOME Keyring, KWallet or
//! anything else that speaks the freedesktop Secret Service API).
//!
//! Secrets travel over the user's own session bus with the `plain`
//! algorithm, like most clients on a single-user desktop. They are stored
//! encrypted by the keyring and never reach the web view.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

const SERVICE: &str = "org.freedesktop.secrets";
const PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";
const APP: &str = "io.github.alimohammad0816.Portal";

/// Keyring entries: a profile's sign-in, its private key passphrase, and
/// the connection proxy's sign-in (shared by all profiles).
pub fn login_slot(profile: &str) -> String {
    profile.to_string()
}

pub fn key_slot(profile: &str) -> String {
    format!("{profile}:key")
}

pub const PROXY_SLOT: &str = "connection-proxy";

#[derive(Serialize, Deserialize, Clone)]
pub struct Saved {
    pub username: String,
    pub password: String,
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

async fn service(conn: &Connection) -> zbus::Result<Proxy<'static>> {
    Proxy::new(conn, SERVICE, PATH, "org.freedesktop.Secret.Service").await
}

async fn open_session(svc: &Proxy<'_>) -> zbus::Result<OwnedObjectPath> {
    let (_out, path): (OwnedValue, OwnedObjectPath) =
        svc.call("OpenSession", &("plain", Value::from(""))).await?;
    Ok(path)
}

fn attributes(profile: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", APP), ("profile", profile)])
}

/// Run a Secret Service prompt (e.g. "unlock your keyring") to completion.
async fn prompt(conn: &Connection, path: &OwnedObjectPath) -> zbus::Result<bool> {
    if path.as_str() == "/" {
        return Ok(true);
    }
    use futures_util::StreamExt;
    let p = Proxy::new(
        conn,
        SERVICE,
        path.as_str(),
        "org.freedesktop.Secret.Prompt",
    )
    .await?;
    let mut done = p.receive_signal("Completed").await?;
    p.call_method("Prompt", &("",)).await?;
    let Some(msg) = done.next().await else {
        return Ok(false);
    };
    let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize()?;
    Ok(!dismissed)
}

async fn unlock(
    conn: &Connection,
    svc: &Proxy<'_>,
    objects: Vec<OwnedObjectPath>,
) -> zbus::Result<bool> {
    if objects.is_empty() {
        return Ok(true);
    }
    let (_unlocked, p): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        svc.call("Unlock", &(objects,)).await?;
    prompt(conn, &p).await
}

pub async fn load(profile: &str) -> zbus::Result<Option<Saved>> {
    let conn = Connection::session().await?;
    let svc = service(&conn).await?;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attributes(profile),)).await?;
    let mut items = unlocked;
    if !locked.is_empty() && unlock(&conn, &svc, locked.clone()).await? {
        items.extend(locked);
    }
    let Some(item) = items.into_iter().next() else {
        return Ok(None);
    };
    let session = open_session(&svc).await?;
    let secrets: HashMap<OwnedObjectPath, Secret> = svc
        .call("GetSecrets", &(vec![item.clone()], &session))
        .await?;
    let _ = Proxy::new(
        &conn,
        SERVICE,
        session.as_str(),
        "org.freedesktop.Secret.Session",
    )
    .await?
    .call_method("Close", &())
    .await;
    Ok(secrets
        .get(&item)
        .and_then(|(_, _, value, _)| serde_json::from_slice(value).ok()))
}

pub async fn save(profile: &str, profile_name: &str, saved: &Saved) -> zbus::Result<()> {
    let conn = Connection::session().await?;
    let svc = service(&conn).await?;
    let collection: OwnedObjectPath = ObjectPath::try_from(DEFAULT_COLLECTION)?.into();
    unlock(&conn, &svc, vec![collection.clone()]).await?;
    let session = open_session(&svc).await?;
    let label = format!("Portal VPN: {profile_name}");
    let props: HashMap<&str, Value> = HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from(label)),
        (
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes(profile)),
        ),
    ]);
    let value = serde_json::to_vec(saved).map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let secret: Secret = (session, Vec::new(), value, "application/json".into());
    let col = Proxy::new(
        &conn,
        SERVICE,
        DEFAULT_COLLECTION,
        "org.freedesktop.Secret.Collection",
    )
    .await?;
    let (_item, p): (OwnedObjectPath, OwnedObjectPath) =
        col.call("CreateItem", &(props, secret, true)).await?;
    prompt(&conn, &p).await?;
    Ok(())
}

pub async fn forget(profile: &str) -> zbus::Result<()> {
    let conn = Connection::session().await?;
    let svc = service(&conn).await?;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attributes(profile),)).await?;
    for item in unlocked.into_iter().chain(locked) {
        let p = Proxy::new(&conn, SERVICE, item.as_str(), "org.freedesktop.Secret.Item").await?;
        let prompt_path: OwnedObjectPath = p.call("Delete", &()).await?;
        prompt(&conn, &prompt_path).await?;
    }
    Ok(())
}

pub async fn has(profile: &str) -> bool {
    let Ok(conn) = Connection::session().await else {
        return false;
    };
    let Ok(svc) = service(&conn).await else {
        return false;
    };
    let r: zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> =
        svc.call("SearchItems", &(attributes(profile),)).await;
    matches!(r, Ok((u, l)) if !u.is_empty() || !l.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round trip against the real keyring of the session running the
    /// tests: `cargo test -p portal-desktop -- --ignored keyring`.
    #[tokio::test]
    #[ignore]
    async fn keyring_round_trip() {
        let id = "test-profile-delete-me";
        let saved = Saved {
            username: "alice".into(),
            password: "p@ss \"w\"".into(),
        };
        save(id, "test", &saved).await.unwrap();
        assert!(has(id).await);
        let back = load(id).await.unwrap().unwrap();
        assert_eq!(
            (back.username.as_str(), back.password.as_str()),
            ("alice", "p@ss \"w\"")
        );
        forget(id).await.unwrap();
        assert!(!has(id).await);
        assert!(load(id).await.unwrap().is_none());
    }
}
