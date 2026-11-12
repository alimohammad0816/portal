//! Which network we're on, from NetworkManager, so Tunnel can connect by
//! itself on networks you haven't marked as trusted.

use futures_util::StreamExt;
use serde::Serialize;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Network {
    /// Connection name; for Wi-Fi this is normally the network name.
    pub name: String,
    pub wireless: bool,
}

async fn primary(conn: &Connection) -> zbus::Result<Option<Network>> {
    let nm = Proxy::new(conn, NM, NM_PATH, NM).await?;
    let path: OwnedObjectPath = nm.get_property("PrimaryConnection").await?;
    if path.as_str() == "/" {
        return Ok(None);
    }
    let ac = Proxy::new(
        conn,
        NM,
        path.as_str(),
        "org.freedesktop.NetworkManager.Connection.Active",
    )
    .await?;
    let name: String = ac.get_property("Id").await?;
    let kind: String = ac.get_property("Type").await?;
    // Our own tunnel never becomes NetworkManager's primary connection,
    // but other VPNs might.
    if kind == "vpn" || kind == "tun" {
        return Ok(None);
    }
    Ok(Some(Network {
        name,
        wireless: kind == "802-11-wireless",
    }))
}

pub async fn current() -> Option<Network> {
    let conn = Connection::system().await.ok()?;
    primary(&conn).await.ok().flatten()
}

/// Call `on_change` with the primary network now and whenever it changes.
pub async fn watch<F, Fut>(mut on_change: F)
where
    F: FnMut(Option<Network>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let Ok(conn) = Connection::system().await else {
        return;
    };
    let Ok(nm) = Proxy::new(&conn, NM, NM_PATH, NM).await else {
        return;
    };
    let mut changes = nm
        .receive_property_changed::<OwnedObjectPath>("PrimaryConnection")
        .await;
    let mut last = primary(&conn).await.ok().flatten();
    on_change(last.clone()).await;
    while changes.next().await.is_some() {
        // Give the new connection a moment to settle (DHCP, DNS).
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let now = primary(&conn).await.ok().flatten();
        if now != last {
            last = now.clone();
            on_change(now).await;
        }
    }
}

#[cfg(test)]
mod tests {
    /// Reads the real NetworkManager state: `cargo test -p tunnel-desktop -- --ignored network`.
    #[tokio::test]
    #[ignore]
    async fn network_reads_primary_connection() {
        let n = super::current().await;
        eprintln!("primary network: {n:?}");
    }
}
