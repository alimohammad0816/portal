// Tunnel VPN: a quick settings tile next to Wi-Fi and Bluetooth.
//
// Status and settings come straight from the tunneld service over D-Bus.
// Connecting goes through the Tunnel app (`tunnel-desktop --connect`),
// which holds saved passwords in the keyring and asks when it needs to.

import Gio from 'gi://Gio';
import GObject from 'gi://GObject';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {QuickMenuToggle, SystemIndicator} from 'resource:///org/gnome/shell/ui/quickSettings.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const BUS_NAME = 'org.tunnelvpn.Daemon1';
const OBJECT_PATH = '/org/tunnelvpn/Daemon1';
const IFACE = `
<node>
  <interface name="org.tunnelvpn.Daemon1">
    <method name="ListProfiles"><arg type="s" direction="out"/></method>
    <method name="GetStatus"><arg type="s" direction="out"/></method>
    <method name="GetSettings"><arg type="s" direction="out"/></method>
    <method name="SetSettings"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
    <method name="Disconnect"/>
    <signal name="StatusChanged"><arg type="s"/></signal>
    <signal name="SettingsChanged"><arg type="s"/></signal>
  </interface>
</node>`;
const DaemonProxy = Gio.DBusProxy.makeProxyWrapper(IFACE);

const APP = 'tunnel-desktop';
const ICON = 'network-vpn-symbolic';
const ICON_OFF = 'network-vpn-disconnected-symbolic';

function launch(args) {
    try {
        Gio.Subprocess.new([APP, ...args], Gio.SubprocessFlags.NONE);
    } catch (e) {
        logError(e, 'Tunnel: could not start the app');
    }
}

function parse(json, fallback) {
    try {
        return JSON.parse(json);
    } catch {
        return fallback;
    }
}

const TunnelToggle = GObject.registerClass(
class TunnelToggle extends QuickMenuToggle {
    _init() {
        super._init({title: 'Tunnel', iconName: ICON_OFF, toggleMode: false});
        this.menu.setHeader(ICON, 'Tunnel', 'Not connected');

        this._status = {state: 'disconnected'};
        this._settings = null;
        this._profiles = [];

        this._locations = new PopupMenu.PopupMenuSection();
        this.menu.addMenuItem(this._locations);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._firewall = new PopupMenu.PopupSwitchMenuItem('Firewall', false);
        this._firewall.connect('toggled', (_item, on) =>
            this._changeSettings(s => {
                s.firewall = on ? 'auto' : 'off';
            }));
        this.menu.addMenuItem(this._firewall);

        this._split = new PopupMenu.PopupSwitchMenuItem('Split tunneling', false);
        this._split.connect('toggled', (_item, on) =>
            this._changeSettings(s => {
                s.split.enabled = on;
            }));
        this.menu.addMenuItem(this._split);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addAction('Open Tunnel', () => launch(['--show']));

        this.connect('clicked', () => {
            if (!this._proxy || this._status.state === 'needs_credentials')
                launch(['--show']);
            else if (this._status.state === 'disconnected' && !this._status.internet_blocked)
                launch(['--connect']);
            else
                this._proxy.DisconnectAsync().catch(e => logError(e, 'Tunnel: disconnect'));
        });

        this._watch = Gio.bus_watch_name(Gio.BusType.SYSTEM, BUS_NAME, Gio.BusNameWatcherFlags.NONE,
            () => this._attach(), () => this._detach());
    }

    _attach() {
        this._proxy = new DaemonProxy(Gio.DBus.system, BUS_NAME, OBJECT_PATH, (proxy, error) => {
            if (error) {
                this._detach();
                return;
            }
            this._signals = [
                proxy.connectSignal('StatusChanged', (_p, _s, [json]) => this._onStatus(parse(json, this._status))),
                proxy.connectSignal('SettingsChanged', (_p, _s, [json]) => this._onSettings(parse(json, null))),
            ];
            this._refresh();
        });
    }

    _detach() {
        if (this._proxy && this._signals)
            this._signals.forEach(id => this._proxy.disconnectSignal(id));
        this._proxy = null;
        this._signals = null;
        this.checked = false;
        this.subtitle = 'Service not running';
        this.iconName = ICON_OFF;
        this.emit('state-changed');
    }

    async _refresh() {
        if (!this._proxy)
            return;
        try {
            const [profiles] = await this._proxy.ListProfilesAsync();
            const [status] = await this._proxy.GetStatusAsync();
            const [settings] = await this._proxy.GetSettingsAsync();
            this._profiles = parse(profiles, []);
            this._onSettings(parse(settings, null));
            this._onStatus(parse(status, this._status));
        } catch (e) {
            logError(e, 'Tunnel: refresh');
        }
    }

    _name(id) {
        return this._profiles.find(p => p.id === id)?.name ?? 'VPN';
    }

    _onStatus(s) {
        const known = !s.profile_id || this._profiles.some(p => p.id === s.profile_id);
        this._status = s;
        if (!known) {
            this._refresh();
            return;
        }
        const name = this._name(s.profile_id);
        const text = {
            connected: name,
            connecting: 'Connecting…',
            needs_credentials: 'Waiting for password…',
            disconnecting: 'Disconnecting…',
            disconnected: s.internet_blocked ? 'Internet blocked' : 'Not connected',
        }[s.state] ?? '';
        this.checked = s.state !== 'disconnected';
        this.subtitle = text;
        this.iconName = s.state === 'connected' ? ICON : ICON_OFF;
        this.menu.setHeader(ICON, 'Tunnel', s.state === 'connected' ? `Connected · ${name}` : text);
        this._buildLocations();
        this.emit('state-changed');
    }

    _onSettings(settings) {
        if (!settings)
            return;
        this._settings = settings;
        this._firewall.setToggleState(settings.firewall !== 'off');
        this._split.setToggleState(settings.split?.enabled ?? false);
    }

    _buildLocations() {
        this._locations.removeAll();
        const recent = [...this._profiles]
            .sort((a, b) => (b.last_connected_at ?? 0) - (a.last_connected_at ?? 0))
            .slice(0, 8);
        for (const p of recent) {
            const label = p.country ? `${p.name}  ·  ${p.country}` : p.name;
            const item = new PopupMenu.PopupMenuItem(label);
            if (p.id === this._status.profile_id && this._status.state !== 'disconnected')
                item.setOrnament(PopupMenu.Ornament.CHECK);
            else
                item.setOrnament(PopupMenu.Ornament.NONE);
            item.connect('activate', () => launch(['--connect', p.id]));
            this._locations.addMenuItem(item);
        }
        if (recent.length === 0) {
            const item = new PopupMenu.PopupMenuItem('Import a profile…');
            item.connect('activate', () => launch(['--show']));
            this._locations.addMenuItem(item);
        }
    }

    _changeSettings(edit) {
        if (!this._proxy || !this._settings)
            return;
        const next = JSON.parse(JSON.stringify(this._settings));
        edit(next);
        this._proxy.SetSettingsAsync(JSON.stringify(next))
            .then(([stored]) => this._onSettings(parse(stored, null)))
            .catch(e => {
                logError(e, 'Tunnel: settings');
                this._onSettings(this._settings);
            });
    }

    destroy() {
        if (this._watch)
            Gio.bus_unwatch_name(this._watch);
        this._detach();
        super.destroy();
    }
});

const TunnelIndicator = GObject.registerClass(
class TunnelIndicator extends SystemIndicator {
    _init() {
        super._init();
        this._indicator = this._addIndicator();
        this._indicator.iconName = ICON;
        this._indicator.visible = false;

        this._toggle = new TunnelToggle();
        this._toggle.connect('state-changed', () => {
            // Show the panel icon while connected or blocking.
            const s = this._toggle._status;
            this._indicator.visible = s.state === 'connected' || Boolean(s.internet_blocked);
            this._indicator.iconName = s.state === 'connected' ? ICON : ICON_OFF;
        });
        this.quickSettingsItems.push(this._toggle);
    }

    destroy() {
        this.quickSettingsItems.forEach(item => item.destroy());
        super.destroy();
    }
});

export default class TunnelExtension extends Extension {
    enable() {
        this._indicator = new TunnelIndicator();
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
