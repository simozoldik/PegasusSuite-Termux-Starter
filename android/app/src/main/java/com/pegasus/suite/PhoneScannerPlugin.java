package com.pegasus.suite;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.wifi.WifiManager;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;

/**
 * PhoneScanner — enumerates devices visible from this device on the local
 * network: its own addresses, and (best-effort) the kernel ARP table used to
 * discover reachable neighbours. Read-only; performs no active scanning by
 * itself. Use strictly on networks you are authorized to test.
 */
@CapacitorPlugin(name = "PhoneScanner")
public class PhoneScannerPlugin extends Plugin {

    @PluginMethod
    public void deviceInfo(PluginCall call) {
        JSObject ret = new JSObject();
        try {
            ret.put("wifiEnabled", isWifiEnabled());
            ret.put("localAddresses", localAddresses());
            ret.put("arp", readArpTable());
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Failed to enumerate devices: " + e.getMessage());
        }
    }

    private boolean isWifiEnabled() {
        try {
            WifiManager wm = (WifiManager) getContext().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            return wm != null && wm.isWifiEnabled();
        } catch (Exception e) {
            return false;
        }
    }

    private JSArray localAddresses() {
        JSArray arr = new JSArray();
        try {
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (nif == null || !nif.isUp()) continue;
                for (InetAddress addr : Collections.list(nif.getInetAddresses())) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        JSObject o = new JSObject();
                        o.put("iface", nif.getName());
                        o.put("address", addr.getHostAddress());
                        arr.put(o);
                    }
                }
            }
        } catch (Exception ignored) { /* best effort */ }
        return arr;
    }

    /** Reads /proc/net/arp (no root required on most devices). */
    private JSArray readArpTable() {
        JSArray arr = new JSArray();
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            boolean first = true;
            while ((line = br.readLine()) != null) {
                if (first) { first = false; continue; } // header
                String[] cols = line.trim().split("\\s+");
                if (cols.length >= 6) {
                    JSObject o = new JSObject();
                    o.put("ip", cols[0]);
                    o.put("mac", cols[3]);
                    o.put("device", cols[5]);
                    arr.put(o);
                }
            }
        } catch (Exception ignored) { /* /proc may be unavailable */ }
        return arr;
    }
}
