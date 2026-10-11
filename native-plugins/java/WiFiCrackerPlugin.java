package com.pegasus.suite;

import android.Manifest;
import android.content.Context;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import java.util.List;

/**
 * WiFiCracker — lists nearby Wi-Fi access points (SSID/BSSID/signal/security)
 * and returns them to JavaScript. It does NOT capture handshakes or crack
 * keys by itself: it only surfaces what the OS already scans, so the operator
 * can build a plan against networks they are authorized to test.
 */
@CapacitorPlugin(
    name = "WiFiCracker",
    permissions = {
        @Permission(alias = "wifi", strings = { Manifest.permission.ACCESS_FINE_LOCATION })
    }
)
public class WiFiCrackerPlugin extends Plugin {

    @PluginMethod
    public void scan(PluginCall call) {
        if (!hasRequiredPermissions()) {
            requestPermissionForAlias("wifi", call, "permissionCallback");
            return;
        }
        doScan(call);
    }

    @PermissionCallback
    private void permissionCallback(PluginCall call) {
        if (hasRequiredPermissions()) {
            doScan(call);
        } else {
            call.reject("Location permission is required to scan Wi-Fi networks.");
        }
    }

    @SuppressWarnings("deprecation")
    private void doScan(PluginCall call) {
        try {
            WifiManager wm = (WifiManager) getContext().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm == null) {
                call.reject("WifiManager unavailable.");
                return;
            }
            List<ScanResult> results = wm.getScanResults();
            JSArray aps = new JSArray();
            if (results != null) {
                for (ScanResult r : results) {
                    JSObject o = new JSObject();
                    o.put("ssid", r.SSID != null ? r.SSID : "");
                    o.put("bssid", r.BSSID);
                    o.put("rssi", r.level);
                    o.put("frequency", r.frequency);
                    o.put("security", r.capabilities);
                    aps.put(o);
                }
            }
            JSObject ret = new JSObject();
            ret.put("accessPoints", aps);
            ret.put("count", aps.length());
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Wi-Fi scan failed: " + e.getMessage());
        }
    }
}
