package com.pegasus.suite;

import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

/**
 * MainActivity — Capacitor host. Registers the Security Suite plugins
 * (CellTower, PhoneScanner, WiFiCracker) before the bridge starts, so the
 * WebView can call them via window.Capacitor.Plugins.*.
 *
 * Plugin registration MUST happen before super.onCreate().
 */
public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(CellTowerPlugin.class);
        registerPlugin(PhoneScannerPlugin.class);
        registerPlugin(WiFiCrackerPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
