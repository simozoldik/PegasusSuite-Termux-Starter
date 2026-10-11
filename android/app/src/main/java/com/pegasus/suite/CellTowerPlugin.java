package com.pegasus.suite;

import android.Manifest;
import android.content.Context;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoWcdma;
import android.telephony.CellSignalStrength;
import android.telephony.TelephonyManager;

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
 * CellTower — reads the device's visible cell towers (serving + neighbours)
 * and returns them to JavaScript so the backend can triangulate a position.
 *
 * Requires location permission (runtime). Returns only cell identity + signal
 * strength; no user data leaves the device.
 */
@CapacitorPlugin(
    name = "CellTower",
    permissions = {
        @Permission(alias = "location", strings = { Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION })
    }
)
public class CellTowerPlugin extends Plugin {

    @PluginMethod
    public void getCells(PluginCall call) {
        if (!hasRequiredPermissions()) {
            requestPermissionForAlias("location", call, "permissionCallback");
            return;
        }
        readCells(call);
    }

    @PermissionCallback
    private void permissionCallback(PluginCall call) {
        if (hasRequiredPermissions()) {
            readCells(call);
        } else {
            call.reject("Location permission is required to read cell towers.");
        }
    }

    private void readCells(PluginCall call) {
        try {
            TelephonyManager tm = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) {
                call.reject("TelephonyManager unavailable.");
                return;
            }

            JSArray towers = new JSArray();
            List<CellInfo> infos = tm.getAllCellInfo();
            if (infos != null) {
                for (CellInfo info : infos) {
                    JSObject t = toTower(info);
                    if (t != null) towers.put(t);
                }
            }

            JSObject ret = new JSObject();
            ret.put("towers", towers);
            ret.put("count", towers.length());
            ret.put("networkOperator", tm.getNetworkOperator());
            call.resolve(ret);
        } catch (SecurityException e) {
            call.reject("Permission denied reading cell info: " + e.getMessage());
        } catch (Exception e) {
            call.reject("Failed to read cell info: " + e.getMessage());
        }
    }

    private JSObject toTower(CellInfo info) {
        JSObject o = new JSObject();
        try {
            if (info instanceof CellInfoLte) {
                CellInfoLte lte = (CellInfoLte) info;
                CellIdentityLte id = lte.getCellIdentity();
                CellSignalStrength ss = lte.getCellSignalStrength();
                o.put("type", "lte");
                o.put("cellId", id.getCi());
                o.put("lac", id.getTac());
                o.put("mcc", id.getMccString());
                o.put("mnc", id.getMncString());
                o.put("registered", info.isRegistered());
                o.put("rssi", ss.getDbm());
                return o;
            } else if (info instanceof CellInfoGsm) {
                CellInfoGsm gsm = (CellInfoGsm) info;
                CellIdentityGsm id = gsm.getCellIdentity();
                o.put("type", "gsm");
                o.put("cellId", id.getCid());
                o.put("lac", id.getLac());
                o.put("mcc", id.getMccString());
                o.put("mnc", id.getMncString());
                o.put("registered", info.isRegistered());
                o.put("rssi", gsm.getCellSignalStrength().getDbm());
                return o;
            } else if (info instanceof CellInfoWcdma) {
                CellInfoWcdma w = (CellInfoWcdma) info;
                CellIdentityWcdma id = w.getCellIdentity();
                o.put("type", "wcdma");
                o.put("cellId", id.getCid());
                o.put("lac", id.getLac());
                o.put("mcc", id.getMccString());
                o.put("mnc", id.getMncString());
                o.put("registered", info.isRegistered());
                o.put("rssi", w.getCellSignalStrength().getDbm());
                return o;
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }
}
