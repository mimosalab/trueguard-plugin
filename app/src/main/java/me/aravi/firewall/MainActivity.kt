package me.aravi.firewall

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {

    private external fun dump_memory_profile()
    private external fun jni_getprop(name: String): String
    private external fun is_numeric_address(ip: String): Boolean

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btn = findViewById<Button>(R.id.start_service)
        val serviceIntent = Intent(this, TrueguardService::class.java)

        justCheckPermission()
        btn.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
        }


    }


    private fun justCheckPermission(): Boolean {
        val vpn = VpnService.prepare(this)
        startActivity(vpn)
        return vpn == null
    }
}