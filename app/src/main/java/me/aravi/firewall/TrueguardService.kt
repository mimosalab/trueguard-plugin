package me.aravi.firewall

import android.R
import android.annotation.TargetApi
import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import android.util.TypedValue
import androidx.core.app.NotificationCompat
import androidx.preference.PreferenceManager
import logcat.asLog
import logcat.logcat
import me.aravi.firewall.beans.Allowed
import me.aravi.firewall.beans.Packet
import me.aravi.firewall.beans.ResourceRecord
import me.aravi.firewall.beans.Usage
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.system.exitProcess


public class TrueguardService : VpnService() {

    private var jni_lock = Any()
    private var jni_context: Long = 0

    private var tunnelThread: Thread? = null
    private var vpn: ParcelFileDescriptor? = null


    companion object {
        init {
            try {
                System.loadLibrary("trueguard")
            } catch (e: Exception) {
                when (e) {
                    is SecurityException -> {

                    }
                    is NullPointerException -> {

                    }
                    else -> {
                        exitProcess(1)
                    }
                }

            }
        }


        private const val NOTIFY_ENFORCING = 1
        private const val NOTIFY_WAITING = 2
        private const val NOTIFY_DISABLED = 3
        private const val NOTIFY_LOCKDOWN = 4
        private const val NOTIFY_AUTOSTART = 5
        private const val NOTIFY_ERROR = 6
        private const val NOTIFY_TRAFFIC = 7
        private const val NOTIFY_UPDATE = 8
        const val NOTIFY_EXTERNAL = 9
        const val NOTIFY_DOWNLOAD = 10

    }


    private external fun jni_init(sdk: Int): Long

    private external fun jni_start(context: Long, loglevel: Int)

    private external fun jni_run(context: Long, tun: Int, fwd53: Boolean, rcode: Int)

    private external fun jni_stop(context: Long)

    private external fun jni_clear(context: Long)

    private external fun jni_get_mtu(): Int

    private external fun jni_get_stats(context: Long): IntArray

    private external fun jni_pcap(name: String, record_size: Int, file_size: Int)

    private external fun jni_socks5(addr: String, port: Int, username: String, password: String)

    private external fun jni_done(context: Long)


    override fun onCreate() {
        logcat { "CREATE" }
        startForeground(NOTIFY_WAITING, getWaitingNotification())
        if (jni_context != 0L) {
            logcat { jni_context.toString() }
            jni_stop(jni_context)
            synchronized(jni_lock) {
                jni_done(jni_context)
                jni_context = 0
            }
        }

        // Native init
        jni_context = jni_init(Build.VERSION.SDK_INT)
        super.onCreate()
    }


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        logcat { "START" }
        vpn = startVPN(Builder(this))
        startNative(vpn)
        return START_STICKY
    }


    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Throws(SecurityException::class)
    private fun startVPN(builder: TrueguardService.Builder): ParcelFileDescriptor? {
        return try {
            val pfd: ParcelFileDescriptor? = builder.establish()

            // Set underlying network
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
                val active = cm.activeNetwork
                if (active != null) {
                    logcat { "Setting underlying network=" + cm.getNetworkInfo(active) }
                    setUnderlyingNetworks(arrayOf(active))
                }
            }
            pfd
        } catch (ex: SecurityException) {
            throw ex
        } catch (ex: Throwable) {
            null
        }
    }


    private fun startNative(
        vpn: ParcelFileDescriptor?,
    ) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val log = prefs.getBoolean("log", false)
        val log_app = prefs.getBoolean("log_app", false)
        val filter = prefs.getBoolean("filter", false)

        jni_socks5("", 0, "", "")

        logcat { "Start native log=$log/$log_app filter=$filter" }

        if (tunnelThread == null) {
            val prio = prefs.getString("loglevel", Integer.toString(Log.WARN))!!
                .toInt()
            val rcode = prefs.getString("rcode", "3")!!.toInt()

            logcat { "Starting tunnel thread context=$jni_context" }
            jni_start(jni_context, prio)
            tunnelThread = Thread {
                logcat { "Running tunnel context=$jni_context" }
                vpn?.fd?.let {
                    jni_run(
                        jni_context,
                        it,
                        false,
                        rcode
                    )
                }
                logcat { "tunnel exited" }
                tunnelThread = null
            }
//            tunnelThread?.priority = Thread.MAX_PRIORITY
            tunnelThread?.start()
            logcat { "Started tunnel thread" }
        }

    }

    private fun stopNative(vpn: ParcelFileDescriptor?) {
        logcat { "Stop native" }
        if (tunnelThread != null) {
            logcat { "Stopping tunnel thread" }
            jni_stop(jni_context)
            var thread = tunnelThread
            while (thread != null && thread.isAlive) {
                try {
                    logcat { "Joining tunnel thread context=$jni_context" }
                    thread.join()
                } catch (ignored: InterruptedException) {
                    logcat { "Joined tunnel interrupted = ${ignored.asLog()}" }
                }
                thread = tunnelThread
            }
            tunnelThread = null
            jni_clear(jni_context)
            logcat { "Stopped tunnel thread" }
        }
    }

    private fun stopVPN(pfd: ParcelFileDescriptor?) {
        logcat { "Stopping" }
        try {
            pfd?.close()
        } catch (ex: IOException) {
            logcat { ex.asLog() }
        }
    }


    // Called from native code
    private fun nativeExit(reason: String?) {
        logcat { "Native exit reason=$reason" }

    }

    // Called from native code
    private fun nativeError(error: Int, message: String) {
        logcat { "Native error $error: $message" }
    }

    // Called from native code
    private fun logPacket(packet: Packet) {
        logcat { packet.toString() }
    }

    // Called from native code
    private fun dnsResolved(rr: ResourceRecord) {
        logcat { "DNS RESOLVED= ${rr.toString()}" }

    }

    // Called from native code
    private fun isDomainBlocked(name: String): Boolean {
        return false
    }

    // Called from native code
    @TargetApi(Build.VERSION_CODES.Q)
    private fun getUidQ(
        version: Int,
        protocol: Int,
        saddr: String,
        sport: Int,
        daddr: String,
        dport: Int
    ): Int {
        if (protocol != 6 /* TCP */ && protocol != 17 /* UDP */) return Process.INVALID_UID
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val local = InetSocketAddress(saddr, sport)
        val remote = InetSocketAddress(daddr, dport)
        logcat { "Get uid local=$local remote=$remote" }
        val uid = cm.getConnectionOwnerUid(protocol, local, remote)
        logcat { "Get uid=$uid" }
        return uid
    }

    // Called from native code
    private fun isAddressAllowed(packet: Packet): Allowed? {
        var allowed: Allowed? = null
        return allowed
    }

    // Called from native code
    private fun accountUsage(usage: Usage) {
        logcat { usage.toString() }
    }


    private inner class Builder(context: Context) : VpnService.Builder() {
        private val networkInfo =
            (context.getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager).activeNetworkInfo
        private var mtu = 0
        private val listAddress: MutableList<String> = ArrayList()
        private val listRoute: MutableList<String> = ArrayList()
        private val listDns: MutableList<InetAddress> = ArrayList()
        private val listDisallowed: MutableList<String> = ArrayList()


        override fun setMtu(mtu: Int): VpnService.Builder {
            this.mtu = mtu
            super.setMtu(mtu)
            return this
        }

        override fun addAddress(address: String, prefixLength: Int): Builder {
            listAddress.add("$address/$prefixLength")
            super.addAddress(address, prefixLength)
            return this
        }

        override fun addRoute(address: String, prefixLength: Int): Builder {
            listRoute.add("$address/$prefixLength")
            super.addRoute(address, prefixLength)
            return this
        }

        override fun addRoute(address: InetAddress, prefixLength: Int): Builder {
            listRoute.add(address.hostAddress + "/" + prefixLength)
            super.addRoute(address, prefixLength)
            return this
        }

        override fun addDnsServer(address: InetAddress): Builder {
            listDns.add(address)
            super.addDnsServer(address)
            return this
        }

        override fun addDisallowedApplication(packageName: String): Builder {
            listDisallowed.add(packageName)
            super.addDisallowedApplication(packageName)
            return this
        }

        override fun equals(obj: Any?): Boolean {
            val other = obj as Builder? ?: return false
            if (networkInfo == null || other.networkInfo == null || networkInfo.type != other.networkInfo.type) return false
            if (mtu != other.mtu) return false
            if (listAddress.size != other.listAddress.size) return false
            if (listRoute.size != other.listRoute.size) return false
            if (listDns.size != other.listDns.size) return false
            if (listDisallowed.size != other.listDisallowed.size) return false
            for (address in listAddress) if (!other.listAddress.contains(address)) return false
            for (route in listRoute) if (!other.listRoute.contains(route)) return false
            for (dns in listDns) if (!other.listDns.contains(dns)) return false
            for (pkg in listDisallowed) if (!other.listDisallowed.contains(pkg)) return false
            return true
        }


    }


    private fun getWaitingNotification(): Notification {
        val main = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this,
            0,
            main,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val tv = TypedValue()
        theme.resolveAttribute(R.attr.colorPrimary, tv, true)
        val builder = NotificationCompat.Builder(this, "foreground")
        builder.setSmallIcon(R.drawable.ic_lock_idle_alarm)
            .setContentIntent(pi)
            .setColor(tv.data)
            .setOngoing(true)
            .setAutoCancel(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle("Connection await")
        else builder.setContentTitle("Connection await")
            .setContentText("Waiting")
        builder.setCategory(
            NotificationCompat.CATEGORY_STATUS
        )
            .setVisibility(NotificationCompat.VISIBILITY_SECRET).priority =
            NotificationCompat.PRIORITY_MIN
        return builder.build()
    }


    override fun onDestroy() {
        super.onDestroy()
        logcat { "destroy" }
        synchronized(this) {
            stopVPN(vpn)
            stopNative(vpn)
        }
    }


}



