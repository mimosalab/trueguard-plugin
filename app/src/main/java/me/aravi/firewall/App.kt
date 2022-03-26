package me.aravi.firewall

import android.annotation.TargetApi
import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) createNotificationChannels()

    }


    @TargetApi(Build.VERSION_CODES.O)
    private fun createNotificationChannels() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val foreground = NotificationChannel(
            "foreground",
            "Foregriund stuff",
            NotificationManager.IMPORTANCE_MIN
        )
        foreground.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        nm.createNotificationChannel(foreground)

//        val notify = NotificationChannel(
//            "notify",
//            getString(R.string.channel_notify),
//            NotificationManager.IMPORTANCE_DEFAULT
//        )
//        notify.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
//        notify.setBypassDnd(true)
//        nm.createNotificationChannel(notify)
//
//        val access = NotificationChannel(
//            "access",
//            getString(R.string.channel_access),
//            NotificationManager.IMPORTANCE_DEFAULT
//        )
//        access.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
//        access.setBypassDnd(true)
//        nm.createNotificationChannel(access)
    }
}