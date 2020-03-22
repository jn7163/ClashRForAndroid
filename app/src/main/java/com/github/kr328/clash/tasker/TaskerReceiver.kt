package com.github.kr328.clash.tasker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import com.twofortyfouram.locale.api.Intent as ApiIntent
import com.github.kr328.clash.utils.startClashService
import com.github.kr328.clash.utils.stopClashService

class TaskerReceiver: BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        var bundle = if (intent.hasExtra(ApiIntent.EXTRA_BUNDLE)) intent.getBundleExtra(ApiIntent.EXTRA_BUNDLE) else Bundle.EMPTY
        var switch = bundle.getBoolean("switch_state", false)

        if (switch)
            context.startClashService()
        else
            context.stopClashService()
    }
}