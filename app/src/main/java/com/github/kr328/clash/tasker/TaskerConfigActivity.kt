package com.github.kr328.clash.tasker

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import androidx.core.os.bundleOf
import com.github.kr328.clash.R
import kotlinx.android.synthetic.main.activity_tasker_config.*
import com.twofortyfouram.locale.api.Intent as ApiIntent

class TaskerConfigActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tasker_config)

        val intent = intent
        if (intent == null) {
            finish()
            return
        }
        var bundle = if (intent.hasExtra(ApiIntent.EXTRA_BUNDLE)) intent.getBundleExtra(ApiIntent.EXTRA_BUNDLE) else Bundle.EMPTY
        var switch = bundle.getBoolean("switch_state", false)
        switch1.isChecked = switch
    }

    fun SetOption(view: View) {
        var switch = switch1.isChecked()
        var intent = Intent()

        intent.putExtra(ApiIntent.EXTRA_STRING_BLURB, getString(if (switch) R.string.switch_on_clash else R.string.switch_off_clash))
        intent.putExtra(ApiIntent.EXTRA_BUNDLE, bundleOf(Pair("switch_state", switch)))
        setResult(Activity.RESULT_OK, intent)
        finish()
    }

}
