package com.mazza.guard

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var apiKeyInput: EditText
    private lateinit var systemSwitch: CheckBox
    private lateinit var adapter: ReportAdapter
    private val prefs by lazy { getSharedPreferences("mazzaguard", Context.MODE_PRIVATE) }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "MazzaGuard"

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(8))
        }

        apiKeyInput = EditText(this).apply {
            hint = "Chave de API do VirusTotal (opcional)"
            setText(prefs.getString("vt_key", ""))
            setSingleLine()
        }
        systemSwitch = CheckBox(this).apply { text = "Incluir apps do sistema" }
        val scanBtn = Button(this).apply {
            text = "ESCANEAR COM MAZZAGUARD"
            setOnClickListener { runScan() }
        }
        progress = ProgressBar(this).apply { visibility = View.GONE }
        status = TextView(this).apply {
            text = "Toque em ESCANEAR para analisar os apps instalados."
            setPadding(0, dp(8), 0, dp(8))
        }
        val list = ListView(this)
        adapter = ReportAdapter()
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ -> showDetails(adapter.getItem(pos)!!) }

        root.addView(apiKeyInput)
        root.addView(systemSwitch)
        root.addView(scanBtn)
        root.addView(progress)
        root.addView(status)
        root.addView(list, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
    }

    private fun runScan() {
        prefs.edit().putString("vt_key", apiKeyInput.text.toString().trim()).apply()
        progress.visibility = View.VISIBLE
        status.text = "Analisando..."
        lifecycleScope.launch {
            val reports = withContext(Dispatchers.Default) {
                Scanner.scan(this@MainActivity, systemSwitch.isChecked)
            }
            adapter.clear()
            adapter.addAll(reports)
            progress.visibility = View.GONE
            val high = reports.count { it.level == "ALTO" }
            val mid = reports.count { it.level == "MÉDIO" }
            status.text = "${reports.size} apps analisados • $high risco alto • $mid risco médio\nToque em um app para ver detalhes."
        }
    }

    private fun showDetails(r: AppReport) {
        AlertDialog.Builder(this)
            .setTitle("${r.name}  (${r.score}/100 — ${r.level})")
            .setMessage(r.reasons.joinToString("\n") + "\n\nPacote: ${r.pkg}")
            .setPositiveButton("VirusTotal") { _, _ -> checkVirusTotal(r) }
            .setNeutralButton("Desinstalar") { _, _ ->
                startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${r.pkg}")))
            }
            .setNegativeButton("Fechar", null)
            .show()
    }

    private fun checkVirusTotal(r: AppReport) {
        val key = apiKeyInput.text.toString().trim()
        if (key.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Chave necessária")
                .setMessage("Cole sua chave gratuita do VirusTotal no campo do topo (virustotal.com > perfil > API key).")
                .setPositiveButton("OK", null).show()
            return
        }
        progress.visibility = View.VISIBLE
        lifecycleScope.launch {
            val msg = withContext(Dispatchers.IO) {
                try {
                    VirusTotal.lookup(VirusTotal.sha256(File(r.apkPath)), key)
                } catch (e: Exception) {
                    "Falha na consulta: ${e.message}"
                }
            }
            progress.visibility = View.GONE
            AlertDialog.Builder(this@MainActivity)
                .setTitle("VirusTotal — ${r.name}")
                .setMessage(msg)
                .setPositiveButton("OK", null).show()
        }
    }

    inner class ReportAdapter : ArrayAdapter<AppReport>(
        this@MainActivity, android.R.layout.simple_list_item_2
    ) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView ?: layoutInflater.inflate(
                android.R.layout.simple_list_item_2, parent, false)
            val r = getItem(position)!!
            val t1 = v.findViewById<TextView>(android.R.id.text1)
            val t2 = v.findViewById<TextView>(android.R.id.text2)
            t1.text = r.name
            t2.text = "Risco ${r.level} • ${r.score}/100"
            t2.setTextColor(when (r.level) {
                "ALTO" -> Color.parseColor("#D32F2F")
                "MÉDIO" -> Color.parseColor("#F57C00")
                else -> Color.parseColor("#388E3C")
            })
            return v
        }
    }
}
