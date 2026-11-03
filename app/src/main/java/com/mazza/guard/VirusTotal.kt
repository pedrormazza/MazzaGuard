package com.mazza.guard

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

object VirusTotal {

    fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /** Consulta pelo hash. Não envia o APK, só o hash (privado e rápido). */
    fun lookup(hash: String, apiKey: String): String {
        val conn = URL("https://www.virustotal.com/api/v3/files/$hash")
            .openConnection() as HttpURLConnection
        conn.setRequestProperty("x-apikey", apiKey)
        conn.connectTimeout = 15000
        conn.readTimeout = 15000
        return try {
            when (val code = conn.responseCode) {
                200 -> {
                    val body = conn.inputStream.bufferedReader().readText()
                    val stats = JSONObject(body).getJSONObject("data")
                        .getJSONObject("attributes").getJSONObject("last_analysis_stats")
                    val mal = stats.optInt("malicious")
                    val sus = stats.optInt("suspicious")
                    val ok = stats.optInt("harmless")
                    val und = stats.optInt("undetected")
                    val verdict = when {
                        mal >= 3 -> "🚨 PROVAVELMENTE MALICIOSO — considere desinstalar."
                        mal > 0 || sus > 0 -> "⚠ Detecções isoladas (pode ser falso positivo)."
                        else -> "✅ Nenhuma detecção."
                    }
                    "Malicioso: $mal\nSuspeito: $sus\nLimpo: $ok\nNão detectado: $und\n\n$verdict\n\nSHA-256:\n$hash"
                }
                404 -> "Este APK nunca foi enviado ao VirusTotal (hash desconhecido).\nIsso é comum em apps raros ou modificados.\n\nSHA-256:\n$hash"
                401 -> "Chave de API inválida."
                429 -> "Limite de consultas atingido (chave gratuita: 4 por minuto). Aguarde e tente de novo."
                else -> "Erro HTTP $code"
            }
        } finally {
            conn.disconnect()
        }
    }
}
