package com.mazza.guard

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

data class AppReport(
    val name: String,
    val pkg: String,
    val score: Int,
    val reasons: List<String>,
    val apkPath: String,
    val installer: String
) {
    val level: String
        get() = when {
            score >= 60 -> "ALTO"
            score >= 30 -> "MÉDIO"
            else -> "BAIXO"
        }
}

object Scanner {

    private val permissionWeights = mapOf(
        "android.permission.SEND_SMS" to (15 to "Pode enviar SMS (golpes de SMS pago)"),
        "android.permission.READ_SMS" to (15 to "Pode ler seus SMS (códigos de verificação)"),
        "android.permission.RECEIVE_SMS" to (10 to "Pode interceptar SMS recebidos"),
        "android.permission.READ_CALL_LOG" to (8 to "Pode ler o histórico de chamadas"),
        "android.permission.SYSTEM_ALERT_WINDOW" to (15 to "Pode desenhar sobre outros apps (tela falsa/overlay)"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to (10 to "Pode instalar outros APKs"),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to (10 to "Acesso total a todos os arquivos"),
        "android.permission.READ_CONTACTS" to (5 to "Pode ler seus contatos"),
        "android.permission.RECORD_AUDIO" to (5 to "Pode gravar áudio"),
        "android.permission.READ_PHONE_STATE" to (3 to "Pode ler estado/identificadores do telefone"),
        "android.permission.CAMERA" to (3 to "Pode usar a câmera"),
        "android.permission.ACCESS_FINE_LOCATION" to (3 to "Pode ver sua localização precisa")
    )

    fun scan(ctx: Context, includeSystem: Boolean = false): List<AppReport> {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS

        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(flags)

        val enabledA11y = Settings.Secure.getString(
            ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: ""
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val activeAdmins = dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()

        val out = mutableListOf<AppReport>()
        for (pi in packages) {
            val ai = pi.applicationInfo ?: continue
            if (pi.packageName == ctx.packageName) continue

            val isPureSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            if (isPureSystem && !includeSystem) continue

            var score = 0
            val reasons = mutableListOf<String>()

            // 1) Permissões solicitadas
            val requested = pi.requestedPermissions?.toSet() ?: emptySet()
            for ((perm, info) in permissionWeights) {
                if (perm in requested) {
                    score += info.first
                    reasons += "• ${info.second}"
                }
            }

            // 2) Serviço de acessibilidade declarado / ativo (vetor nº 1 de trojans bancários)
            val declaresA11y = pi.services?.any {
                it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
            } == true
            if (declaresA11y) {
                score += 10
                reasons += "• Declara serviço de acessibilidade"
                if (enabledA11y.contains(pi.packageName + "/")) {
                    score += 30
                    reasons += "• ⚠ Acessibilidade ATIVADA para este app (pode ler a tela e clicar por você)"
                }
            }

            // 3) Administrador de dispositivo ativo
            if (pi.packageName in activeAdmins) {
                score += 25
                reasons += "• ⚠ É administrador do dispositivo (dificulta desinstalar)"
            }

            // 4) Origem da instalação
            val installer = installerOf(pm, pi.packageName)
            if (!isPureSystem && installer != "com.android.vending") {
                score += 15
                reasons += "• Não foi instalado pela Play Store (origem: ${installer.ifEmpty { "desconhecida/APK manual" }})"
            }

            if (reasons.isEmpty()) reasons += "• Nenhum comportamento suspeito detectado"

            out += AppReport(
                name = pm.getApplicationLabel(ai).toString(),
                pkg = pi.packageName,
                score = score.coerceAtMost(100),
                reasons = reasons,
                apkPath = ai.sourceDir,
                installer = installer
            )
        }
        return out.sortedByDescending { it.score }
    }

    private fun installerOf(pm: PackageManager, pkg: String): String = try {
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName ?: ""
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg) ?: ""
        }
    } catch (e: Exception) { "" }
}
