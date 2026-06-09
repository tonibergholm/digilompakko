package fi.digilompakko.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

private val Brand = Color(0xFF0D4589)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = lightColorScheme(primary = Brand)) {
                WalletScreen(viewModel())
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(vm: WalletViewModel) {
    var presenting by remember { mutableStateOf<StoredCredential?>(null) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Digilompakko") }) },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { vm.receivePid() },
                icon = { Icon(Icons.Filled.Add, null) },
                text = { Text("Receive") },
            )
        }
    ) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).fillMaxSize().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            KeyBanner(vm.isHardwareBacked.value)
            if (vm.credentials.isEmpty()) {
                EmptyState()
            } else {
                vm.credentials.forEach { cred ->
                    CredentialCard(cred) { presenting = cred }
                }
            }
            if (vm.status.value.isNotEmpty()) {
                Text(vm.status.value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }
        }
    }

    presenting?.let { cred ->
        PresentDialog(cred, vm) { presenting = null }
    }
}

@Composable
private fun KeyBanner(hardware: Boolean) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text(if (hardware) "StrongBox key" else "Keystore key (no StrongBox)", fontWeight = FontWeight.SemiBold)
                Text("Holder key · ES256 / P-256", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }
        }
    }
}

@Composable
private fun EmptyState() {
    Column(Modifier.fillMaxWidth().padding(vertical = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text("No credentials yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text("Tap Receive to get your PID from the demo issuer.",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun CredentialCard(cred: StoredCredential, onPresent: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Brand, contentColor = Color.White),
        shape = RoundedCornerShape(18.dp)
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("SD-JWT VC", style = MaterialTheme.typography.labelSmall)
            Text(if (cred.vct.contains("pid")) "Person Identification" else cred.vct,
                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(cred.vct, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.8f))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("${cred.disclosures.size} attributes", style = MaterialTheme.typography.bodySmall)
                FilledTonalButton(onClick = onPresent) { Text("Present") }
            }
        }
    }
}

@Composable
private fun PresentDialog(cred: StoredCredential, vm: WalletViewModel, onClose: () -> Unit) {
    val selected = remember { mutableStateListOf<String>().apply { addAll(cred.disclosures.map { it.name }) } }

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Present") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Choose what to share. Only selected attributes are disclosed.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                Spacer(Modifier.height(8.dp))
                cred.disclosures.forEach { d ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                        Switch(checked = selected.contains(d.name), onCheckedChange = {
                            if (it) selected.add(d.name) else selected.remove(d.name)
                        })
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(d.name)
                            Text(d.value, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                        }
                    }
                }
                if (vm.lastResult.value.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    Text(vm.lastResult.value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(onClick = { vm.present(cred, selected.toList()) }, enabled = selected.isNotEmpty()) { Text("Share") }
        },
        dismissButton = { TextButton(onClick = onClose) { Text("Close") } }
    )
}
