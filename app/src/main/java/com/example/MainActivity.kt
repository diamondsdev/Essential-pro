package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.SentinelViewModel
import com.example.ui.screens.EngagementScreen
import com.example.ui.screens.FindingsScreen
import com.example.ui.screens.ReportsScreen
import com.example.ui.screens.ScannerScreen
import com.example.ui.theme.CyberSlate700
import com.example.ui.theme.CyberSlate800
import com.example.ui.theme.CyberSlate900
import com.example.ui.theme.CyberSlate950
import com.example.ui.theme.SentinelCyan
import com.example.ui.theme.SentinelTheme
import com.example.ui.theme.SeverityClean

enum class SentinelTab(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    ENGAGEMENT("Scope & ROA", Icons.Default.Shield),
    SCANNER("Assessment", Icons.Default.PlayArrow),
    FINDINGS("Findings", Icons.Default.BugReport),
    REPORTS("Reports & Audit", Icons.Default.Assessment)
}

class MainActivity : ComponentActivity() {

    private val viewModel: SentinelViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SentinelTheme(darkTheme = true) {
                MainApp(viewModel = viewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainApp(viewModel: SentinelViewModel) {
    var selectedTab by remember { mutableStateOf(SentinelTab.SCANNER) }
    val auth by viewModel.currentAuthorization.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = CyberSlate950,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = CyberSlate900,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                ),
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(SentinelCyan.copy(alpha = 0.18f))
                                .border(1.dp, SentinelCyan, RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = "Sentinel Logo",
                                tint = SentinelCyan,
                                modifier = Modifier.size(20.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(10.dp))

                        Column {
                            Text(
                                text = "SENTINEL PRO",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 1.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "DEFENSIVE SECURITY ASSESSMENT",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = SentinelCyan,
                                letterSpacing = 1.sp
                            )
                        }
                    }
                },
                actions = {
                    val isAuthActive = auth != null && auth!!.explicitTestingPermitted
                    Box(
                        modifier = Modifier
                            .padding(end = 12.dp)
                            .clip(RoundedCornerShape(6.dp))
                            .background(if (isAuthActive) SeverityClean.copy(alpha = 0.15f) else Color(0x33EF4444))
                            .border(1.dp, if (isAuthActive) SeverityClean.copy(alpha = 0.5f) else Color(0xFFEF4444), RoundedCornerShape(6.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(if (isAuthActive) SeverityClean else Color(0xFFEF4444))
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = if (isAuthActive) "ROA ACTIVE" else "ROA REQUIRED",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = if (isAuthActive) SeverityClean else Color(0xFFEF4444)
                            )
                        }
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = CyberSlate900,
                contentColor = MaterialTheme.colorScheme.onSurface,
                tonalElevation = 8.dp,
                modifier = Modifier.testTag("bottom_nav_bar")
            ) {
                SentinelTab.entries.forEach { tab ->
                    val isSelected = selectedTab == tab
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { selectedTab = tab },
                        icon = {
                            Icon(
                                imageVector = tab.icon,
                                contentDescription = tab.label
                            )
                        },
                        label = {
                            Text(
                                text = tab.label,
                                fontSize = 11.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CyberSlate900,
                            selectedTextColor = SentinelCyan,
                            indicatorColor = SentinelCyan,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
                        ),
                        modifier = Modifier.testTag("nav_item_${tab.name.lowercase()}")
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (selectedTab) {
                SentinelTab.ENGAGEMENT -> EngagementScreen(viewModel = viewModel)
                SentinelTab.SCANNER -> ScannerScreen(
                    viewModel = viewModel,
                    onNavigateToFindings = { selectedTab = SentinelTab.FINDINGS }
                )
                SentinelTab.FINDINGS -> FindingsScreen(viewModel = viewModel)
                SentinelTab.REPORTS -> ReportsScreen(viewModel = viewModel)
            }
        }
    }
}
